#!/usr/bin/env python3
"""Create or update the Kibana alerting rules in kibana/alert-rules.json.

    KIBANA_URL=https://localhost:5601 ES_AUTH=elastic:changeme python3 kibana/load_alert_rules.py

Rules are matched by id: an existing rule is updated in place (its enabled/
disabled state and, unless ALERT_CONNECTOR_ID is given, its actions are
kept), a missing one is created enabled. Optional:
  ALERT_CONNECTOR_ID  id of a Kibana connector (Slack, Microsoft Teams,
                      server log, webhook, ...) to message whenever a rule
                      fires; replaces the rules' actions with that one.
                      Without it, new rules record alerts in Kibana (Stack
                      Management → Alerts) but notify no one.
  DATA_VIEW_ID        dnstap data view id (default bind-dnstap-data-view,
                      from bind-dashboards.ndjson — import that first).
Standard library only. TLS certificates aren't verified, like setup.sh's curl -k.
"""

import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
KIBANA = os.environ.get("KIBANA_URL", "").rstrip("/")
AUTH = os.environ.get("ES_AUTH", "")
CONNECTOR = os.environ.get("ALERT_CONNECTOR_ID", "")
DATA_VIEW = os.environ.get("DATA_VIEW_ID", "bind-dnstap-data-view")
CTX = ssl._create_unverified_context()


def call(method, path, body=None):
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    if AUTH:
        headers["Authorization"] = "Basic " + base64.b64encode(AUTH.encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(KIBANA + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=CTX) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except ValueError:
            return e.code, {"message": e.reason}


def rule_params(p):
    """Elasticsearch query rule params: an ES|QL query when the rule has "esql",
    otherwise KQL against the data view (so its runtime fields work)."""
    if "esql" in p:
        # An ES|QL rule fires when the query returns rows: one alert, whose
        # context lists the rows (size). Kibana 8.17 has no per-row alerts.
        return {
            "searchType": "esqlQuery", "esqlQuery": {"esql": p["esql"]},
            "timeField": "@timestamp", "size": 10, "groupBy": "all",
            "thresholdComparator": ">", "threshold": [0],
            "timeWindowSize": p["timeWindowSize"], "timeWindowUnit": p["timeWindowUnit"],
        }
    params = {
        "searchType": "searchSource",
        "searchConfiguration": {"query": {"query": p["kql"], "language": "kuery"}, "index": DATA_VIEW},
        "timeField": "@timestamp", "size": 0, "excludeHitsFromPreviousRun": False,
        "aggType": p["aggType"], "groupBy": p["groupBy"],
        "thresholdComparator": p["thresholdComparator"], "threshold": p["threshold"],
        "timeWindowSize": p["timeWindowSize"], "timeWindowUnit": p["timeWindowUnit"],
    }
    for key in ("aggField", "termField", "termSize"):
        if key in p:
            params[key] = p[key]
    return params


def actions():
    if not CONNECTOR:
        return []
    return [{
        "id": CONNECTOR, "group": "query matched",
        "params": {"message": "{{rule.name}}\n{{context.message}}\n{{context.link}}"},
        "frequency": {"summary": False, "notify_when": "onActionGroupChange", "throttle": None},
    }]


def main():
    if not KIBANA:
        sys.exit("set KIBANA_URL (and ES_AUTH)")
    status, dv = call("GET", f"/api/data_views/data_view/{DATA_VIEW}")
    if status != 200:
        sys.exit(f"data view '{DATA_VIEW}' not found in Kibana — import kibana/bind-dashboards.ndjson first")

    rules = json.load(open(os.path.join(HERE, "alert-rules.json"), encoding="utf-8"))["rules"]
    failures = 0
    for r in rules:
        body = {
            "name": r["name"], "tags": r["tags"], "schedule": {"interval": r["interval"]},
            "params": rule_params(r["params"]), "actions": actions(),
        }
        status, existing = call("GET", f"/api/alerting/rule/{r['id']}")
        if status == 200:
            if not CONNECTOR:
                # Keep notifications someone already set up on the rule (in
                # Kibana or an earlier run) instead of wiping them.
                body["actions"] = [{k: a[k] for k in ("id", "group", "params", "frequency", "uuid") if k in a}
                                   for a in existing.get("actions", [])]
            status, res = call("PUT", f"/api/alerting/rule/{r['id']}", body)
            verb = "updated"
        else:
            body.update({"rule_type_id": ".es-query", "consumer": "stackAlerts", "enabled": True})
            status, res = call("POST", f"/api/alerting/rule/{r['id']}", body)
            verb = "created"
        if status in (200, 201):
            print(f"{verb}: {r['name']}")
        else:
            failures += 1
            print(f"FAILED ({status}): {r['name']}: {res.get('message', res)}", file=sys.stderr)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
