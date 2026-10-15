#!/usr/bin/env python3
"""Generate kibana/bind-dashboards.ndjson: data views, Lens visualizations,
saved searches and two dashboards for the BIND data streams.

    python3 kibana/build_dashboards.py

Edit the panel definitions below and re-run instead of hand-editing the
NDJSON: Kibana saved objects embed JSON-in-JSON and are easy to break.
Import the result with setup.sh (KIBANA_URL) or Stack Management → Saved
Objects → Import.
"""

import json
import os
import uuid

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bind-dashboards.ndjson")

DV_DNSTAP = "bind-dnstap-data-view"
DV_LOG = "bind-log-data-view"
DASH_DNSTAP = "bind-dnstap-dashboard"
DASH_LOG = "bind-log-dashboard"

# Saved-object versions for Kibana 8.17 (as exported by it); objects built in
# this shape import unchanged into 8.17 and are migrated forward by newer releases.
VERSIONS = {
    "index-pattern": ("8.8.0", "8.0.0"),
    "lens": ("8.8.0", "8.9.0"),
    "visualization": ("8.8.0", "8.5.0"),
    "search": ("8.8.0", "10.5.0"),
    "dashboard": ("8.8.0", "10.2.0"),
    "links": ("8.8.0", None),   # model-versioned type: Kibana stores no typeMigrationVersion
}

objects = []


def add(obj_type, obj_id, attributes, references=()):
    core, typ = VERSIONS[obj_type]
    obj = {"id": obj_id, "type": obj_type, "attributes": attributes, "references": list(references),
           "managed": False, "coreMigrationVersion": core}
    if typ:
        obj["typeMigrationVersion"] = typ
    objects.append(obj)


# ----------------------------------------------------------------- data views
def data_view(dv_id, title, name, runtime, formats=None):
    add("index-pattern", dv_id, {
        "title": title, "name": name, "timeFieldName": "@timestamp", "allowHidden": False,
        "runtimeFieldMap": json.dumps(runtime), "fieldFormatMap": json.dumps({
            **{f: {"id": "number", "params": {"pattern": "0,0.[00]"}} for f, d in runtime.items() if d["type"] == "double"},
            **(formats or {})}), "fieldAttrs": "{}", "sourceFilters": "[]", "fields": "[]",
    })


data_view(DV_DNSTAP, "logs-bind.dnstap-*", "BIND DNS answers (dnstap)", {
    # event.duration is nanoseconds; dashboards read milliseconds.
    "dns.response_time_ms": {"type": "double", "script": {"source":
        "if (doc.containsKey('event.duration') && doc['event.duration'].size() > 0) "
        "{ emit(doc['event.duration'].value / 1000000.0); }"}},
    # Length of the leftmost label: long random labels are a classic sign of
    # DGA malware or random-subdomain (water-torture) attacks.
    "dns.question.first_label_length": {"type": "long", "script": {"source":
        "if (doc.containsKey('dns.question.name') && doc['dns.question.name'].size() > 0) "
        "{ String n = doc['dns.question.name'].value; int i = n.indexOf('.'); emit(i < 0 ? n.length() : i); }"}},
})
# Zone serials are identifiers (2026101409), not quantities: no thousands separators.
data_view(DV_LOG, "logs-bind-*", "BIND server logs", {}, {"bind.zone.serial": {"id": "string"}})


# ----------------------------------------------------------------- Lens helpers
def count(label, kql=None):
    c = {"label": label, "customLabel": True, "dataType": "number", "operationType": "count",
         "isBucketed": False, "scale": "ratio", "sourceField": "___records___", "params": {"emptyAsNull": True}}
    if kql:
        c["filter"] = {"query": kql, "language": "kuery"}
    return c


def metric(op, field, label, kql=None, params=None, data_type="number"):
    c = {"label": label, "customLabel": True, "dataType": data_type, "operationType": op, "isBucketed": False,
         "scale": "ratio", "sourceField": field, "params": dict(params or {})}
    if op in ("unique_count", "sum", "average", "max", "min", "median"):
        c["params"].setdefault("emptyAsNull", True)
    if kql:
        c["filter"] = {"query": kql, "language": "kuery"}
    return c


def date_hist():
    return {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
            "sourceField": "@timestamp", "isBucketed": True, "scale": "interval",
            "params": {"interval": "auto", "includeEmptyRows": True, "dropPartials": False}}


def terms(field, label, order_by, size=10, data_type="string", other=True):
    return {"label": label, "customLabel": True, "dataType": data_type, "operationType": "terms",
            "sourceField": field, "isBucketed": True, "scale": "ordinal",
            "params": {"size": size, "orderBy": {"type": "column", "columnId": order_by}, "orderDirection": "desc",
                       "otherBucket": other, "missingBucket": False, "parentFormat": {"id": "terms"},
                       "include": [], "exclude": [], "includeIsRegex": False, "excludeIsRegex": False}}


def lens(obj_id, title, dv, vis_type, columns, visualization, kql="", description=""):
    """columns: ordered dict of column id -> column definition (layer L1)."""
    add("lens", obj_id, {
        "title": title, "description": description, "visualizationType": vis_type,
        "state": {
            "datasourceStates": {"formBased": {"layers": {"L1": {
                "columns": columns, "columnOrder": list(columns), "incompleteColumns": {}, "sampling": 1}}}},
            "visualization": visualization,
            "query": {"query": kql, "language": "kuery"},
            "filters": [], "internalReferences": [], "adHocDataViews": {},
        },
    }, [{"type": "index-pattern", "id": dv, "name": "indexpattern-datasource-layer-L1"}])
    return obj_id


KPI_IDS = set()


def metric_vis(obj_id, title, dv, column, kql=""):
    KPI_IDS.add(obj_id)
    column = dict(column, label=title, customLabel=True)
    return lens(obj_id, title, dv, "lnsMetric", {"m": column},
                {"layerId": "L1", "layerType": "data", "metricAccessor": "m"}, kql)


def xy_vis(obj_id, title, dv, columns, accessors, x, split=None, series="bar_stacked", kql=""):
    if split:
        # Split first: otherwise Lens ranks the top N within each time bucket
        # instead of overall, and the legend fills with one-off values.
        columns = {split: columns[split], **{k: v for k, v in columns.items() if k != split}}
    layer = {"layerId": "L1", "layerType": "data", "seriesType": series, "position": "top",
             "showGridlines": False, "xAccessor": x, "accessors": accessors}
    if split:
        layer["splitAccessor"] = split
    return lens(obj_id, title, dv, "lnsXY", columns, {
        "legend": {"isVisible": True, "position": "right"}, "valueLabels": "hide", "fittingFunction": "Linear",
        "axisTitlesVisibilitySettings": {"x": False, "yLeft": False, "yRight": True},
        "preferredSeriesType": series, "layers": [layer]}, kql)


def pie_vis(obj_id, title, dv, group_col, metric_col, kql=""):
    return lens(obj_id, title, dv, "lnsPie", {"g": group_col, "v": metric_col}, {
        "shape": "donut", "layers": [{"layerId": "L1", "layerType": "data", "primaryGroups": ["g"],
                                      "metrics": ["v"], "numberDisplay": "percent", "categoryDisplay": "default",
                                      "legendDisplay": "default", "nestedLegend": False}]}, kql)


def table_vis(obj_id, title, dv, columns, kql=""):
    return lens(obj_id, title, dv, "lnsDatatable", columns, {
        "layerId": "L1", "layerType": "data", "rowHeight": "single", "headerRowHeight": "single",
        "columns": [{"columnId": c} for c in columns]}, kql)


def saved_search(obj_id, title, dv, columns, kql):
    add("search", obj_id, {
        "title": title, "description": "", "columns": columns, "sort": [["@timestamp", "desc"]],
        "grid": {}, "hideChart": False, "isTextBasedQuery": False,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
            "query": {"query": kql, "language": "kuery"}, "filter": [],
            "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})},
    }, [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": dv}])
    return obj_id


def markdown(obj_id, title, text):
    add("visualization", obj_id, {
        "title": title, "description": "", "uiStateJSON": "{}", "version": 1,
        "visState": json.dumps({"title": title, "type": "markdown", "aggs": [],
                                "params": {"fontSize": 12, "openLinksInNewTab": False, "markdown": text}}),
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"},
                                                                  "filter": []})},
    })
    return obj_id


def links(obj_id, title, targets):
    """Kibana Links panel: dashboard-to-dashboard navigation that, unlike a
    Markdown "#/view/..." link, actually reloads the panels."""
    items, refs = [], []
    for n, (dash_id, label) in enumerate(targets):
        ref = f"link_l{n}_dashboard"
        items.append({"id": f"l{n}", "type": "dashboardLink", "order": n, "destinationRefName": ref, "label": label})
        refs.append({"name": ref, "type": "dashboard", "id": dash_id})
    add("links", obj_id, {"title": title, "layout": "horizontal", "links": items}, refs)
    return obj_id


def dashboard(obj_id, title, description, layout):
    """layout: list of (saved object id, type, x, y, w, h)."""
    panels, refs = [], []
    for n, (ref_id, ref_type, x, y, w, h) in enumerate(layout, 1):
        # Panel ids must be unique across dashboards, not just within one:
        # switching dashboards in-app reuses any panel whose id matches, so
        # two dashboards both numbering panels p1, p2, ... show stale panels.
        # uuid5 keeps them stable across rebuilds.
        p = str(uuid.uuid5(uuid.NAMESPACE_URL, f"bind-dashboards/{obj_id}/{ref_id}"))
        config = {"enhancements": {}}
        if ref_id in KPI_IDS:
            config["hidePanelTitles"] = True   # the metric shows its own label
        panels.append({"type": ref_type, "panelIndex": p, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": p},
                       "embeddableConfig": config, "panelRefName": f"panel_{p}"})
        refs.append({"name": f"{p}:panel_{p}", "type": ref_type, "id": ref_id})
    add("dashboard", obj_id, {
        "title": title, "description": description, "version": 3,
        "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
        "refreshInterval": {"pause": True, "value": 60000},
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "syncCursor": True,
                                   "syncTooltips": True, "hidePanelTitles": False}),
        "panelsJSON": json.dumps(panels),
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"},
                                                                  "filter": []})},
    }, refs)


def nav(prefix, note):
    """Top row: a Links panel to both dashboards plus a short description."""
    return [
        (links(f"{prefix}-links", "BIND dashboards",
               [(DASH_DNSTAP, "DNS answers (dnstap)"), (DASH_LOG, "Server logs")]), "links", 0, 0, 16, 4),
        (markdown(f"{prefix}-about", "About this dashboard", note), "visualization", 16, 0, 32, 4),
    ]

# ======================================================== dnstap dashboard
D = DV_DNSTAP
CLIENT = "event.action:client_response"   # what the server answered clients (not its own upstream lookups)
UPSTREAM = "event.action:resolver_response"

dn = nav("bind-dnstap", (
    "Every answer BIND sent, captured by dnstap and exported by the `bind_dns` role. Panels count answers "
    "to clients unless they say otherwise; the upstream panel shows the server's own lookups.")) + [

    (metric_vis("bind-dnstap-kpi-answers", "Answers to clients", D, count("Answers"), CLIENT), "lens", 0, 4, 8, 6),
    (metric_vis("bind-dnstap-kpi-clients", "Unique clients", D,
                metric("unique_count", "client.ip", "Clients"), CLIENT), "lens", 8, 4, 8, 6),
    (metric_vis("bind-dnstap-kpi-failures", "Failed answers", D,
                count("SERVFAIL / REFUSED / errors", "event.outcome:failure"), CLIENT), "lens", 16, 4, 8, 6),
    (metric_vis("bind-dnstap-kpi-nxdomain", "NXDOMAIN answers", D,
                count("NXDOMAIN", "dns.response_code:NXDOMAIN"), CLIENT), "lens", 24, 4, 8, 6),
    (metric_vis("bind-dnstap-kpi-p50", "Median response time (ms)", D,
                metric("median", "dns.response_time_ms", "Median ms"), CLIENT), "lens", 32, 4, 8, 6),
    (metric_vis("bind-dnstap-kpi-p95", "95th percentile response time (ms)", D,
                metric("percentile", "dns.response_time_ms", "p95 ms", params={"percentile": 95}), CLIENT),
     "lens", 40, 4, 8, 6),

    (xy_vis("bind-dnstap-over-time-rcode", "Answers over time by response code", D,
            {"t": date_hist(), "s": terms("dns.response_code", "Response code", "v", 6), "v": count("Answers")},
            ["v"], "t", "s", kql=CLIENT), "lens", 0, 10, 32, 13),
    (pie_vis("bind-dnstap-rcode-donut", "Response codes", D,
             terms("dns.response_code", "Response code", "v", 8), count("Answers"), CLIENT), "lens", 32, 10, 16, 13),

    (pie_vis("bind-dnstap-qtype-donut", "Query types", D,
             terms("dns.question.type", "Query type", "v", 10), count("Answers"), CLIENT), "lens", 0, 23, 16, 13),
    (xy_vis("bind-dnstap-response-time", "Response time (ms): median and 95th percentile", D,
            {"t": date_hist(),
             "a": metric("median", "dns.response_time_ms", "Median"),
             "b": metric("percentile", "dns.response_time_ms", "95th percentile", params={"percentile": 95})},
            ["a", "b"], "t", series="line", kql=CLIENT), "lens", 16, 23, 16, 13),
    (xy_vis("bind-dnstap-by-server", "Answers by server", D,
            {"s": terms("observer.hostname", "Server", "v", 10), "v": count("Answers"),
             "tr": terms("network.transport", "Transport", "v", 3)},
            ["v"], "s", "tr", series="bar_horizontal_stacked", kql=CLIENT), "lens", 32, 23, 16, 13),

    (table_vis("bind-dnstap-top-names", "Top queried names", D,
               {"n": terms("dns.question.name", "Name", "v", 15, other=False), "v": count("Answers"),
                "c": metric("unique_count", "client.ip", "Clients")}, CLIENT), "lens", 0, 36, 16, 15),
    (table_vis("bind-dnstap-top-domains", "Top registered domains", D,
               {"d": terms("dns.question.registered_domain", "Domain", "v", 15, other=False), "v": count("Answers"),
                "u": metric("unique_count", "dns.question.name", "Distinct names")}, CLIENT), "lens", 16, 36, 16, 15),
    (table_vis("bind-dnstap-top-clients", "Top clients", D,
               {"c": terms("client.ip", "Client", "v", 15, data_type="ip", other=False), "v": count("Answers"),
                "u": metric("unique_count", "dns.question.name", "Distinct names"),
                "f": count("NXDOMAIN", "dns.response_code:NXDOMAIN")}, CLIENT), "lens", 32, 36, 16, 15),

    (xy_vis("bind-dnstap-nxdomain-by-client", "NXDOMAIN over time by client", D,
            {"t": date_hist(), "c": terms("client.ip", "Client", "v", 5, data_type="ip"), "v": count("NXDOMAIN")},
            ["v"], "t", "c", kql=f"{CLIENT} and dns.response_code:NXDOMAIN"), "lens", 0, 51, 24, 14),
    (table_vis("bind-dnstap-nxdomain-domains",
               "NXDOMAIN by domain (many distinct names under one domain suggests DGA or random-subdomain traffic)", D,
               {"d": terms("dns.question.registered_domain", "Domain", "v", 15, other=False), "v": count("NXDOMAIN"),
                "u": metric("unique_count", "dns.question.name", "Distinct names"),
                "c": metric("unique_count", "client.ip", "Clients"),
                "l": metric("average", "dns.question.first_label_length", "Avg first-label length")},
               f"{CLIENT} and dns.response_code:NXDOMAIN"), "lens", 24, 51, 24, 14),

    (table_vis("bind-dnstap-failed-names", "Names answered with SERVFAIL / REFUSED", D,
               {"n": terms("dns.question.name", "Name", "v", 15, other=False),
                "r": terms("dns.response_code", "Code", "v", 3, other=False), "v": count("Answers")},
               f"{CLIENT} and event.outcome:failure"), "lens", 0, 65, 16, 14),
    (table_vis("bind-dnstap-slowest", "Slowest domains (median response time)", D,
               {"n": terms("dns.question.registered_domain", "Domain", "m", 15, other=False),
                "m": metric("median", "dns.response_time_ms", "Median ms"), "v": count("Answers")}, CLIENT),
     "lens", 16, 65, 16, 14),
    (table_vis("bind-dnstap-resolved-ips", "Top resolved addresses", D,
               {"i": terms("dns.resolved_ip", "Address", "v", 15, data_type="ip", other=False),
                "v": count("Answers"), "n": metric("unique_count", "dns.question.name", "Names")}, CLIENT),
     "lens", 32, 65, 16, 14),

    (table_vis("bind-dnstap-upstreams", "Upstream servers (resolver lookups; needs 'resolver response' in bind_dnstap_types)", D,
               {"s": terms("server.ip", "Upstream server", "v", 10, data_type="ip", other=False),
                "v": count("Lookups"), "f": count("Failures", "event.outcome:failure"),
                "m": metric("median", "dns.response_time_ms", "Median ms")}, UPSTREAM), "lens", 0, 79, 24, 12),
    (table_vis("bind-dnstap-long-labels", "Longest first labels (possible DGA / tunnelling)", D,
               {"n": terms("dns.question.name", "Name", "l", 15, other=False),
                "l": metric("max", "dns.question.first_label_length", "First-label length"),
                "c": metric("unique_count", "client.ip", "Clients")}, CLIENT), "lens", 24, 79, 24, 12),

    (saved_search("bind-dnstap-search", "BIND DNS answers", D,
                  ["observer.hostname", "client.ip", "dns.question.name", "dns.question.type", "dns.response_code",
                   "dns.answers.data", "dns.response_time_ms"], CLIENT), "search", 0, 91, 48, 16),
]
dashboard(DASH_DNSTAP, "[BIND] DNS answers (dnstap)",
          "Answers sent by BIND, captured with dnstap and exported by the bind_dns Ansible role.", dn)

# ======================================================== text-log dashboard
L = DV_LOG
lg = nav("bind-log", (
    "BIND's text logs (all logging categories, via bind-log-pipeline). Query-log panels only show the "
    "question; the dnstap dashboard has the answers.")) + [

    (metric_vis("bind-log-kpi-events", "Log events", L, count("Events")), "lens", 0, 4, 8, 6),
    (metric_vis("bind-log-kpi-errors", "Errors and warnings", L,
                count("Errors / warnings", "log.level:(error or warning or critical)")), "lens", 8, 4, 8, 6),
    (metric_vis("bind-log-kpi-failures", "Failures", L, count("Failures", "event.outcome:failure")), "lens", 16, 4, 8, 6),
    (metric_vis("bind-log-kpi-denials", "Security denials", L,
                count("Denied", "bind.security.decision:denied")), "lens", 24, 4, 8, 6),
    (metric_vis("bind-log-kpi-transfers", "Zone transfers", L,
                count("Transfers", "bind.category:(xfer-in or xfer-out) and bind.transfer.zone:*")), "lens", 32, 4, 8, 6),
    (metric_vis("bind-log-kpi-updates", "Dynamic updates", L, count("Updates", "bind.update.action:*")),
     "lens", 40, 4, 8, 6),

    (xy_vis("bind-log-over-time", "Log events over time by category", L,
            {"t": date_hist(), "c": terms("bind.category", "Category", "v", 10), "v": count("Events")},
            ["v"], "t", "c"), "lens", 0, 10, 32, 13),
    (pie_vis("bind-log-levels", "Log levels", L, terms("log.level", "Level", "v", 8), count("Events")),
     "lens", 32, 10, 16, 13),

    (xy_vis("bind-log-denials-over-time", "Security denials over time by target", L,
            {"t": date_hist(), "g": terms("bind.security.target", "Target", "v", 5), "v": count("Denied")},
            ["v"], "t", "g", kql="bind.security.decision:denied"), "lens", 0, 23, 24, 13),
    (table_vis("bind-log-denied-clients", "Denied clients", L,
               {"c": terms("client.ip", "Client", "v", 15, data_type="ip", other=False), "v": count("Denied"),
                "t": metric("unique_count", "bind.security.target", "Distinct targets")},
               "bind.security.decision:denied"), "lens", 24, 23, 24, 13),

    (table_vis("bind-log-transfers", "Zone transfers by zone", L,
               {"z": terms("bind.transfer.zone", "Zone", "v", 20, other=False),
                "d": terms("bind.category", "Direction", "v", 2, other=False), "v": count("Events"),
                "l": metric("max", "@timestamp", "Last seen", data_type="date")},
               "bind.category:(xfer-in or xfer-out) and bind.transfer.zone:*"), "lens", 0, 36, 24, 14),
    (table_vis("bind-log-serials", "Latest zone serials (from notify / transfer logs)", L,
               {"z": terms("bind.zone.name", "Zone", "s", 20, other=False),
                "s": metric("max", "bind.zone.serial", "Latest serial"), "v": count("Events")},
               "bind.zone.serial:*"), "lens", 24, 36, 24, 14),

    (table_vis("bind-log-lame", "Resolver errors (lame servers, unreachable, timeouts)", L,
               {"n": terms("bind.resolving.name", "Name", "v", 15, other=False),
                "r": terms("bind.error.reason", "Reason", "v", 3, other=False),
                "v": count("Events"), "s": metric("unique_count", "bind.resolving.server_ip", "Servers")},
               "bind.error.reason:*"), "lens", 0, 50, 24, 14),
    (table_vis("bind-log-updates", "Dynamic updates", L,
               {"z": terms("bind.update.zone", "Zone", "v", 15, other=False),
                "a": terms("bind.update.action", "Action", "v", 5, other=False),
                "k": terms("bind.tsig_key", "TSIG key", "v", 5, other=False), "v": count("Updates")},
               "bind.update.action:*"), "lens", 24, 50, 24, 14),

    (table_vis("bind-log-query-names", "Query log: top names", L,
               {"n": terms("dns.question.name", "Name", "v", 15, other=False),
                "q": terms("dns.question.type", "Type", "v", 3, other=False), "v": count("Queries")},
               "bind.category:queries"), "lens", 0, 64, 24, 14),
    (table_vis("bind-log-query-clients", "Query log: top clients", L,
               {"c": terms("client.ip", "Client", "v", 15, data_type="ip", other=False), "v": count("Queries"),
                "u": metric("unique_count", "dns.question.name", "Distinct names")},
               "bind.category:queries"), "lens", 24, 64, 24, 14),

    (saved_search("bind-log-search-problems", "BIND log errors, warnings and failures", L,
                  ["bind.category", "log.level", "client.ip", "bind.message"],
                  "log.level:(error or warning or critical) or event.outcome:failure"), "search", 0, 78, 48, 16),
]
dashboard(DASH_LOG, "[BIND] Server logs",
          "BIND text logs parsed by bind-log-pipeline: activity, errors, security, transfers, updates.", lg)

with open(OUT, "w", encoding="utf-8", newline="\n") as f:
    for o in objects:
        f.write(json.dumps(o, separators=(",", ":")) + "\n")
print(f"wrote {len(objects)} saved objects to {OUT}")
