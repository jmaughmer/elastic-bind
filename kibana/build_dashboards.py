#!/usr/bin/env python3
"""Generate kibana/bind-dashboards.ndjson: data views, Lens visualizations,
saved searches and three dashboards for the BIND data streams (one also
combining dnstap with the Network Packet Capture integration's DNS data).

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
DV_TRAFFIC = "bind-dns-traffic-data-view"
DASH_DNSTAP = "bind-dnstap-dashboard"
DASH_LOG = "bind-log-dashboard"
DASH_TRAFFIC = "bind-dns-traffic-dashboard"

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


DNS_RUNTIME = {
    # event.duration is nanoseconds; dashboards read milliseconds.
    "dns.response_time_ms": {"type": "double", "script": {"source":
        "if (doc.containsKey('event.duration') && doc['event.duration'].size() > 0) "
        "{ emit(doc['event.duration'].value / 1000000.0); }"}},
    # Length of the leftmost label: long random labels are a classic sign of
    # DGA malware or random-subdomain (water-torture) attacks.
    "dns.question.first_label_length": {"type": "long", "script": {"source":
        "if (doc.containsKey('dns.question.name') && doc['dns.question.name'].size() > 0) "
        "{ String n = doc['dns.question.name'].value; int i = n.indexOf('.'); emit(i < 0 ? n.length() : i); }"}},
    # Shannon entropy (bits per character) of the leftmost label: random,
    # machine-generated labels (DGA, tunnelled data) score high, words low.
    "dns.question.first_label_entropy": {"type": "double", "script": {"source":
        "if (doc.containsKey('dns.question.name') && doc['dns.question.name'].size() > 0) {"
        " String n = doc['dns.question.name'].value; int i = n.indexOf('.'); String l = i < 0 ? n : n.substring(0, i);"
        " if (l.length() > 0) { Map c = new HashMap();"
        " for (int k = 0; k < l.length(); k++) { String ch = l.substring(k, k + 1); c.put(ch, c.containsKey(ch) ? c.get(ch) + 1 : 1); }"
        " double h = 0; for (def v : c.values()) { double p = v / (double) l.length(); h -= p * Math.log(p) / Math.log(2); }"
        " emit(h); } }"}},
    # The zone an answer came from: dnstap's query_zone (authoritative and
    # upstream answers carry it), else the registered domain.
    "dns.zone": {"type": "keyword", "script": {"source":
        "if (doc.containsKey('bind.dnstap.query_zone') && doc['bind.dnstap.query_zone'].size() > 0) { emit(doc['bind.dnstap.query_zone'].value); }"
        " else if (doc.containsKey('dns.question.registered_domain') && doc['dns.question.registered_domain'].size() > 0) { emit(doc['dns.question.registered_domain'].value); }"}},
    # Client network: IPv4 /24, IPv6 /48.
    "client.subnet": {"type": "keyword", "script": {"source":
        "if (doc.containsKey('client.ip') && doc['client.ip'].size() > 0) { String ip = doc['client.ip'].value;"
        " if (ip.indexOf(':') < 0) { emit(ip.substring(0, ip.lastIndexOf('.')) + '.0/24'); }"
        " else { int dc = ip.indexOf('::'); int n = 0; int k = 0;"
        " for (; k < ip.length(); k++) { if (ip.charAt(k) == (char) ':') { n++; if (n == 3) { break; } } }"
        " String p = (dc >= 0 && dc < k) ? ip.substring(0, dc) : ip.substring(0, k);"
        " emit(p + '::/48'); } }"}},
    # DNS message size classes that matter for UDP: fits the classic 512-byte
    # limit, fits the 1232-byte EDNS default, needs a bigger EDNS buffer, or
    # only works over TCP.
    "bind.dnstap.message_size_class": {"type": "keyword", "script": {"source":
        "if (doc.containsKey('bind.dnstap.message_size') && doc['bind.dnstap.message_size'].size() > 0) {"
        " long s = doc['bind.dnstap.message_size'].value;"
        " emit(s <= 512 ? '1. up to 512 B' : s <= 1232 ? '2. 513-1232 B' : s <= 4096 ? '3. 1233-4096 B' : '4. over 4096 B'); }"}},
}
data_view(DV_DNSTAP, "logs-bind.dnstap-*", "BIND DNS messages (dnstap)", DNS_RUNTIME)
# Both DNS sources in one data view: BIND's dnstap export and the Network
# Packet Capture integration's DNS transactions (logs-network_traffic.dns-*,
# Packetbeat's ECS fields). dns.source names which one an event came from.
data_view(DV_TRAFFIC, "logs-bind.dnstap-*,logs-network_traffic.dns-*", "DNS traffic (dnstap + packet capture)", {
    **DNS_RUNTIME,
    "dns.source": {"type": "keyword", "script": {"source":
        "if (doc.containsKey('data_stream.dataset') && doc['data_stream.dataset'].size() > 0) {"
        " String d = doc['data_stream.dataset'].value;"
        " emit(d == 'bind.dnstap' ? 'BIND (dnstap)' : d == 'network_traffic.dns' ? 'Packet capture' : d); }"}},
})
# Zone serials are identifiers (2026101409), not quantities: no thousands separators.
data_view(DV_LOG, "logs-bind-*", "BIND server logs", {}, {"bind.zone.serial": {"id": "string"}})


# ----------------------------------------------------------------- Lens helpers
def count(label, kql=None, per_second=False):
    c = {"label": label, "customLabel": True, "dataType": "number", "operationType": "count",
         "isBucketed": False, "scale": "ratio", "sourceField": "___records___", "params": {"emptyAsNull": True}}
    if kql:
        c["filter"] = {"query": kql, "language": "kuery"}
    if per_second:
        c["timeScale"] = "s"   # normalize to a rate: messages per second
    return c


def filters(label, buckets):
    """Bucket by KQL filters: buckets is a list of (label, kql)."""
    return {"label": label, "customLabel": True, "dataType": "string", "operationType": "filters",
            "isBucketed": True, "scale": "ordinal",
            "params": {"filters": [{"input": {"query": q, "language": "kuery"}, "label": l} for l, q in buckets]}}


def metric(op, field, label, kql=None, params=None, data_type="number", decimals=None):
    c = {"label": label, "customLabel": True, "dataType": data_type, "operationType": op, "isBucketed": False,
         "scale": "ratio", "sourceField": field, "params": dict(params or {})}
    if decimals is None and field == "bind.dnstap.message_size":
        decimals = 0   # bytes
    if decimals is not None:
        c["params"]["format"] = {"id": "number", "params": {"decimals": decimals}}
    if op in ("unique_count", "sum", "average", "max", "min", "median"):
        c["params"].setdefault("emptyAsNull", True)
    if kql:
        c["filter"] = {"query": kql, "language": "kuery"}
    return c


def date_hist():
    return {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
            "sourceField": "@timestamp", "isBucketed": True, "scale": "interval",
            "params": {"interval": "auto", "includeEmptyRows": True, "dropPartials": False}}


def terms(field, label, order_by, size=10, data_type="string", other=True, ascending=False):
    return {"label": label, "customLabel": True, "dataType": data_type, "operationType": "terms",
            "sourceField": field, "isBucketed": True, "scale": "ordinal",
            "params": {"size": size, "orderBy": {"type": "column", "columnId": order_by},
                       "orderDirection": "asc" if ascending else "desc",
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
    if column["operationType"] in ("count", "unique_count", "sum"):
        # A count of nothing is 0, not "N/A".
        column["params"] = dict(column["params"], emptyAsNull=False)
    return lens(obj_id, title, dv, "lnsMetric", {"m": column},
                {"layerId": "L1", "layerType": "data", "metricAccessor": "m"}, kql)


def xy_vis(obj_id, title, dv, columns, accessors, x, split=None, series="bar_stacked", kql="", legend="right"):
    if split:
        # Split first: otherwise Lens ranks the top N within each time bucket
        # instead of overall, and the legend fills with one-off values.
        columns = {split: columns[split], **{k: v for k, v in columns.items() if k != split}}
    layer = {"layerId": "L1", "layerType": "data", "seriesType": series, "position": "top",
             "showGridlines": False, "xAccessor": x, "accessors": accessors}
    if split:
        layer["splitAccessor"] = split
    return lens(obj_id, title, dv, "lnsXY", columns, {
        "legend": {"isVisible": True, "position": legend}, "valueLabels": "hide", "fittingFunction": "Linear",
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
        if n > 2:   # everything below the two nav panels
            y += NAV_ROWS - 4
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


DASH_RESOLVER = "bind-resolver-dashboard"
DASH_FORWARDER = "bind-forwarder-dashboard"
DASH_AUTH = "bind-authoritative-dashboard"
DASH_THREAT = "bind-threat-dashboard"
DASH_CAPACITY = "bind-capacity-dashboard"
NAV_ROWS = 6   # height of the nav rows below; dashboards lay their panels out from y=4, shifted by NAV_ROWS - 4


def nav(prefix, note):
    """Top rows: a Links panel to every dashboard, then a short description."""
    return [
        (links(f"{prefix}-links", "BIND dashboards",
               [(DASH_DNSTAP, "Answers"), (DASH_TRAFFIC, "DNS traffic (+ packet capture)"),
                (DASH_RESOLVER, "Resolver internals"), (DASH_FORWARDER, "Forwarders"),
                (DASH_AUTH, "Authoritative"), (DASH_THREAT, "Threat hunting"),
                (DASH_CAPACITY, "Capacity"), (DASH_LOG, "Server logs")]), "links", 0, 0, 48, 2),
        (markdown(f"{prefix}-about", "About this dashboard", note), "visualization", 0, 2, 48, 4),
    ]

# ======================================================== dnstap dashboard
D = DV_DNSTAP
# What the server answered clients (not its own upstream lookups). BIND logs
# an answer to a query with recursion desired (RD) as CLIENT_RESPONSE and one
# without as AUTH_RESPONSE: on an authoritative server, most of what other
# resolvers ask arrives without RD.
CLIENT = "event.action:(client_response or auth_response)"
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

# ============================================ dnstap + packet capture dashboard
T = DV_TRAFFIC
BIND_ANS = 'data_stream.dataset:"bind.dnstap" and event.action:("client_response" or "auth_response")'
# Packetbeat writes one event per DNS transaction: the question and, if one
# came back, the answer. No response code means no answer was seen.
WIRE = 'data_stream.dataset:"network_traffic.dns"'
WIRE_ANS = f"{WIRE} and dns.response_code:*"
WIRE_NOANS = f"{WIRE} and not dns.response_code:*"
# One event per answered (or, on the wire, attempted) lookup from each source.
TRAFFIC = f"({BIND_ANS}) or ({WIRE})"
TIMED = f"({BIND_ANS}) or ({WIRE_ANS})"
FAILED = "dns.response_code:(SERVFAIL or REFUSED)"


def by_source(label_bind, label_wire, kql=None):
    """Two count columns, one per source, for side-by-side tables."""
    extra = f" and ({kql})" if kql else ""
    return {"b": count(label_bind, f"({BIND_ANS}){extra}"), "w": count(label_wire, f"({WIRE}){extra}")}


SRC = terms("dns.source", "Source", "v", 3)

tr = nav("bind-traffic", (
    "BIND's own record of its answers (dnstap) next to the DNS traffic Elastic's Network Packet Capture "
    "integration sees on the wire. If the capture runs on the BIND servers, both see the same lookups, so "
    "panels compare the sources instead of adding them up. Only the wire shows DNS servers other than BIND "
    "and queries that never got an answer.")) + [

    (metric_vis("bind-traffic-kpi-bind", "Answers sent by BIND (dnstap)", T, count("Answers"), BIND_ANS),
     "lens", 0, 4, 8, 6),
    (metric_vis("bind-traffic-kpi-wire", "DNS transactions on the wire", T, count("Transactions"), WIRE),
     "lens", 8, 4, 8, 6),
    (metric_vis("bind-traffic-kpi-unanswered", "Unanswered queries on the wire", T, count("Unanswered"),
                WIRE_NOANS), "lens", 16, 4, 8, 6),
    (metric_vis("bind-traffic-kpi-servers", "DNS servers seen on the wire", T,
                metric("unique_count", "server.ip", "Servers"), WIRE), "lens", 24, 4, 8, 6),
    (metric_vis("bind-traffic-kpi-p50-bind", "Median response time, BIND (ms)", T,
                metric("median", "dns.response_time_ms", "Median ms"), BIND_ANS), "lens", 32, 4, 8, 6),
    (metric_vis("bind-traffic-kpi-p50-wire", "Median response time, wire (ms)", T,
                metric("median", "dns.response_time_ms", "Median ms"), WIRE_ANS), "lens", 40, 4, 8, 6),

    (xy_vis("bind-traffic-over-time", "DNS traffic over time by source", T,
            {"t": date_hist(), "s": SRC, "v": count("Lookups")}, ["v"], "t", "s", series="line", kql=TRAFFIC, legend="bottom"),
     "lens", 0, 10, 32, 13),
    (xy_vis("bind-traffic-rcodes", "Response codes by source", T,
            {"r": terms("dns.response_code", "Response code", "v", 8, other=False), "s": SRC, "v": count("Lookups")},
            ["v"], "r", "s", series="bar_horizontal", kql=TIMED, legend="bottom"), "lens", 32, 10, 16, 13),

    (xy_vis("bind-traffic-p50", "Median response time (ms) by source", T,
            {"t": date_hist(), "s": SRC, "v": metric("median", "dns.response_time_ms", "Median ms")},
            ["v"], "t", "s", series="line", kql=TIMED, legend="bottom"), "lens", 0, 23, 24, 13),
    (xy_vis("bind-traffic-p95", "95th percentile response time (ms) by source", T,
            {"t": date_hist(), "s": SRC,
             "v": metric("percentile", "dns.response_time_ms", "p95 ms", params={"percentile": 95})},
            ["v"], "t", "s", series="line", kql=TIMED, legend="bottom"), "lens", 24, 23, 24, 13),

    (table_vis("bind-traffic-servers",
               "DNS servers clients use (packet capture; anything that isn't one of your BIND servers bypasses them)", T,
               {"s": terms("server.ip", "DNS server", "v", 15, data_type="ip", other=False), "v": count("Transactions"),
                "c": metric("unique_count", "client.ip", "Clients"),
                "n": count("Unanswered", "not dns.response_code:*"),
                "m": metric("median", "dns.response_time_ms", "Median ms")}, WIRE), "lens", 0, 36, 24, 14),
    (table_vis("bind-traffic-client-servers",
               "Clients by number of DNS servers they use (packet capture; more than your BIND servers means some bypass them)", T,
               {"c": terms("client.ip", "Client", "u", 15, data_type="ip", other=False),
                "u": metric("unique_count", "server.ip", "DNS servers"), "v": count("Transactions"),
                "n": count("Unanswered", "not dns.response_code:*")}, WIRE), "lens", 24, 36, 24, 14),

    (table_vis("bind-traffic-top-names", "Top queried names: BIND vs wire", T,
               {"n": terms("dns.question.name", "Name", "t", 15, other=False), "t": count("Both sources"),
                **by_source("BIND answers", "Wire transactions"),
                "c": metric("unique_count", "client.ip", "Clients")}, TRAFFIC), "lens", 0, 50, 24, 15),
    (table_vis("bind-traffic-top-clients", "Top clients: BIND vs wire", T,
               {"c": terms("client.ip", "Client", "t", 15, data_type="ip", other=False), "t": count("Both sources"),
                **by_source("BIND answers", "Wire transactions"),
                "u": metric("unique_count", "dns.question.name", "Distinct names")}, TRAFFIC), "lens", 24, 50, 24, 15),

    (table_vis("bind-traffic-nxdomain", "NXDOMAIN by domain: BIND vs wire", T,
               {"d": terms("dns.question.registered_domain", "Domain", "t", 15, other=False), "t": count("Both sources"),
                **by_source("BIND", "Wire"),
                "u": metric("unique_count", "dns.question.name", "Distinct names")},
               f"({TRAFFIC}) and dns.response_code:NXDOMAIN"), "lens", 0, 65, 24, 14),
    (table_vis("bind-traffic-unanswered", "Unanswered queries on the wire (no response seen)", T,
               {"n": terms("dns.question.name", "Name", "v", 15, other=False), "v": count("Queries"),
                "s": metric("unique_count", "server.ip", "Servers"),
                "c": metric("unique_count", "client.ip", "Clients")}, WIRE_NOANS), "lens", 24, 65, 24, 14),

    (xy_vis("bind-traffic-qtypes", "Query types by source", T,
            {"q": terms("dns.question.type", "Query type", "v", 8, other=False), "s": SRC, "v": count("Lookups")},
            ["v"], "q", "s", series="bar_horizontal", kql=TRAFFIC, legend="bottom"), "lens", 0, 79, 16, 12),
    (table_vis("bind-traffic-failures", "SERVFAIL / REFUSED by server: BIND vs wire", T,
               {"s": terms("server.ip", "Server", "t", 10, data_type="ip", other=False), "t": count("Both sources"),
                **by_source("BIND", "Wire")}, f"({TIMED}) and {FAILED}"), "lens", 16, 79, 16, 12),
    (table_vis("bind-traffic-resolved", "Top resolved addresses: BIND vs wire", T,
               {"i": terms("dns.resolved_ip", "Address", "t", 15, data_type="ip", other=False), "t": count("Both sources"),
                **by_source("BIND", "Wire")}, TRAFFIC), "lens", 32, 79, 16, 12),

    (saved_search("bind-traffic-search", "DNS traffic: dnstap and packet capture", T,
                  ["dns.source", "client.ip", "server.ip", "dns.question.name", "dns.question.type",
                   "dns.response_code", "dns.answers.data", "dns.response_time_ms"], TRAFFIC), "search", 0, 91, 48, 16),
]
dashboard(DASH_TRAFFIC, "[BIND] DNS traffic (dnstap + packet capture)",
          "BIND's dnstap answers alongside the Network Packet Capture integration's DNS transactions.", tr)

# ======================================================== resolver internals
# named's own lookups to other servers. BIND logs every query it sends while
# resolving (to authorities, and to forwarders) as RESOLVER_QUERY and the reply
# as RESOLVER_RESPONSE, never as FORWARDER_*. Lookups sent to forwarders are the
# ones with recursion desired (RD) set; iterative ones to authorities have none.
UP_Q = "event.action:resolver_query"
UP_R = "event.action:resolver_response"
ITER_Q = f"{UP_Q} and not dns.header_flags:RD"
FWD_Q = f"{UP_Q} and dns.header_flags:RD"
FWD_R = f"{UP_R} and dns.header_flags:RD"
FWD = f"event.action:(resolver_query or resolver_response) and dns.header_flags:RD"
CLIENT_Q = "event.action:client_query"

rs = nav("bind-resolver", (
    "What a recursive server does behind its cache: every lookup named sends to other servers while resolving. "
    "Needs `resolver query` and `resolver response` in `bind_dnstap_types` (and `client query` for the "
    "client-queries comparison). Lookups to forwarders have their own dashboard.")) + [

    (metric_vis("bind-resolver-kpi-client", "Client queries", D, count("Queries"), CLIENT_Q), "lens", 0, 4, 8, 6),
    (metric_vis("bind-resolver-kpi-upstream", "Upstream lookups (iterative)", D, count("Lookups"), ITER_Q),
     "lens", 8, 4, 8, 6),
    (metric_vis("bind-resolver-kpi-forwarded", "Lookups sent to forwarders", D, count("Lookups"), FWD_Q),
     "lens", 16, 4, 8, 6),
    (metric_vis("bind-resolver-kpi-failures", "Failed upstream answers", D,
                count("Failures", "event.outcome:failure"), UP_R), "lens", 24, 4, 8, 6),
    (metric_vis("bind-resolver-kpi-servers", "Servers contacted", D,
                metric("unique_count", "server.ip", "Servers"), UP_Q), "lens", 32, 4, 8, 6),
    (metric_vis("bind-resolver-kpi-p50", "Median upstream response time (ms)", D,
                metric("median", "dns.response_time_ms", "Median ms"), UP_R), "lens", 40, 4, 8, 6),

    (xy_vis("bind-resolver-cache", "Client queries vs upstream lookups (the gap is answered from cache)", D,
            {"t": date_hist(), "c": count("Client queries", CLIENT_Q), "u": count("Upstream lookups", UP_Q)},
            ["c", "u"], "t", series="line", legend="bottom"), "lens", 0, 10, 32, 13),
    (pie_vis("bind-resolver-rcodes", "Upstream response codes", D,
             terms("dns.response_code", "Response code", "v", 8), count("Answers"), UP_R), "lens", 32, 10, 16, 13),

    (table_vis("bind-resolver-servers", "Upstream servers", D,
               {"s": terms("server.ip", "Server", "q", 15, data_type="ip", other=False),
                "q": count("Lookups", UP_Q), "a": count("Answered", UP_R),
                "f": count("Failures", f"{UP_R} and event.outcome:failure"),
                "m": metric("median", "dns.response_time_ms", "Median ms"),
                "p": metric("percentile", "dns.response_time_ms", "p95 ms", params={"percentile": 95})},
               f"event.action:(resolver_query or resolver_response)"), "lens", 0, 23, 24, 15),
    (table_vis("bind-resolver-zones", "Zones looked up (the zone each upstream server was asked as an authority for)", D,
               {"z": terms("bind.dnstap.query_zone", "Zone", "v", 15, other=False), "v": count("Lookups"),
                "s": metric("unique_count", "server.ip", "Servers"),
                "m": metric("median", "dns.response_time_ms", "Median ms")}, UP_R), "lens", 24, 23, 24, 15),

    (table_vis("bind-resolver-latency", "Slowest upstream servers (by 95th percentile)", D,
               {"s": terms("server.ip", "Server", "p", 10, data_type="ip", other=False),
                "p": metric("percentile", "dns.response_time_ms", "p95 ms", params={"percentile": 95}),
                "m": metric("median", "dns.response_time_ms", "Median ms"),
                "x": metric("max", "dns.response_time_ms", "Max ms"), "v": count("Answers"),
                "z": metric("unique_count", "bind.dnstap.query_zone", "Zones")}, UP_R), "lens", 0, 38, 24, 13),
    (table_vis("bind-resolver-truncated", "Truncated upstream answers (retried over TCP)", D,
               {"s": terms("server.ip", "Server", "v", 10, data_type="ip", other=False),
                "v": count("Truncated", "dns.header_flags:TC"),
                "t": count("Lookups over TCP", "network.transport:tcp")}, UP_R), "lens", 24, 38, 24, 13),

    (table_vis("bind-resolver-misses", "Names needing the most upstream lookups (cache misses)", D,
               {"n": terms("dns.question.name", "Name", "v", 15, other=False), "v": count("Lookups"),
                "s": metric("unique_count", "server.ip", "Servers")}, ITER_Q), "lens", 0, 51, 24, 14),
    (table_vis("bind-resolver-failing", "Failing upstream lookups", D,
               {"n": terms("dns.question.name", "Name", "v", 15, other=False),
                "r": terms("dns.response_code", "Code", "v", 3, other=False),
                "s": metric("unique_count", "server.ip", "Servers"), "v": count("Answers")},
               f"{UP_R} and event.outcome:failure"), "lens", 24, 51, 24, 14),

    (saved_search("bind-resolver-search", "BIND upstream lookups", D,
                  ["observer.hostname", "server.ip", "bind.dnstap.query_zone", "dns.question.name", "dns.question.type",
                   "dns.response_code", "dns.header_flags", "dns.response_time_ms"], UP_R), "search", 0, 65, 48, 16),
]
dashboard(DASH_RESOLVER, "[BIND] Resolver internals (upstream lookups)",
          "What a recursive BIND server asks other servers while resolving, from dnstap resolver messages.", rs)

# ================================================================ forwarders
fw = nav("bind-forwarder", (
    "Health of the forwarders recursive servers use (`bind_forwarders`, or `type: forward` zones). Needs "
    "`resolver query` and `resolver response` in `bind_dnstap_types`: BIND records forwarded lookups as "
    "resolver messages with recursion desired set. Lookups sent but never answered are the forwarder's "
    "timeouts.")) + [

    (metric_vis("bind-forwarder-kpi-sent", "Lookups sent to forwarders", D, count("Sent"), FWD_Q), "lens", 0, 4, 8, 6),
    (metric_vis("bind-forwarder-kpi-answered", "Answered", D, count("Answered"), FWD_R), "lens", 8, 4, 8, 6),
    (metric_vis("bind-forwarder-kpi-servers", "Forwarders used", D,
                metric("unique_count", "server.ip", "Forwarders"), FWD_Q), "lens", 16, 4, 8, 6),
    (metric_vis("bind-forwarder-kpi-failures", "Failed answers", D,
                count("Failures", "event.outcome:failure"), FWD_R), "lens", 24, 4, 8, 6),
    (metric_vis("bind-forwarder-kpi-p50", "Median response time (ms)", D,
                metric("median", "dns.response_time_ms", "Median ms"), FWD_R), "lens", 32, 4, 8, 6),
    (metric_vis("bind-forwarder-kpi-p95", "95th percentile response time (ms)", D,
                metric("percentile", "dns.response_time_ms", "p95 ms", params={"percentile": 95}), FWD_R),
     "lens", 40, 4, 8, 6),

    (xy_vis("bind-forwarder-over-time", "Lookups sent by forwarder", D,
            {"t": date_hist(), "s": terms("server.ip", "Forwarder", "v", 6, data_type="ip", other=False),
             "v": count("Lookups")}, ["v"], "t", "s", kql=FWD_Q, legend="bottom"), "lens", 0, 10, 24, 13),
    (xy_vis("bind-forwarder-latency", "Response time by forwarder (median ms)", D,
            {"t": date_hist(), "s": terms("server.ip", "Forwarder", "v", 6, data_type="ip", other=False),
             "v": metric("median", "dns.response_time_ms", "Median ms")},
            ["v"], "t", "s", series="line", kql=FWD_R, legend="bottom"), "lens", 24, 10, 24, 13),

    (table_vis("bind-forwarder-table", "Forwarders: sent, answered (the difference timed out), failures and latency", D,
               {"s": terms("server.ip", "Forwarder", "q", 10, data_type="ip", other=False),
                "q": count("Sent", FWD_Q), "a": count("Answered", FWD_R),
                "f": count("Failures", f"{FWD_R} and event.outcome:failure"),
                "m": metric("median", "dns.response_time_ms", "Median ms"),
                "p": metric("percentile", "dns.response_time_ms", "p95 ms", params={"percentile": 95})},
               FWD), "lens", 0, 23, 24, 14),
    (xy_vis("bind-forwarder-rcodes", "Response codes by forwarder", D,
            {"s": terms("server.ip", "Forwarder", "v", 6, data_type="ip", other=False),
             "r": terms("dns.response_code", "Response code", "v", 6), "v": count("Answers")},
            ["v"], "s", "r", series="bar_horizontal_stacked", kql=FWD_R, legend="bottom"), "lens", 24, 23, 24, 14),

    (table_vis("bind-forwarder-zones", "Forwarded zones", D,
               {"z": terms("bind.dnstap.query_zone", "Zone", "v", 15, other=False), "v": count("Answers"),
                "s": metric("unique_count", "server.ip", "Forwarders"),
                "m": metric("median", "dns.response_time_ms", "Median ms")}, FWD_R), "lens", 0, 37, 24, 14),
    (table_vis("bind-forwarder-failing", "Names forwarders answered with an error (SERVFAIL, REFUSED, ...)", D,
               {"n": terms("dns.question.name", "Name", "v", 15, other=False),
                "r": terms("dns.response_code", "Code", "v", 3, other=False),
                "s": terms("server.ip", "Forwarder", "v", 3, data_type="ip", other=False), "v": count("Answers")},
               f"{FWD_R} and event.outcome:failure"), "lens", 24, 37, 24, 14),

    (saved_search("bind-forwarder-search", "BIND forwarded lookups", D,
                  ["observer.hostname", "server.ip", "bind.dnstap.query_zone", "dns.question.name",
                   "dns.question.type", "dns.response_code", "dns.response_time_ms"], FWD_R), "search", 0, 51, 48, 16),
]
dashboard(DASH_FORWARDER, "[BIND] Forwarders",
          "Lookups recursive BIND servers forward, from dnstap resolver messages with recursion desired.", fw)

# ============================================================= authoritative
# Answers from the server's own zones (AA set), plus REFUSED: a query for a
# zone it doesn't serve, or for recursion it doesn't offer.
AUTH = f"{CLIENT} and (dns.header_flags:AA or dns.response_code:(REFUSED or NOTAUTH))"
DO = "dns.header_flags:DO"

au = nav("bind-auth", (
    "What an authoritative server is asked and answers, zone by zone. Needs `auth response` (and `client response`) "
    "in `bind_dnstap_types`: resolvers querying an authoritative server don't set recursion desired, so BIND logs "
    "those answers as AUTH_RESPONSE. Client location and network need the pipeline's GeoIP lookups (public "
    "addresses only). Filter on a server with the table at the bottom.")) + [

    (metric_vis("bind-auth-kpi-answers", "Authoritative answers", D, count("Answers"), AUTH), "lens", 0, 4, 8, 6),
    (metric_vis("bind-auth-kpi-clients", "Querying resolvers", D,
                metric("unique_count", "client.ip", "Clients"), AUTH), "lens", 8, 4, 8, 6),
    (metric_vis("bind-auth-kpi-nxdomain", "NXDOMAIN", D, count("NXDOMAIN", "dns.response_code:NXDOMAIN"), AUTH),
     "lens", 16, 4, 8, 6),
    (metric_vis("bind-auth-kpi-refused", "REFUSED (not our zone, or recursion)", D,
                count("REFUSED", "dns.response_code:REFUSED"), AUTH), "lens", 24, 4, 8, 6),
    (metric_vis("bind-auth-kpi-any", "ANY queries", D, count("ANY", "dns.question.type:ANY"), AUTH),
     "lens", 32, 4, 8, 6),
    (metric_vis("bind-auth-kpi-size", "Median answer size (bytes)", D,
                metric("median", "bind.dnstap.message_size", "Median bytes"), AUTH), "lens", 40, 4, 8, 6),

    (xy_vis("bind-auth-over-time", "Answers over time by response code", D,
            {"t": date_hist(), "s": terms("dns.response_code", "Response code", "v", 6), "v": count("Answers")},
            ["v"], "t", "s", kql=AUTH), "lens", 0, 10, 32, 13),
    (pie_vis("bind-auth-zones", "Answers by zone", D, terms("dns.zone", "Zone", "v", 10), count("Answers"),
             f"{AUTH} and not dns.response_code:REFUSED"), "lens", 32, 10, 16, 13),

    (table_vis("bind-auth-names", "Top names asked", D,
               {"n": terms("dns.question.name", "Name", "v", 15, other=False),
                "q": terms("dns.question.type", "Type", "v", 3, other=False), "v": count("Answers")},
               f"{AUTH} and not dns.response_code:REFUSED"), "lens", 0, 23, 16, 15),
    (table_vis("bind-auth-nxdomain", "NXDOMAIN names (typos, stale links, zone walking)", D,
               {"n": terms("dns.question.name", "Name", "v", 15, other=False), "v": count("NXDOMAIN"),
                "c": metric("unique_count", "client.ip", "Clients")}, f"{AUTH} and dns.response_code:NXDOMAIN"),
     "lens", 16, 23, 16, 15),
    (table_vis("bind-auth-refused", "REFUSED clients (open-resolver probing, misconfigured resolvers)", D,
               {"c": terms("client.ip", "Client", "v", 15, data_type="ip", other=False), "v": count("REFUSED"),
                "n": metric("unique_count", "dns.question.name", "Names")}, f"{AUTH} and dns.response_code:REFUSED"),
     "lens", 32, 23, 16, 15),

    (pie_vis("bind-auth-qtypes", "Query types", D, terms("dns.question.type", "Query type", "v", 10),
             count("Answers"), AUTH), "lens", 0, 38, 16, 13),
    (pie_vis("bind-auth-dnssec", "DNSSEC-aware resolvers (DO bit)", D,
             filters("DNSSEC", [("DNSSEC OK (DO set)", DO), ("No DNSSEC", f"not {DO}")]), count("Answers"), AUTH),
     "lens", 16, 38, 16, 13),
    (xy_vis("bind-auth-udp-size", "EDNS buffer size resolvers advertise", D,
            {"u": terms("bind.dnstap.edns.udp_size", "UDP buffer (bytes)", "v", 8, data_type="number", other=False),
             "v": count("Answers")}, ["v"], "u", series="bar_horizontal", kql=AUTH), "lens", 32, 38, 16, 13),

    (table_vis("bind-auth-countries", "Where queries come from", D,
               {"g": terms("client.geo.country_name", "Country", "v", 15, other=False), "v": count("Answers"),
                "c": metric("unique_count", "client.ip", "Resolvers")}, AUTH), "lens", 0, 51, 16, 15),
    (table_vis("bind-auth-networks", "Networks querying (ASN)", D,
               {"o": terms("client.as.organization.name", "Network", "v", 15, other=False), "v": count("Answers"),
                "c": metric("unique_count", "client.ip", "Resolvers")}, AUTH), "lens", 16, 51, 16, 15),
    (table_vis("bind-auth-largest", "Largest answers (amplification potential)", D,
               {"n": terms("dns.question.name", "Name", "m", 15, other=False),
                "q": terms("dns.question.type", "Type", "m", 2, other=False),
                "m": metric("max", "bind.dnstap.message_size", "Max bytes"),
                "a": metric("average", "bind.dnstap.message_size", "Avg bytes"), "v": count("Answers")}, AUTH),
     "lens", 32, 51, 16, 15),

    (table_vis("bind-auth-bytes", "Clients sent the most bytes (spoofed-source floods target these)", D,
               {"c": terms("client.ip", "Client", "b", 15, data_type="ip", other=False),
                "b": metric("sum", "bind.dnstap.message_size", "Bytes sent"), "v": count("Answers"),
                "y": count("ANY", "dns.question.type:ANY")}, AUTH), "lens", 0, 66, 24, 14),
    (xy_vis("bind-auth-by-server", "Answers by server and transport", D,
            {"s": terms("observer.hostname", "Server", "v", 10), "v": count("Answers"),
             "tr": terms("network.transport", "Transport", "v", 3)},
            ["v"], "s", "tr", series="bar_horizontal_stacked", kql=AUTH, legend="bottom"), "lens", 24, 66, 24, 14),

    (saved_search("bind-auth-search", "BIND authoritative answers", D,
                  ["observer.hostname", "client.ip", "client.geo.country_iso_code", "dns.zone", "dns.question.name",
                   "dns.question.type", "dns.response_code", "bind.dnstap.message_size"], AUTH), "search", 0, 80, 48, 16),
]
dashboard(DASH_AUTH, "[BIND] Authoritative server",
          "Queries an authoritative BIND server receives and answers, by zone, client and network.", au)

# ============================================================ threat hunting
# Answers a recursive server gave its own clients: they carry RA (recursion
# available), which an authoritative server's answers to the internet don't.
RECURSIVE = "event.action:client_response and dns.header_flags:RA"
UNUSUAL_TYPES = "not dns.question.type:(A or AAAA or PTR or HTTPS or SVCB or CNAME or SOA or NS or DS or DNSKEY)"
RANDOM = "dns.question.first_label_entropy >= 3.5 and dns.question.first_label_length >= 12"

th = nav("bind-threat", (
    "Lookups worth a second look, from client answers on recursive servers: data tunnelled through DNS, "
    "machine-generated names, unusual record types and rarely seen domains. Long, high-entropy labels are "
    "normal for some CDNs and anti-spam services, so check before acting. To flag known-bad names or "
    "addresses, add an enrich processor with your threat feed to `logs-bind.dnstap@custom`.")) + [

    (metric_vis("bind-threat-kpi-domains", "Distinct domains", D,
                metric("unique_count", "dns.question.registered_domain", "Domains"), RECURSIVE), "lens", 0, 4, 8, 6),
    (metric_vis("bind-threat-kpi-tlds", "Distinct TLDs", D,
                metric("unique_count", "dns.question.top_level_domain", "TLDs"), RECURSIVE), "lens", 8, 4, 8, 6),
    (metric_vis("bind-threat-kpi-long", "Lookups with 40+ character labels", D,
                count("Long labels", "dns.question.first_label_length >= 40"), RECURSIVE), "lens", 16, 4, 8, 6),
    (metric_vis("bind-threat-kpi-random", "Random-looking names", D, count("High entropy", RANDOM), RECURSIVE),
     "lens", 24, 4, 8, 6),
    (metric_vis("bind-threat-kpi-txt", "TXT and NULL lookups", D,
                count("TXT/NULL", "dns.question.type:(TXT or NULL)"), RECURSIVE), "lens", 32, 4, 8, 6),
    (metric_vis("bind-threat-kpi-nx", "NXDOMAIN answers", D,
                count("NXDOMAIN", "dns.response_code:NXDOMAIN"), RECURSIVE), "lens", 40, 4, 8, 6),

    (table_vis("bind-threat-tunnel",
               "Possible DNS tunnelling by domain (many distinct, long, random names; TXT/NULL answers; many bytes)", D,
               {"d": terms("dns.question.registered_domain", "Domain", "u", 15, other=False),
                "u": metric("unique_count", "dns.question.name", "Distinct names"),
                "l": metric("average", "dns.question.first_label_length", "Avg label length"),
                "e": metric("average", "dns.question.first_label_entropy", "Avg entropy"),
                "x": count("TXT/NULL", "dns.question.type:(TXT or NULL)"),
                "b": metric("sum", "bind.dnstap.message_size", "Bytes"),
                "c": metric("unique_count", "client.ip", "Clients")}, RECURSIVE), "lens", 0, 10, 48, 15),

    (table_vis("bind-threat-clients", "Clients with the broadest query profile", D,
               {"c": terms("client.ip", "Client", "d", 15, data_type="ip", other=False),
                "d": metric("unique_count", "dns.question.registered_domain", "Distinct domains"),
                "n": metric("unique_count", "dns.question.name", "Distinct names"),
                "x": count("NXDOMAIN", "dns.response_code:NXDOMAIN"),
                "t": count("TXT/NULL", "dns.question.type:(TXT or NULL)")}, RECURSIVE), "lens", 0, 25, 24, 15),
    (table_vis("bind-threat-first-seen", "Most recently first-seen domains (within the time range)", D,
               {"d": terms("dns.question.registered_domain", "Domain", "f", 15, other=False),
                "f": metric("min", "@timestamp", "First seen", data_type="date"), "v": count("Lookups"),
                "c": metric("unique_count", "client.ip", "Clients")}, RECURSIVE), "lens", 24, 25, 24, 15),

    (table_vis("bind-threat-rare-tlds", "Least-queried TLDs", D,
               {"t": terms("dns.question.top_level_domain", "TLD", "v", 15, other=False, ascending=True),
                "v": count("Lookups"), "d": metric("unique_count", "dns.question.registered_domain", "Domains")},
               RECURSIVE), "lens", 0, 40, 16, 14),
    (table_vis("bind-threat-random", "Random-looking names (entropy 3.5+, 12+ characters)", D,
               {"n": terms("dns.question.name", "Name", "e", 15, other=False),
                "e": metric("max", "dns.question.first_label_entropy", "Entropy"),
                "c": metric("unique_count", "client.ip", "Clients")}, f"{RECURSIVE} and {RANDOM}"), "lens", 16, 40, 16, 14),
    (table_vis("bind-threat-types", "Unusual record types by client", D,
               {"c": terms("client.ip", "Client", "v", 15, data_type="ip", other=False),
                "q": terms("dns.question.type", "Type", "v", 3, other=False), "v": count("Lookups")},
               f"{RECURSIVE} and {UNUSUAL_TYPES}"), "lens", 32, 40, 16, 14),

    (saved_search("bind-threat-search", "BIND suspicious-looking lookups", D,
                  ["client.ip", "dns.question.name", "dns.question.type", "dns.response_code",
                   "dns.question.first_label_length", "dns.question.first_label_entropy", "dns.answers.data"],
                  f"{RECURSIVE} and ({RANDOM} or dns.question.first_label_length >= 40 or dns.question.type:(TXT or NULL))"),
     "search", 0, 54, 48, 16),
]
dashboard(DASH_THREAT, "[BIND] Threat hunting",
          "Signs of DNS tunnelling, machine-generated names and unusual lookups in BIND's client answers.", th)

# ======================================================= capacity and tuning
QUERIES = "event.action:(client_query or auth_query)"

cp = nav("bind-capacity", (
    "Load and the settings it informs: answer rates per server and transport, truncation and TCP fallback, "
    "answer sizes against the EDNS buffer clients offer (`edns-udp-size`, 1232 by default), and response time "
    "by query type and client network. Rates are per second.")) + [

    (metric_vis("bind-capacity-kpi-rate", "Answers per second", D, count("Answers/s", per_second=True), CLIENT),
     "lens", 0, 4, 8, 6),
    (metric_vis("bind-capacity-kpi-tcp", "Answers over TCP", D, count("TCP", "network.transport:tcp"), CLIENT),
     "lens", 8, 4, 8, 6),
    (metric_vis("bind-capacity-kpi-tc", "Truncated answers (TC)", D, count("Truncated", "dns.header_flags:TC"), CLIENT),
     "lens", 16, 4, 8, 6),
    (metric_vis("bind-capacity-kpi-big", "Answers over 1232 bytes", D,
                count("Large", "bind.dnstap.message_size > 1232"), CLIENT), "lens", 24, 4, 8, 6),
    (metric_vis("bind-capacity-kpi-p50", "Median response time (ms)", D,
                metric("median", "dns.response_time_ms", "Median ms"), CLIENT), "lens", 32, 4, 8, 6),
    (metric_vis("bind-capacity-kpi-p99", "99th percentile response time (ms)", D,
                metric("percentile", "dns.response_time_ms", "p99 ms", params={"percentile": 99}), CLIENT),
     "lens", 40, 4, 8, 6),

    (xy_vis("bind-capacity-rate-server", "Answers per second by server", D,
            {"t": date_hist(), "s": terms("observer.hostname", "Server", "v", 10), "v": count("Answers/s", per_second=True)},
            ["v"], "t", "s", series="line", kql=CLIENT, legend="bottom"), "lens", 0, 10, 32, 13),
    (pie_vis("bind-capacity-transport", "Transport", D, terms("network.transport", "Transport", "v", 4),
             count("Answers"), CLIENT), "lens", 32, 10, 16, 13),

    (xy_vis("bind-capacity-rate-transport", "Answers per second by transport", D,
            {"t": date_hist(), "s": terms("network.transport", "Transport", "v", 4), "v": count("Answers/s", per_second=True)},
            ["v"], "t", "s", series="line", kql=CLIENT, legend="bottom"), "lens", 0, 23, 24, 13),
    (xy_vis("bind-capacity-truncated", "Truncated answers (TC) over time, by server", D,
            {"t": date_hist(), "s": terms("observer.hostname", "Server", "v", 10), "v": count("Truncated")},
            ["v"], "t", "s", kql=f"{CLIENT} and dns.header_flags:TC", legend="bottom"), "lens", 24, 23, 24, 13),

    (xy_vis("bind-capacity-udp-size", "EDNS buffer size clients advertise", D,
            {"u": terms("bind.dnstap.edns.udp_size", "UDP buffer (bytes)", "v", 8, data_type="number", other=False),
             "v": count("Queries")}, ["v"], "u", series="bar_horizontal", kql=QUERIES), "lens", 0, 36, 16, 13),
    (pie_vis("bind-capacity-sizes", "Answer sizes", D, terms("bind.dnstap.message_size_class", "Size", "v", 4),
             count("Answers"), CLIENT), "lens", 16, 36, 16, 13),
    (table_vis("bind-capacity-qtype-latency", "Response time by query type", D,
               {"q": terms("dns.question.type", "Type", "v", 12, other=False), "v": count("Answers"),
                "m": metric("median", "dns.response_time_ms", "Median ms"),
                "p": metric("percentile", "dns.response_time_ms", "p95 ms", params={"percentile": 95}),
                "z": metric("average", "bind.dnstap.message_size", "Avg bytes")}, CLIENT), "lens", 32, 36, 16, 13),

    (table_vis("bind-capacity-clients", "Busiest clients", D,
               {"c": terms("client.ip", "Client", "v", 15, data_type="ip", other=False), "v": count("Answers"),
                "r": count("Answers/s", per_second=True),
                "m": metric("median", "dns.response_time_ms", "Median ms")}, CLIENT), "lens", 0, 49, 24, 15),
    (table_vis("bind-capacity-subnets", "Busiest client networks (/24, /48)", D,
               {"s": terms("client.subnet", "Network", "v", 15, other=False), "v": count("Answers"),
                "c": metric("unique_count", "client.ip", "Clients"),
                "m": metric("median", "dns.response_time_ms", "Median ms")}, CLIENT), "lens", 24, 49, 24, 15),
]
dashboard(DASH_CAPACITY, "[BIND] Capacity and tuning",
          "Answer rates, TCP and truncation, answer sizes against EDNS buffers, and latency by query type and network.", cp)

# ======================================================== text-log dashboard
L = DV_LOG
lg = nav("bind-log", (
    "BIND's text logs (all logging categories, via logs-bind@custom). Query-log panels only show the "
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
          "BIND text logs parsed by logs-bind@custom: activity, errors, security, transfers, updates.", lg)

with open(OUT, "w", encoding="utf-8", newline="\n") as f:
    for o in objects:
        f.write(json.dumps(o, separators=(",", ":")) + "\n")
print(f"wrote {len(objects)} saved objects to {OUT}")
