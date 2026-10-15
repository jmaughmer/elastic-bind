# BIND log pipeline for Elasticsearch

Parses BIND9 `named` log lines from all 17 logging categories (`default`,
`general`, `database`, `security`, `config`, `resolver`, `xfer-in`,
`xfer-out`, `notify`, `client`, `unmatched`, `queries`, `network`, `update`,
`dispatch`, `dnssec`, `lame-servers`) into ECS fields plus a `bind.*`
namespace for category-specific detail.

A second pipeline handles **DNS answers**: BIND's text logs only ever
record the question, so the `bind_dns` Ansible role can capture full
messages with dnstap and export them as JSON — see **dnstap answers**
below.

## Files

| File | Purpose |
|---|---|
| [named.conf.logging.conf](named.conf.logging.conf) | BIND logging stanza — routes all 17 categories into one file with `print-time yes` (9.11-compatible), `print-category yes`, `print-severity yes`. |
| [bind-ingest-pipeline.json](bind-ingest-pipeline.json) | The Elasticsearch ingest pipeline (`PUT _ingest/pipeline/bind-log-pipeline`). |
| [logs-bind.log@custom.json](logs-bind.log@custom.json) | Component template with explicit field mappings (ip/long/keyword) that Fleet auto-composes into the `logs-bind.log-*` index template it generates for the dataset. |
| [elastic-agent-custom-logs.yml](elastic-agent-custom-logs.yml) | Stream YAML for Elastic Agent's **Custom Logs** integration (Fleet) — filestream input, wired to the pipeline. |
| [bind-pipeline-simulate-test.json](bind-pipeline-simulate-test.json) | One sample line per category, for `_simulate` testing. |
| [bind-dnstap-pipeline.json](bind-dnstap-pipeline.json) | Ingest pipeline for dnstap answers exported as NDJSON (`PUT _ingest/pipeline/bind-dnstap-pipeline`). |
| [logs-bind.dnstap@custom.json](logs-bind.dnstap@custom.json) | Component template with the field mappings for the `logs-bind.dnstap-*` data stream. |
| [elastic-agent-dnstap.yml](elastic-agent-dnstap.yml) | Stream YAML for a second **Custom Logs** integration that ships the dnstap NDJSON through that pipeline. |
| [bind-dnstap-simulate-test.json](bind-dnstap-simulate-test.json) | Sample exported events (real converter output), for `_simulate` testing. |
| [kibana/bind-dashboards.ndjson](kibana/bind-dashboards.ndjson) | Kibana dashboards for both data streams, with their data views (Saved Objects import). |
| [kibana/build_dashboards.py](kibana/build_dashboards.py) | Generates that NDJSON — edit panels here and re-run, rather than hand-editing the export. |
| [kibana/alert-rules.json](kibana/alert-rules.json) | Kibana alerting rules for the dnstap data (thresholds, queries, what each one means). |
| [kibana/load_alert_rules.py](kibana/load_alert_rules.py) | Creates or updates those rules through Kibana's alerting API. |
| [setup.sh](setup.sh) | Loads both pipelines + component templates, runs both simulate tests, and (with `KIBANA_URL`) imports the dashboards and creates the alerting rules. |

## How it works

1. **Envelope grok** splits every line into `bind.category`, `log.level`,
   and the remaining `bind.message`. It tries BIND's legacy `print-time yes`
   format first (`14-Aug-2026 10:23:45.678` — no UTC offset, what 9.11
   produces) and falls back to ISO8601 (`2026-08-14T10:23:45.678Z`, from
   `print-time iso8601-utc` on versions that support it) if the line looks
   like that instead. Because the legacy format carries no timezone, a
   later `date` processor resolves it using `event.timezone` (defaulting to
   UTC if the shipper didn't set it — see **Timezone** below, this needs
   your attention).
2. `bind.category` drives `event.action`, and a Painless script maps it to
   ECS `event.category`/`event.type` (e.g. `queries`/`client`/`resolver` →
   `network`+`dns`; `xfer-in`/`xfer-out`/`notify` → `network`+`connection`;
   `update` → `configuration`+`change`; `security`/`unmatched` →
   `network`+`denied`).
3. A series of small, **unanchored** grok processors then run against
   `bind.message` and pull out whatever structure is present, regardless of
   category — because message shapes repeat across categories (a `client
   ...: query: ...` line looks the same whether it came from `client`,
   `queries`, or `security`). Each is `ignore_failure`/`ignore_missing`, so
   a category with a message shape not covered here just keeps its full
   text in `bind.message` and isn't dropped or errored.
4. `event.outcome` (`success`/`failure`) is inferred from keywords in the
   message (`denied`, `refused`, `failed`, `lame server`, ... vs.
   `approved`, `succeeded`, `completed`, ...) — useful for building a "DNS
   failures" view across categories without per-category logic in Kibana.
5. `related.ip` aggregates every IP found anywhere in the event
   (client, destination, resolver target, transfer peer, listener), and
   `source.ip` mirrors `client.ip` for compatibility with dashboards that
   expect `source.ip`.
6. The pipeline never drops a document: envelope parse failures are tagged
   (`bind_envelope_parse_failure`) rather than thrown, and there's a
   top-level `on_failure` safety net that tags and records
   `error.message` instead of rejecting the write.

### Timezone (important — required action)

BIND 9.11 doesn't support `print-time iso8601-utc`; `named-checkconf` will
reject it. `named.conf.logging.conf` here uses `print-time yes` instead,
which is accepted on every BIND version but only prints the server's local
clock with no UTC offset (e.g. `14-Aug-2026 10:23:45.678`).

Since the log line itself doesn't say what timezone that is,
[elastic-agent-custom-logs.yml](elastic-agent-custom-logs.yml) sets it
explicitly via `fields.event.timezone`, and the pipeline's `date` processor
resolves `@timestamp` using that value (`{{{event.timezone}}}`). **You must
edit that field to the BIND server's actual IANA timezone name** (e.g.
`America/Chicago`, `Europe/London`) — if left unset, the pipeline falls
back to `UTC`, which will be silently wrong for any server not actually
running in UTC. If you later confirm your BIND build does accept
`iso8601-utc`, switching to it removes this whole concern — the offset is
in the string, so `event.timezone` is ignored for that format.

### Key fields produced

- `@timestamp`, `log.level`, `bind.category`, `bind.message` (cleaned text), `event.action/category/type/outcome`
- `client.ip`, `client.port`, `bind.tsig_key`, `source.ip`, `related.ip`
- `dns.question.name/class/type`, `bind.query.flags`, `destination.ip`
- `bind.resolving.name/type/class/server_ip/server_port` (resolver, lame-servers, network, dnssec)
- `bind.zone.name/class/serial`
- `bind.transfer.zone/class/peer_ip/peer_port/status` (xfer-in, xfer-out)
- `bind.view`, `bind.security.target/decision` (security)
- `bind.update.zone/action/detail` (update)
- `bind.error.reason` (lame-servers, network, resolver errors)
- `bind.listen.ip/port` (config, network startup lines)

## Setup

```bash
ES_URL=https://localhost:9200 ES_AUTH=elastic:yourpassword ./setup.sh
```

That loads both pipelines and their component templates
(`logs-bind.log@custom`, `logs-bind.dnstap@custom`), then runs each
pipeline against its sample file and prints the parsed output — **check
that output before pointing real traffic at it**. Both have been run
against a single-node Elasticsearch 8.17.0, where every sample parsed
cleanly; BIND's exact wording still varies a bit by version, so treat the
simulate step as the acceptance test for your own servers.

Do this *before* enabling the integration below: Fleet only composes a
`@custom` component template into the index template it generates for a
data stream if the component template already exists (or, if the
integration is already running, before the next backing-index rollover).

Then:

1. Drop [named.conf.logging.conf](named.conf.logging.conf)'s content into
   `named.conf` (or an included file) and reload BIND (`rndc reconfig`).
2. In Kibana, go to **Fleet → Agent policies → \<your policy\> → Add
   integration → Custom Logs**. Set:
   - **Dataset name**: `bind.log`
   - **Paths**: `/var/log/named/named.log`
   - Under **Advanced options**, paste
     [elastic-agent-custom-logs.yml](elastic-agent-custom-logs.yml) into the
     "Custom configurations" YAML box (adds the pipeline reference and
     multiline handling the basic fields don't expose) — **first edit its
     `event.timezone` value** to the BIND server's real timezone; see
     **Timezone** above.
3. Save and deploy the policy to the Elastic Agent running on the BIND
   server. It uses the `filestream` input type under the hood — no
   standalone Filebeat/Elastic Agent config file needed.

If your Kibana version doesn't expose that YAML box, run Elastic Agent
standalone instead — the commented-out block at the bottom of
[elastic-agent-custom-logs.yml](elastic-agent-custom-logs.yml) is a
complete `elastic-agent.yml` input for that case.

## dnstap answers

BIND's text logs (above) only record the *question* of each query — no
text logging channel includes the answer records. The `bind_dns` Ansible
role can capture full DNS messages with dnstap (`bind_dnstap_enabled`) and
export them (`bind_dnstap_export_enabled`): a converter on the BIND server
turns the binary capture into one JSON object per message in
`/var/log/named/dnstap.ndjson`, already using ECS field names —
`dns.question.*`, `dns.answers[]` (name, type, class, TTL, data),
`dns.response_code`, `dns.header_flags`, `dns.resolved_ip`, `client.*`,
`server.*`, `network.*`, `event.duration`, `observer.*`, plus
`bind.dnstap.*` for what ECS has no field for (authority/additional
records, EDNS, the dnstap message type). Each event carries an absolute
UTC `@timestamp`, so there's no timezone to configure.

`bind-dnstap-pipeline` adds what the converter can't:

- decodes the JSON line itself if Elastic Agent shipped it as plain text,
  and passes already-decoded documents (the agent's `ndjson` parser)
  through unchanged;
- splits `dns.question.name` into `dns.question.registered_domain`,
  `subdomain` and `top_level_domain` (names without a public suffix, like
  internal-only zones, are left as they are);
- sets `event.outcome` from the response code — `success` for an answer,
  including a definite NXDOMAIN, `failure` for SERVFAIL, REFUSED and other
  errors; queries get none;
- sets `event.action` from the dnstap message type (`client_response`,
  `resolver_response`, ...);
- collects `related.ip` (client, server and every answer address) and
  `related.hosts` (the queried name), so searching an IP finds the lookups
  that resolved to it.

Like the text-log pipeline it never drops a document: a line that isn't
valid JSON keeps its `message`, gets the `bind_dnstap_json_parse_failure`
tag and an `error.message`.

To ship it, after `setup.sh`, add a second **Custom Logs** integration to
the same agent policy:

- **Dataset name**: `bind.dnstap`
- **Paths**: `/var/log/named/dnstap.ndjson*` (the `*` also covers the
  converter's rotated files)
- **Advanced options → Custom configurations**: paste
  [elastic-agent-dnstap.yml](elastic-agent-dnstap.yml), which routes events
  through `bind-dnstap-pipeline` and decodes each line on the agent.

Expect one document per DNS response — size the `bind.dnstap` data
stream's lifecycle (ILM) policy for your query rate.

## Kibana dashboards

[kibana/bind-dashboards.ndjson](kibana/bind-dashboards.ndjson) holds two
dashboards, linked to each other by a navigation panel at the top, plus
the data views they use (`logs-bind.dnstap-*`, `logs-bind.log-*`). Import
them with `setup.sh` by also setting `KIBANA_URL` (same credentials as
`ES_AUTH`), or in Kibana under **Stack Management → Saved Objects →
Import**. Both open on the last 24 hours. Built and checked against
Kibana 8.17; newer versions migrate the objects on import.

```bash
ES_URL=https://localhost:9200 ES_AUTH=elastic:yourpassword KIBANA_URL=https://localhost:5601 ./setup.sh
```

**[BIND] DNS answers (dnstap)** — from the dnstap export:

- KPIs: answers to clients, unique clients, failed answers
  (SERVFAIL/REFUSED/errors), NXDOMAIN answers, median and 95th-percentile
  response time.
- Answers over time by response code; response-code and query-type
  breakdowns; response time over time; answers by server and transport.
- Top queried names, top registered domains (with how many distinct names
  each), top clients (with their distinct names and NXDOMAIN count), top
  resolved addresses, slowest domains.

  **Response times** need the queries captured as well as the answers.
  BIND stamps each dnstap message with one time only, so the role's
  converter computes `event.duration` by pairing each answer with its
  query. Set `bind_dnstap_types` to `[auth query, client response]` on
  authoritative servers, or `[client query, client response]` on
  resolvers. Without the queries, the response-time panels and the
  slow-answers alert stay empty. The query events don't affect the other
  panels, which count only `client_response` events.
- Investigation panels: NXDOMAIN over time by client; NXDOMAIN by domain
  with distinct names, clients and average first-label length — many
  distinct, long, random-looking names under one domain is the signature of
  DGA malware or a random-subdomain attack; longest first labels (also a
  DNS-tunnelling signal); names answered with SERVFAIL/REFUSED.
- Upstream servers: lookups, failures and median time per forwarder/
  authority the resolver queried. This needs `resolver response` in the
  role's `bind_dnstap_types`; the default captures only `client response`,
  so the panel stays empty until it's added.
- A table of the individual answers (client, name, type, response code,
  answer data, response time).

**[BIND] Server logs** — from the text logs:

- KPIs: log events, errors and warnings, failures, security denials, zone
  transfers, dynamic updates.
- Log volume over time by category; log levels.
- Security denials over time by target, and the denied clients.
- Zone transfers by zone and direction (with when each was last seen), and
  the latest serial seen per zone in notify/transfer logs.
- Resolver errors (lame servers, unreachable, timeouts) by name, reason and
  server; dynamic updates by zone, action and TSIG key.
- Query-log top names and top clients — the question side only; the
  dnstap dashboard has answers.
- A table of errors, warnings and failures.

The dnstap data view adds two runtime fields the dashboards use:
`dns.response_time_ms` (`event.duration` in milliseconds; see the note on
response times below) and
`dns.question.first_label_length`. To change a dashboard, edit
[kibana/build_dashboards.py](kibana/build_dashboards.py), run
`python3 kibana/build_dashboards.py`, and re-import: the export embeds
JSON inside JSON and is easy to break by hand. A change made in Kibana's
editor and exported instead works too, but the next regeneration
overwrites it.

## Kibana alerting rules

[kibana/alert-rules.json](kibana/alert-rules.json) defines six rules on the
dnstap data. `setup.sh` creates them (after importing the dashboards, whose
data view they use) when `KIBANA_URL` is set, or run the loader on its own:

```bash
KIBANA_URL=https://localhost:5601 ES_AUTH=elastic:yourpassword python3 kibana/load_alert_rules.py
```

| Rule | Fires when | Default threshold |
|---|---|---|
| NXDOMAIN spike from a client | one client gets many "no such domain" answers — DGA malware, a scanner, a broken app | > 100 in 5 min, per client |
| Many distinct NXDOMAIN names under one domain | many *different* non-existent names under one domain — DGA malware or a random-subdomain ("water torture") attack; one app repeating a bad name doesn't trip it | > 50 distinct names in 15 min |
| SERVFAIL / REFUSED spike | a server failing to answer — upstream trouble, DNSSEC failures, an ACL refusing real clients | > 50 in 5 min, per server |
| Slow answers | average time to answer clients is high (needs queries captured; see below) | > 500 ms over 5 min, per server |
| Possible DNS tunnelling | repeated queries with a 40+ character first label — data hidden in DNS names (or some CDN/anti-spam lookups; check before acting) | > 20 in 15 min, per client |
| dnstap export stopped | no answers indexed at all — the converter timer, Elastic Agent, the pipeline, or BIND itself has stopped | < 1 in 15 min |

They're Elasticsearch query rules (available on every license), running
every minute (the no-data rule every 5). Five use KQL against the dnstap
data view, so they can use its runtime fields; the distinct-names rule is
ES|QL, because KQL rules can't count distinct values, and it raises one
alert listing the domains rather than one per domain. Thresholds are
starting points for a small-to-medium site: tune `threshold` and
`timeWindowSize` in the JSON (or the 50 in the ES|QL query) to your query
volume and re-run the loader — it updates rules in place by id, keeping
whether each is enabled.

**Notifications.** Out of the box the rules record alerts in Kibana
(**Stack Management → Alerts and Insights → Rules**, or the Alerts page)
but notify no one. Create a connector in Kibana (Slack, Microsoft Teams,
webhook, server log, ...) and pass its id to attach it to every rule; the
message carries the rule name, what crossed the threshold, and a link to
the matching events in Discover:

```bash
KIBANA_URL=... ES_AUTH=... ALERT_CONNECTOR_ID=<connector id> python3 kibana/load_alert_rules.py
```

Re-running without `ALERT_CONNECTOR_ID` keeps whatever actions the rules
already have, so notifications added in Kibana aren't lost. Email
connectors need a recipient and subject as well, so add those in Kibana's
rule editor instead.

**Requirements.** Kibana alerting needs Elasticsearch security enabled
(rules run with API keys) and an encryption key set in Kibana
(`xpack.encryptedSavedObjects.encryptionKey`) — standard on production
clusters. The user running the loader needs privileges to manage rules.

All six were tested on Elasticsearch/Kibana 8.17 against events built to
trip each one; each fired with the expected group (client, server or
domain), the no-data rule fired on an empty window, and a server-log
connector logged the notification.

## Extending it

Coverage here focuses on the message shapes that recur most often across
categories (client/query lines, resolving, zone/serial, transfer, view,
security decisions, updates, errors, listeners). `database`, `general`,
`default`, and `dispatch` in particular carry a long tail of one-off
internal messages that aren't structured here — they'll still be searchable
via `bind.message`, but if you want specific fields out of them, add another
`ignore_failure` grok processor following the same pattern: unanchored,
tagged, targeting `bind.message`.
