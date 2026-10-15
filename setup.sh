#!/usr/bin/env bash
# Bootstraps both BIND ingest pipelines + their field mappings in
# Elasticsearch, and runs each pipeline against its sample documents before
# anything is wired to real traffic:
#   - bind-log-pipeline     text logs        (dataset bind.log)
#   - bind-dnstap-pipeline  dnstap NDJSON    (dataset bind.dnstap)
#
# Run this BEFORE adding/enabling the Custom Logs integrations in Fleet: a
# component template only composes into the logs-bind.log-* /
# logs-bind.dnstap-* index template that Fleet generates if it already
# exists at that point (or before the first rollover, if the integration is
# already running).
#
# Set KIBANA_URL as well to also import the Kibana dashboards
# (kibana/bind-dashboards.ndjson) and create the dnstap alerting rules
# (kibana/alert-rules.json); same credentials as ES_AUTH. Optionally set
# ALERT_CONNECTOR_ID to a Kibana connector the rules should notify.
#
# Usage: ES_URL=https://localhost:9200 ES_AUTH=elastic:changeme ./setup.sh
#        ES_URL=... ES_AUTH=... KIBANA_URL=https://localhost:5601 ./setup.sh

set -euo pipefail

ES_URL="${ES_URL:-https://localhost:9200}"
ES_AUTH="${ES_AUTH:-elastic:changeme}"
KIBANA_URL="${KIBANA_URL:-}"
CURL="curl -sS -k -u ${ES_AUTH}"

echo "== 1/6 Loading text-log ingest pipeline =="
${CURL} -X PUT "${ES_URL}/_ingest/pipeline/bind-log-pipeline" \
  -H 'Content-Type: application/json' \
  --data-binary @bind-ingest-pipeline.json
echo

echo "== 2/6 Loading logs-bind.log@custom component template =="
${CURL} -X PUT "${ES_URL}/_component_template/logs-bind.log@custom" \
  -H 'Content-Type: application/json' \
  --data-binary @logs-bind.log@custom.json
echo

echo "== 3/6 Loading dnstap ingest pipeline =="
${CURL} -X PUT "${ES_URL}/_ingest/pipeline/bind-dnstap-pipeline" \
  -H 'Content-Type: application/json' \
  --data-binary @bind-dnstap-pipeline.json
echo

echo "== 4/6 Loading logs-bind.dnstap@custom component template =="
${CURL} -X PUT "${ES_URL}/_component_template/logs-bind.dnstap@custom" \
  -H 'Content-Type: application/json' \
  --data-binary @logs-bind.dnstap@custom.json
echo

echo "== 5/6 Simulating text-log pipeline against sample BIND log lines =="
${CURL} -X POST "${ES_URL}/_ingest/pipeline/bind-log-pipeline/_simulate?pretty" \
  -H 'Content-Type: application/json' \
  --data-binary @bind-pipeline-simulate-test.json

echo "== 6/6 Simulating dnstap pipeline against sample exported events =="
${CURL} -X POST "${ES_URL}/_ingest/pipeline/bind-dnstap-pipeline/_simulate?pretty" \
  -H 'Content-Type: application/json' \
  --data-binary @bind-dnstap-simulate-test.json

if [ -n "${KIBANA_URL}" ]; then
  echo
  echo "== Importing Kibana dashboards (KIBANA_URL set) =="
  ${CURL} -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
    -H 'kbn-xsrf: true' \
    --form file=@kibana/bind-dashboards.ndjson
  echo

  # Alerting needs Elasticsearch security enabled and an encryption key in
  # Kibana (xpack.encryptedSavedObjects.encryptionKey); set
  # ALERT_CONNECTOR_ID to have every rule message that connector.
  echo "== Creating/updating Kibana alerting rules (kibana/alert-rules.json) =="
  KIBANA_URL="${KIBANA_URL}" ES_AUTH="${ES_AUTH}" python3 kibana/load_alert_rules.py
fi
