#!/usr/bin/env bash
# Run Nmap Cloud Scanner - Port Scanner + Service Detection | Bulk on Apify and print the dataset rows as JSON.
# Needs an Apify API token: https://console.apify.com/settings/integrations
#   APIFY_TOKEN=... ./run.sh [input.json]
set -euo pipefail
curl -sS -X POST "https://api.apify.com/v2/acts/anshumanatrey~nmap-scanner/run-sync-get-dataset-items" \
  -H "Authorization: Bearer $APIFY_TOKEN" -H "Content-Type: application/json" \
  --data @"${1:-$(dirname "$0")/input.json}"
