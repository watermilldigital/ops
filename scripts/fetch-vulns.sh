#!/usr/bin/env bash
# Fetches the Cloudways Patchstack vulnerability scan for an application
# and emits a normalised JSON array to stdout.
#
# Cloudways endpoint (v2):
#   GET /app/vulnerabilities/{app_id}?server_id={server_id}
# Response:
#   {"status": true, "data": {"last_fetched_date": "...",
#                             "wordpress": {}, "themes": [], "plugins": []}}
#
# Output schema (one object per vulnerable component):
# [{
#   "slug":            "wordpress-seo",            # wp.org slug / directory
#   "type":            "plugin" | "theme" | "core",
#   "current_version": "19.1",
#   "fixed_version":   "19.2.1",                   # null if no fix available
#   "severity":        "critical"|"high"|"medium"|"low"|null,
#   "cve":             "CVE-2024-XXXX" | null,
#   "title":           "Human-readable vulnerability title"
# }, ...]
#
# Required env:
#   CW_EMAIL       Cloudways account email
#   CW_API_KEY     Cloudways API key (Account → API)
#   CW_APP_ID      Application ID
#   CW_SERVER_ID   Server ID (required by the endpoint)
#
# Optional env:
#   CW_API_BASE    Base URL, default https://api.cloudways.com/api/v2
#   CW_REFRESH     If set to "1", triggers a fresh scan before fetching.

set -euo pipefail

: "${CW_EMAIL:?CW_EMAIL is required}"
: "${CW_API_KEY:?CW_API_KEY is required}"
: "${CW_APP_ID:?CW_APP_ID is required}"
: "${CW_SERVER_ID:?CW_SERVER_ID is required}"

CW_API_BASE="${CW_API_BASE:-https://api.cloudways.com/api/v2}"

# 1. OAuth: exchange email + api_key for a short-lived access token.
#    The token endpoint lives on v1 and is shared across API versions.
TOKEN_RESPONSE=$(curl -sS --fail-with-body \
  -X POST https://api.cloudways.com/api/v1/oauth/access_token \
  -d "email=${CW_EMAIL}" \
  -d "api_key=${CW_API_KEY}")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')

if [ -z "$ACCESS_TOKEN" ]; then
  echo "Failed to obtain Cloudways access token" >&2
  echo "$TOKEN_RESPONSE" >&2
  exit 1
fi

AUTH=(-H "Authorization: Bearer ${ACCESS_TOKEN}" -H "Accept: application/json")

# 2. Optionally trigger a fresh Patchstack scan. The refresh endpoint returns
#    an operation_id immediately; we don't poll because the subsequent list
#    call will return whatever data is currently cached.
if [ "${CW_REFRESH:-0}" = "1" ]; then
  curl -sS --fail-with-body "${AUTH[@]}" \
    "${CW_API_BASE}/app/vulnerabilities/${CW_APP_ID}/refresh?server_id=${CW_SERVER_ID}" \
    > /dev/null || echo "Refresh request failed (continuing with cached data)" >&2
fi

# 3. Fetch the vulnerability list.
RAW=$(curl -sS --fail-with-body "${AUTH[@]}" \
  "${CW_API_BASE}/app/vulnerabilities/${CW_APP_ID}?server_id=${CW_SERVER_ID}")

# 3a. Guard against Cloudways returning HTTP 200 with {"status": false, ...}.
#     Without this, malformed responses silently normalise to [] and the
#     workflow looks green despite never actually checking vulnerabilities.
if ! echo "$RAW" | jq -e '.status == true and (.data | type) == "object"' >/dev/null; then
  echo "Cloudways API returned a non-success response:" >&2
  echo "$RAW" | jq . >&2 2>/dev/null || echo "$RAW" >&2
  exit 1
fi

# 3b. Surface scan freshness so stale data is visible in the run log.
LAST_FETCHED=$(echo "$RAW" | jq -r '.data.last_fetched_date // "unknown"')
echo "Cloudways last_fetched_date: $LAST_FETCHED" >&2

# 4. Normalise to the flat schema. The Cloudways response groups components
#    under .data.{plugins|themes|wordpress}. Each component has:
#      - is_vulnerable: 0 or 1
#      - vulnerabilities: [] when not vulnerable, or an object {...} when it is
#        (single object, not an array — despite the plural field name)
#    The vulnerability object uses Patchstack field names directly: fixed_in,
#    cvss_score, title, patch_priority, direct_url.
echo "$RAW" | jq '
  # Map CVSS 0-10 to severity buckets (NIST scale).
  def severity_from_cvss($s):
    if $s == null then null
    elif $s >= 9    then "critical"
    elif $s >= 7    then "high"
    elif $s >= 4    then "medium"
    elif $s > 0     then "low"
    else null end;

  # A single component → array of flat vuln records (usually 0 or 1).
  def expand(t):
    . as $c |
    if ($c.is_vulnerable // 0) == 1 and ($c.vulnerabilities | type) == "object" then
      [{
        slug:            $c.slug,
        type:            t,
        current_version: $c.current_version,
        fixed_version:   $c.vulnerabilities.fixed_in,
        severity:        severity_from_cvss($c.vulnerabilities.cvss_score),
        cvss_score:      $c.vulnerabilities.cvss_score,
        patch_priority:  $c.vulnerabilities.patch_priority,
        vuln_type:       $c.vulnerabilities.vuln_type,
        patchstack_url:  $c.vulnerabilities.direct_url,
        title:           $c.vulnerabilities.title,
        recommendation:  $c.recommendation
      }]
    elif ($c.is_vulnerable // 0) == 1 and ($c.vulnerabilities | type) == "array" then
      # Defensive: if Cloudways ever returns an array of vuln objects
      [$c.vulnerabilities[] | . as $v | {
        slug:            $c.slug,
        type:            t,
        current_version: $c.current_version,
        fixed_version:   $v.fixed_in,
        severity:        severity_from_cvss($v.cvss_score),
        cvss_score:      $v.cvss_score,
        patch_priority:  $v.patch_priority,
        vuln_type:       $v.vuln_type,
        patchstack_url:  $v.direct_url,
        title:           $v.title,
        recommendation:  $c.recommendation
      }]
    else []
    end;

  def component_array(v):
    if v == null then []
    elif (v | type) == "array" then v
    elif (v | type) == "object" and (v | length) > 0 then [v]
    else [] end;

  [ component_array(.data.plugins)[]     | expand("plugin") | .[] ]
  + [ component_array(.data.themes)[]    | expand("theme")  | .[] ]
  + [ component_array(.data.wordpress)[] | expand("core")   | .[] ]
'
