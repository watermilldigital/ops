#!/usr/bin/env bash
# Maintains a single GitHub issue that tracks any Patchstack-reported
# vulnerabilities we couldn't auto-fix via Composer — WP core, themes,
# manually-installed plugins, and watermilldigital/* packages whose
# upstream fix hasn't been mirrored to Bitbucket yet.
#
# The issue is the only persistent signal for these cases (successful auto
# -fixes show up as PRs; transient wpackagist lag self-resolves on the next
# run). Reuses one issue by title so weeks of scans don't pile up duplicates.
#
# Called from the workflow after bump-plugins.sh; reads .github/vuln-report.json.

set -euo pipefail

REPORT=".github/vuln-report.json"
ISSUE_TITLE="Security: vulnerabilities needing manual attention"
ISSUE_LABEL="security"
# Who owns un-auto-fixable vulns. Set by the reusable workflow from
# inputs.assignee / github.repository_owner. Empty = don't assign.
ASSIGNEE="${ASSIGNEE:-}"

if [ ! -f "$REPORT" ]; then
  echo "No report at $REPORT — nothing to track."
  exit 0
fi

# Select skipped items that actually need a human:
#   - type == "core"   → WordPress core vuln
#   - type == "theme"  → theme vuln
#   - package is null  → slug not in composer.json (manually-installed)
#   - watermilldigital/* → private Bitbucket mirror awaiting upstream fix
# Exclude wpackagist-plugin/* skips — those are usually transient wpackagist
# lag and resolve themselves on the next run.
MANUAL_SKIPS=$(jq -c '[
  .skipped[] | select(
    (.package == null)
    or ((.package // "") | startswith("watermilldigital/"))
    or (.type == "core")
    or (.type == "theme")
  )
]' "$REPORT")
MANUAL_COUNT=$(echo "$MANUAL_SKIPS" | jq 'length')

# Find any existing open issue by exact title match.
EXISTING_ISSUE=$(gh issue list --state open --search "$ISSUE_TITLE in:title" \
  --json number,title --jq '.[] | select(.title == "'"$ISSUE_TITLE"'") | .number' \
  | head -n1)

if [ "$MANUAL_COUNT" = "0" ]; then
  if [ -n "$EXISTING_ISSUE" ]; then
    gh issue close "$EXISTING_ISSUE" --comment "All previously-skipped items have been resolved. Closing."
    echo "Closed tracking issue #$EXISTING_ISSUE"
  else
    echo "Nothing to track."
  fi
  exit 0
fi

# Ensure the `security` label exists in the caller repo before tagging the
# issue with it (gh issue create fails hard if the label is missing).
gh label create "$ISSUE_LABEL" \
  --description "Security update (Cloudways/Patchstack vulnerability scan)" \
  --color "d73a4a" 2>/dev/null || true

LAST_FETCHED="${LAST_FETCHED:-unknown}"

ISSUE_BODY=$(echo "$MANUAL_SKIPS" | jq -r \
  --arg last_fetched "$LAST_FETCHED" '
  def sev_emoji:
    {critical:"🔴", high:"🟠", medium:"🟡", low:"🟢"}[. // ""] // "⚪";

  def effective_sev: (.severity // .max_severity // null);

  def category:
    if .type == "core" then "wp-core"
    elif .type == "theme" then "theme"
    elif .package == null then "unmanaged"
    elif (.package // "") | startswith("watermilldigital/") then "private-mirror"
    else "other" end;

  def section_intro($cat):
    if   $cat == "wp-core"        then "### WordPress core\n\nUpdate WordPress from the admin dashboard or via `wp core update`.\n"
    elif $cat == "theme"          then "### Theme\n\nUpdate the theme files and re-deploy.\n"
    elif $cat == "unmanaged"      then "### Manually-installed plugins\n\nThese plugins are not in `composer.json`. Remove them or add to Composer before we can auto-update.\n"
    elif $cat == "private-mirror" then "### Private Bitbucket mirrors\n\nPull the upstream fix, push to the `watermilldigital/` Bitbucket repo, tag the release, then re-run this workflow.\n"
    else "### Other\n" end;

  def entry:
    "- \(effective_sev | sev_emoji) **\(.slug)** "
    + (if .package then "(`\(.package)`) " else "" end)
    + "current `\(.current_version // "unknown")`"
    + (if .fixed_version then " → fix available at `\(.fixed_version)`" else " (no fix available from Patchstack yet)" end)
    + (if effective_sev then "\n  - Severity: **\(effective_sev)**" else "" end)
    + (if (.cvss_score // .max_cvss) then " (CVSS \(.cvss_score // .max_cvss))" else "" end)
    + (if .title                                                                 then "\n  - " + .title else "" end)
    + (if (.titles | type) == "array" and (.titles | length) > 0                 then "\n  - " + (.titles | join("\n  - ")) else "" end)
    + (if .patchstack_url                                                        then "\n  - " + .patchstack_url else "" end)
    + (if (.patchstack_urls | type) == "array" and (.patchstack_urls | length) > 0 then "\n  - " + (.patchstack_urls | join("\n  - ")) else "" end);

  # Severity counts across all skipped items, in criticality order.
  def sev_counts:
    (map(effective_sev) | {
      critical: map(select(. == "critical")) | length,
      high:     map(select(. == "high"))     | length,
      medium:   map(select(. == "medium"))   | length,
      low:      map(select(. == "low"))      | length,
      unknown:  map(select(. == null))       | length
    }) as $c |
    [
      (if $c.critical > 0 then "🔴 \($c.critical) critical" else empty end),
      (if $c.high     > 0 then "🟠 \($c.high) high"         else empty end),
      (if $c.medium   > 0 then "🟡 \($c.medium) medium"     else empty end),
      (if $c.low      > 0 then "🟢 \($c.low) low"           else empty end),
      (if $c.unknown  > 0 then "⚪ \($c.unknown) unrated"   else empty end)
    ] | join(" · ");

  "## Summary\n\n"
  + "**\(length)** vulnerabilities need manual attention — \(sev_counts)\n\n"
  + "_Last Cloudways scan: \($last_fetched)._\n\n"
  + "These cannot be auto-fixed by the weekly Composer update. Each section "
  + "below tells you the one action that resolves the items in it.\n\n"
  + "---\n\n"
  + (group_by(category) | map(
       section_intro(.[0] | category) + "\n"
       + (map(entry) | join("\n"))
     ) | join("\n\n"))
  + "\n\n---\n\n"
  + "<details>\n<summary>About this issue</summary>\n\n"
  + "Auto-generated weekly by `.github/workflows/vulnerability-check.yml` "
  + "(which calls `watermilldigital/ops/.github/workflows/wp-vulnerability-check.yml`). "
  + "Source data: Cloudways Vulnerability Scanner, powered by Patchstack.\n\n"
  + "- Auto-fixable plugin vulnerabilities land in a separate PR labelled `security`, not here.\n"
  + "- This issue is rewritten on every run — don'"'"'t add manual notes to the body, they will be overwritten.\n"
  + "- It auto-closes when Cloudways reports no remaining un-auto-fixable items.\n"
  + "- Comments persist across runs; use them for any manual tracking.\n"
  + "\n</details>\n"
')

assignee_args=()
[ -n "$ASSIGNEE" ] && assignee_args=(--assignee "$ASSIGNEE")
add_assignee_args=()
[ -n "$ASSIGNEE" ] && add_assignee_args=(--add-assignee "$ASSIGNEE")

if [ -n "$EXISTING_ISSUE" ]; then
  gh issue edit "$EXISTING_ISSUE" --body "$ISSUE_BODY" "${add_assignee_args[@]}"
  echo "Updated tracking issue #$EXISTING_ISSUE"
else
  gh issue create \
    --title "$ISSUE_TITLE" \
    --body  "$ISSUE_BODY" \
    --label "$ISSUE_LABEL" "${assignee_args[@]}"
fi
