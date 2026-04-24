#!/usr/bin/env bash
# Reads a normalised vulnerability JSON array (produced by fetch-vulns.sh) and,
# for each vulnerable plugin/theme that we manage via Composer, attempts to
# update it. If the existing version constraint already allows the fixed
# version, a plain `composer update` is enough. Otherwise the constraint is
# bumped via `composer require` so the fix can land.
#
# Input:  path to vulns.json (normalised schema, see fetch-vulns.sh)
# Output: writes a summary JSON to .github/vuln-report.json for the PR step
#         to consume. Leaves composer.json / composer.lock modified in place.
#
# Exits 0 with no changes if there's nothing actionable (no vulns, or every
# vuln lives in an unmanaged component like WP core).

set -euo pipefail

INPUT="${1:-vulns.json}"
REPORT=".github/vuln-report.json"

# Returns 0 iff version $1 >= version $2 (semver-ish comparison via sort -V).
version_gte() {
  [ "$(printf '%s\n%s\n' "${2#v}" "${1#v}" | sort -V | head -n1)" = "${2#v}" ]
}

# Validate that a version string looks like something composer can resolve.
# Rejects "*" (Patchstack's "no fix available" sentinel), empty strings, and
# anything that doesn't start with digits-dot-digits (e.g. "trunk", "latest").
# Tolerates a leading "v" prefix — Composer accepts "^v1.2.3" as "^1.2.3".
is_version_resolvable() {
  [[ "${1#v}" =~ ^[0-9]+\.[0-9]+ ]]
}

# Per-iteration file snapshots live here so a failure for package N doesn't
# wipe composer.json/composer.lock edits made by packages 1..N-1. Using cp
# rather than `git checkout --` is critical — git would revert everything
# back to HEAD.
SNAPSHOT_DIR=$(mktemp -d)
trap 'rm -rf "$SNAPSHOT_DIR"' EXIT

snapshot_save() {
  cp composer.json "$SNAPSHOT_DIR/composer.json"
  cp composer.lock "$SNAPSHOT_DIR/composer.lock" 2>/dev/null || true
}
snapshot_restore() {
  cp "$SNAPSHOT_DIR/composer.json" composer.json
  [ -f "$SNAPSHOT_DIR/composer.lock" ] && cp "$SNAPSHOT_DIR/composer.lock" composer.lock
}

if [ ! -f "$INPUT" ]; then
  echo "Input file $INPUT not found" >&2
  exit 1
fi

if [ ! -f composer.json ]; then
  echo "composer.json not found in CWD" >&2
  exit 1
fi

# Build slug → composer package map from composer.json. The mapping uses the
# trailing path segment of each require key (e.g. wpackagist-plugin/wordfence
# → "wordfence"). Emitted as newline-delimited "slug<TAB>package" pairs.
SLUG_MAP=$(jq -r '.require | to_entries[] | "\(.key | split("/")[-1])\t\(.key)"' composer.json)

# Sort and dedupe vulns by slug so we don't try to update the same package
# twice in one run (a plugin may have multiple open CVEs).
VULNS_BY_SLUG=$(jq -c '
  def max_sev(list):
    (list | map({"critical":4,"high":3,"medium":2,"low":1}[. // ""] // 0) | max) as $n |
    [null,"low","medium","high","critical"][$n];

  group_by(.slug) | map({
    slug:            .[0].slug,
    type:            .[0].type,
    current_version: .[0].current_version,
    fixed_version:   ([.[].fixed_version | select(. != null)] | max),
    titles:          ([.[].title          | select(. != null)] | unique),
    vuln_types:      ([.[].vuln_type      | select(. != null)] | unique),
    patchstack_urls: ([.[].patchstack_url | select(. != null)] | unique),
    max_cvss:        ([.[].cvss_score     | select(. != null)] | max),
    max_severity:    max_sev([.[].severity])
  })[]
' "$INPUT")

if [ -z "$VULNS_BY_SLUG" ]; then
  echo "No vulnerabilities reported — nothing to do."
  echo '{"updates":[],"skipped":[]}' > "$REPORT"
  exit 0
fi

SKIPPED_JSON='[]'
UPDATES_JSON='[]'

# Attempts to update a single composer package to at least $fixed.
# On success, appends to UPDATES_JSON. On failure, restores composer.json/lock
# from the iteration snapshot (NOT via git, which would wipe prior successes)
# and appends to SKIPPED_JSON.
try_bump_package() {
  local package="$1" fixed="$2" vuln="$3"
  local before after

  echo "↳ $package: target ≥ $fixed"
  before=$(composer show "$package" --locked --format=json 2>/dev/null \
           | jq -r '.versions[0] // empty' || true)

  composer update --no-interaction --with-dependencies "$package" \
    2>&1 | tee /tmp/composer-update.log || true
  after=$(composer show "$package" --locked --format=json 2>/dev/null \
          | jq -r '.versions[0] // empty' || true)

  if [ -n "$after" ] && version_gte "$after" "$fixed"; then
    echo "   ✓ $package updated $before → $after"
  else
    echo "   plain update didn't reach $fixed — trying to bump constraint to ^$fixed"
    if composer require --no-interaction --update-with-dependencies \
         "${package}:^${fixed}" 2>&1 | tee /tmp/composer-require.log; then
      after=$(composer show "$package" --locked --format=json 2>/dev/null \
              | jq -r '.versions[0] // empty' || true)
      if [ -n "$after" ] && version_gte "$after" "$fixed"; then
        echo "   ✓ $package bumped $before → $after"
      else
        echo "   ✗ $package: require resolved but installed version ($after) < $fixed"
        snapshot_restore
        SKIPPED_JSON=$(echo "$SKIPPED_JSON" | jq --argjson v "$vuln" --arg pkg "$package" \
          --arg reason "require resolved but installed version below fix" \
          '. + [$v + {package: $pkg, reason: $reason}]')
        return 1
      fi
    else
      echo "   ✗ $package: cannot resolve ^$fixed — tag probably missing from package repo"
      snapshot_restore
      local reason="target version ^${fixed} not available in package repo"
      if [[ "$package" == watermilldigital/* ]]; then
        reason="${reason} (private Bitbucket mirror — needs manual upstream update)"
      fi
      SKIPPED_JSON=$(echo "$SKIPPED_JSON" | jq --argjson v "$vuln" --arg pkg "$package" \
        --arg reason "$reason" \
        '. + [$v + {package: $pkg, reason: $reason}]')
      return 1
    fi
  fi

  UPDATES_JSON=$(echo "$UPDATES_JSON" | jq \
    --argjson v "$vuln" \
    --arg pkg "$package" \
    --arg before "${before:-unknown}" \
    --arg after  "${after:-unknown}" \
    '. + [$v + {package: $pkg, version_before: $before, version_after: $after}]')
  return 0
}

while IFS= read -r vuln; do
  [ -z "$vuln" ] && continue

  slug=$(echo "$vuln" | jq -r '.slug')
  fixed=$(echo "$vuln" | jq -r '.fixed_version // empty')
  type=$(echo "$vuln" | jq -r '.type')

  # Find all composer packages whose trailing path segment matches this slug.
  # Collisions are rare (two composer packages with same trailing segment)
  # but worth handling explicitly — a silent first-match-wins could leave a
  # genuinely vulnerable package untouched.
  mapfile -t matches < <(awk -F'\t' -v s="$slug" '$1 == s {print $2}' <<< "$SLUG_MAP")

  if [ "${#matches[@]}" -eq 0 ]; then
    echo "↳ $slug ($type) not managed by Composer — skipping"
    SKIPPED_JSON=$(echo "$SKIPPED_JSON" | jq --argjson v "$vuln" \
      --arg reason "not managed by composer" '. + [$v + {reason: $reason}]')
    continue
  fi

  if [ -z "$fixed" ]; then
    echo "↳ ${matches[*]}: no fixed version available from Patchstack — skipping"
    SKIPPED_JSON=$(echo "$SKIPPED_JSON" | jq --argjson v "$vuln" \
      --arg pkg "${matches[0]}" --arg reason "no fixed version available" \
      '. + [$v + {package: $pkg, reason: $reason}]')
    continue
  fi

  if ! is_version_resolvable "$fixed"; then
    echo "↳ ${matches[*]}: fixed_version='$fixed' is not resolvable (e.g. '*' or non-numeric) — skipping"
    SKIPPED_JSON=$(echo "$SKIPPED_JSON" | jq --argjson v "$vuln" \
      --arg pkg "${matches[0]}" \
      --arg reason "fixed_version '$fixed' is not resolvable by composer" \
      '. + [$v + {package: $pkg, reason: $reason}]')
    continue
  fi

  if [ "${#matches[@]}" -gt 1 ]; then
    echo "↳ WARNING: slug '$slug' matches ${#matches[@]} composer packages: ${matches[*]}"
    echo "           Attempting update on all of them."
  fi

  for package in "${matches[@]}"; do
    snapshot_save
    try_bump_package "$package" "$fixed" "$vuln" || true
  done
done <<< "$VULNS_BY_SLUG"

jq -n \
  --argjson updates "$UPDATES_JSON" \
  --argjson skipped "$SKIPPED_JSON" \
  '{updates: $updates, skipped: $skipped}' > "$REPORT"

echo
echo "Report written to $REPORT"
jq '. | {update_count: (.updates|length), skipped_count: (.skipped|length)}' "$REPORT"

# Exit 0 even with no updates — open-security-pr.sh decides whether to open a PR.
