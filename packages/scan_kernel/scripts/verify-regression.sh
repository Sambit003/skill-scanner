#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CORPUS_GOLDEN="${SCANNER_DIR}/testdata/regression/mattpocock-skills-84fdeffd12f2ee307994d1eb6feb48173b6e0502.tsv"
MALICIOUS_FIXTURE="${SCANNER_DIR}/testdata/malicious_skill"
FIXTURE_GOLDEN="${SCANNER_DIR}/testdata/regression/malicious-scan.json"
CORPUS_COMMIT="84fdeffd12f2ee307994d1eb6feb48173b6e0502"
# Canonical hashes for CORPUS_COMMIT. The first covers every user-visible
# engine finding field; the second covers the complete summary.
EXPECTED_FINDINGS_SHA256="74c189fb77ec376e8bdb13f94b22f42b9417850fb0fb6781a79647fee87215e0"
EXPECTED_SUMMARY_SHA256="ef3a46c5b193e40c34784c32440b5b435a17ed610599fb4db0e5498482fb3ae7"
REGRESSION_TMP="$(mktemp -d /tmp/scankernel-regression.XXXXXX)"
trap 'rm -rf "${REGRESSION_TMP}"' EXIT
SCAN_KERNEL_DOCKER_IMAGE=""

target="${1:-}"
if [[ -z "${target}" ]]; then
  target="${REGRESSION_TMP}/skills"
  git init -q "${target}"
  git -C "${target}" fetch -q --depth 1 https://github.com/mattpocock/skills.git "${CORPUS_COMMIT}"
  git -C "${target}" checkout -q FETCH_HEAD
fi

run_scanner() {
  local scan_target="$1"
  local output="$2"
  if [[ -n "${SCAN_KERNEL_BINARY:-}" ]]; then
    "${SCAN_KERNEL_BINARY}" scan --offline --scope repository --include-readme --format json "${scan_target}" > "${output}"
    return
  fi
  docker run --rm --network none \
    -v "$(cd "${scan_target}" && pwd):/scan-target:ro" \
    "${SCAN_KERNEL_DOCKER_IMAGE}" \
    /out/scan-kernel-engine scan --offline --scope repository --include-readme --format json /scan-target > "${output}"
}

if [[ -z "${SCAN_KERNEL_BINARY:-}" ]]; then
  command -v docker >/dev/null || { printf 'native-YARA regression requires Docker or SCAN_KERNEL_BINARY\n' >&2; exit 2; }
  SCAN_KERNEL_DOCKER_IMAGE="scankernel-native-regression:current"
  docker build -q \
    --file "${SCANNER_DIR}/build/linux-static.Dockerfile" \
    --target scanner-builder \
    --tag "${SCAN_KERNEL_DOCKER_IMAGE}" \
    "${SCANNER_DIR}" >/dev/null
fi

if [[ -n "${SCAN_KERNEL_BINARY:-}" ]]; then
  "${SCAN_KERNEL_BINARY}" version --json > "${REGRESSION_TMP}/version.json"
else
  docker run --rm "${SCAN_KERNEL_DOCKER_IMAGE}" /out/scan-kernel-engine version --json > "${REGRESSION_TMP}/version.json"
fi
if [[ "$(jq -r '.yara_mode' "${REGRESSION_TMP}/version.json")" != "native-static" ]] || \
   [[ "$(jq -r '.yara_version' "${REGRESSION_TMP}/version.json")" != "4.5.4" ]]; then
  printf 'native-YARA regression requires a native-static YARA 4.5.4 binary\n' >&2
  exit 2
fi

run_scanner "${target}" "${REGRESSION_TMP}/actual.json"

jq -r '.findings[] | [.id,.severity,.category,.location.file,(.location.start_line|tostring),(.pattern // ""),(.confidence|tostring)] | @tsv' \
  "${REGRESSION_TMP}/actual.json" | sort > "${REGRESSION_TMP}/actual.tsv"

diff -u "${CORPUS_GOLDEN}" "${REGRESSION_TMP}/actual.tsv"

actual_findings_sha256="$(
  jq -cS '[.findings[] | {id,category,pattern,severity,confidence,location,finding,explanation,remediation,code_snippet,intent,tags}] | sort_by(.id,.location.file,.location.start_line,.pattern)' \
    "${REGRESSION_TMP}/actual.json" | shasum -a 256 | awk '{print $1}'
)"
actual_summary_sha256="$(
  jq -cS '.summary | {risk_score,severity,recommendation,safe_to_install,findings_count,findings_by_severity,findings_by_category}' \
    "${REGRESSION_TMP}/actual.json" | shasum -a 256 | awk '{print $1}'
)"
if [[ "${actual_findings_sha256}" != "${EXPECTED_FINDINGS_SHA256}" ]]; then
  printf 'Corpus finding regression failed: expected %s, got %s\n' \
    "${EXPECTED_FINDINGS_SHA256}" "${actual_findings_sha256}" >&2
  exit 1
fi
if [[ "${actual_summary_sha256}" != "${EXPECTED_SUMMARY_SHA256}" ]]; then
  printf 'Corpus summary regression failed: expected %s, got %s\n' \
    "${EXPECTED_SUMMARY_SHA256}" "${actual_summary_sha256}" >&2
  exit 1
fi

jq -r '"Corpus regression verified: \(.summary.findings_count) findings (HIGH=\(.summary.findings_by_severity.HIGH // 0), MEDIUM=\(.summary.findings_by_severity.MEDIUM // 0), LOW=\(.summary.findings_by_severity.LOW // 0))"' \
  "${REGRESSION_TMP}/actual.json"

run_scanner "${MALICIOUS_FIXTURE}" "${REGRESSION_TMP}/malicious-actual.json"
jq -S '{summary,findings}' "${REGRESSION_TMP}/malicious-actual.json" > "${REGRESSION_TMP}/malicious-actual-canonical.json"
jq -S '{summary,findings}' "${FIXTURE_GOLDEN}" > "${REGRESSION_TMP}/malicious-expected-canonical.json"
diff -u "${REGRESSION_TMP}/malicious-expected-canonical.json" "${REGRESSION_TMP}/malicious-actual-canonical.json"
printf 'Native-YARA regression verified: exact 14-finding malicious fixture payload.\n'
