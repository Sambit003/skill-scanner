#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
module_dir="$(CDPATH= cd -- "${script_dir}/.." && pwd)"
repo_dir="$(git -C "${module_dir}" rev-parse --show-toplevel)"
parity_dir="${module_dir}/testdata/parity"
lock_file="${parity_dir}/corpus.lock.json"
output_root="${SCAN_KERNEL_PARITY_DIR:-${repo_dir}/dist/scan-kernel-parity}"
corpus_root="${output_root}/corpus"
results_root="${output_root}/results"
oracle_image="scankernel-parity-oracle:b630d79"
go_image="scankernel-parity-go:current"
parity_limit="${SCAN_KERNEL_PARITY_LIMIT:-100}"

milliseconds() {
  perl -MTime::HiRes=time -e 'printf "%.0f\n", time * 1000'
}

if [[ "${1:-}" == "--acquire-one" ]]; then
  asset_id="$2"
  commit="$3"
  slug="${asset_id//\//__}"
  destination="$4/${slug}"
  mkdir -p "${destination}"
  git -C "${destination}" init -q
  if git -C "${destination}" remote get-url origin >/dev/null 2>&1; then
    git -C "${destination}" remote set-url origin "https://github.com/${asset_id}.git"
  else
    git -C "${destination}" remote add origin "https://github.com/${asset_id}.git"
  fi
  git -C "${destination}" fetch -q --depth 1 origin "${commit}"
  git -C "${destination}" checkout -q --detach --force FETCH_HEAD
  actual="$(git -C "${destination}" rev-parse HEAD)"
  [[ "${actual}" == "${commit}" ]]
  exit 0
fi

if [[ "${1:-}" == "--scan-one" ]]; then
  asset_id="$2"
  commit="$3"
  corpus_root="$4"
  results_root="$5"
  parity_dir="$6"
  oracle_image="$7"
  go_image="$8"
  slug="${asset_id//\//__}"
  target="${corpus_root}/${slug}"
  destination="${results_root}/${slug}"
  mkdir -p "${destination}"

  python_start="$(milliseconds)"
  python_status="ok"
  if ! docker run --rm --network none \
    -e SCAN_KERNEL_ORACLE_JOBS="${SCAN_KERNEL_ORACLE_JOBS:-8}" \
    --entrypoint timeout \
    -v "${target}:/corpus:ro" \
    -v "${parity_dir}:/parity:ro" \
    -v "${destination}:/results" \
    "${oracle_image}" 90 python /oracle/oracle_runner.py /corpus \
      --osv-fixture /parity/osv-responses.json \
      --baseline /parity/baseline.json \
      --inventory /results/python.inventory.json \
      --timing /results/python.stages.json > "${destination}/python.json"; then
    python_status="failed"
  fi
  python_end="$(milliseconds)"

  go_start="$(milliseconds)"
  go_status="ok"
  if ! docker run --rm --network none \
    -e SCAN_KERNEL_OSV_FIXTURE=/parity/osv-responses.json \
    -e SCAN_KERNEL_PARITY_SNAPSHOT=/results/go.inventory.json \
    -e SCAN_KERNEL_PARITY_STAGE_TIMING=/results/go.stages.json \
    -v "${target}:/corpus:ro" \
    -v "${parity_dir}:/parity:ro" \
    -v "${destination}:/results" \
    "${go_image}" timeout 90 /out/scan-kernel-engine scan \
      --timeout 90s --format json --baseline /parity/baseline.json /corpus > "${destination}/go.json"; then
    go_status="failed"
  fi
  go_end="$(milliseconds)"

  printf '{"python_scan_ms":%d,"go_scan_ms":%d,"python_status":"%s","go_status":"%s","commit":"%s"}\n' \
    "$((python_end - python_start))" "$((go_end - go_start))" "${python_status}" "${go_status}" "${commit}" \
    > "${destination}/timing.json"
  exit 0
fi

for command in git jq docker go perl; do
  command -v "${command}" >/dev/null || { printf 'required command not found: %s\n' "${command}" >&2; exit 2; }
done
jq -e '.schema_version == 1 and (.assets | length == 100) and ([.assets[].commit | test("^[0-9a-f]{40}$")] | all)' "${lock_file}" >/dev/null
jq -e '.schema_version == 1' "${parity_dir}/osv-responses.json" >/dev/null
jq -e '.schema_version == 1 and (.exceptions | type == "array")' "${parity_dir}/reviewed-exceptions.json" >/dev/null

mkdir -p "${corpus_root}" "${results_root}"
acquisition_start="$(milliseconds)"
jq --argjson limit "${parity_limit}" -r '.assets[:$limit][] | [.id,.commit] | @tsv' "${lock_file}" | \
  xargs -P "${SCAN_KERNEL_PARITY_ACQUIRE_JOBS:-6}" -n 2 bash -c \
    'exec bash "$0" --acquire-one "$2" "$3" "$1"' "${script_dir}/verify-parity.sh" "${corpus_root}"
acquisition_end="$(milliseconds)"
acquisition_ms="$((acquisition_end - acquisition_start))"

oracle_context="$(mktemp -d /tmp/scankernel-parity-oracle.XXXXXX)"
trap 'rm -rf "${oracle_context}"' EXIT
git -C "${repo_dir}" archive "$(jq -r '.oracle_commit' "${lock_file}")" packages/scan_kernel | tar -x -C "${oracle_context}"
cp "${parity_dir}/Oracle.Dockerfile" "${oracle_context}/Oracle.Dockerfile"
cp "${script_dir}/oracle_runner.py" "${oracle_context}/oracle_runner.py"
docker build -q -f "${oracle_context}/Oracle.Dockerfile" -t "${oracle_image}" "${oracle_context}" >/dev/null

docker build -q \
  -f "${module_dir}/build/linux-static.Dockerfile" \
  --target scanner-builder \
  --build-arg SCAN_KERNEL_BUILD_TAGS=netgo,osusergo,custom_plugins,plugin_agent_skill,yara_native,parity \
  -t "${go_image}" "${module_dir}" >/dev/null

jq --argjson limit "${parity_limit}" -r '.assets[:$limit][] | [.id,.commit] | @tsv' "${lock_file}" | \
  xargs -P "${SCAN_KERNEL_PARITY_SCAN_JOBS:-1}" -n 2 bash -c \
    'exec bash "$0" --scan-one "$6" "$7" "$1" "$2" "$3" "$4" "$5"' \
    "${script_dir}/verify-parity.sh" "${corpus_root}" "${results_root}" "${parity_dir}" "${oracle_image}" "${go_image}"

(
  cd "${module_dir}"
  go run ./cmd/parity \
    -lock "${lock_file}" \
    -results "${results_root}" \
    -exceptions "${parity_dir}/reviewed-exceptions.json" \
    -json "${output_root}/report.json" \
    -markdown "${output_root}/report.md" \
    -limit "${parity_limit}" \
    -acquisition-ms "${acquisition_ms}"
)
