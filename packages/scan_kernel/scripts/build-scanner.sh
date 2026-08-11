#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
module_dir="$(CDPATH= cd -- "$script_dir/.." && pwd)"
profile="skill"
version="dev"
output_root="$module_dir/dist/bundles"
targets="linux/amd64,linux/arm64"
yara_mode="native-static"

usage() {
  printf '%s\n' "usage: build-scanner.sh [--profile skill] [--version VERSION] [--targets os/arch,...] [--output DIR] [--yara native-static|fallback]"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile) profile="$2"; shift 2 ;;
    --version) version="$2"; shift 2 ;;
    --targets) targets="$2"; shift 2 ;;
    --output) output_root="$2"; shift 2 ;;
    --yara) yara_mode="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$profile" in
  ''|*[!A-Za-z0-9_-]*) printf 'invalid profile name: %s\n' "$profile" >&2; exit 2 ;;
esac
case "$version" in
  ''|*[!A-Za-z0-9._-]*) printf 'invalid version: %s\n' "$version" >&2; exit 2 ;;
esac

profile_file="$module_dir/build/profiles/$profile.env"
if [ ! -f "$profile_file" ]; then
  printf 'unknown build profile: %s\n' "$profile" >&2
  exit 2
fi

# shellcheck disable=SC1090
. "$profile_file"
if [ -z "${PLUGIN_IDS:-}" ] || [ -z "${BUILD_TAGS:-}" ]; then
  printf 'profile %s must define PLUGIN_IDS and BUILD_TAGS\n' "$profile" >&2
  exit 2
fi
if [ "$yara_mode" = "native" ]; then
  yara_mode="native-static"
fi
if [ "$yara_mode" != "fallback" ] && [ "$yara_mode" != "native-static" ]; then
  printf 'yara mode must be native-static or fallback\n' >&2
  exit 2
fi

commit="$(git -C "$module_dir" rev-parse --short=12 HEAD 2>/dev/null || printf unknown)"
build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
bundle_root="$output_root/$profile/$version"
mkdir -p "$bundle_root"

notices="$bundle_root/THIRD_PARTY_NOTICES.txt"
(
  printf 'ScanKernel third-party Go modules\n\n'
  cd "$module_dir"
  go list -m all
) > "$notices"

old_ifs="$IFS"
IFS=','
for target in $targets; do
	case "$target" in
		linux/amd64|linux/arm64|darwin/amd64|darwin/arm64|windows/amd64|windows/arm64) ;;
		*) printf 'unsupported target: %s\n' "$target" >&2; exit 2 ;;
	esac
  IFS='/' read -r target_os target_arch <<EOF
$target
EOF
  IFS=','
  if [ -z "$target_os" ] || [ -z "$target_arch" ]; then
    printf 'invalid target: %s\n' "$target" >&2
    exit 2
  fi
  target_name="$target_os-$target_arch"
  stage="$bundle_root/$target_name"
  mkdir -p "$stage"
  binary="scan-kernel-engine"
  if [ "$target_os" = "windows" ]; then binary="$binary.exe"; fi
  printf 'building %s (%s)\n' "$profile" "$target"
	if [ "$yara_mode" = "native-static" ]; then
		case "$target" in
			linux/amd64|linux/arm64) ;;
			*) printf 'certified native-static bundles currently support linux/amd64 and linux/arm64, not %s\n' "$target" >&2; exit 2 ;;
		esac
		docker buildx build \
			--platform "$target" \
			--file "$module_dir/build/linux-static.Dockerfile" \
			--target export \
			--output "type=local,dest=$stage" \
			--build-arg "SCAN_KERNEL_VERSION=$version" \
			--build-arg "SCAN_KERNEL_COMMIT=$commit" \
			--build-arg "SCAN_KERNEL_BUILD_TIME=$build_time" \
			"$module_dir"
		if ! file "$stage/$binary" | grep -q 'statically linked'; then
			printf 'native-static build is not fully static: %s\n' "$stage/$binary" >&2
			exit 3
		fi
	else
		(
			cd "$module_dir"
			CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build \
				-trimpath -tags "$BUILD_TAGS" \
				-ldflags "-s -w -X gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/buildinfo.Version=$version -X gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/buildinfo.Commit=$commit -X gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/buildinfo.BuildTime=$build_time" \
				-o "$stage/$binary" ./cmd/scankernel
		)
	fi
  cp "$notices" "$stage/THIRD_PARTY_NOTICES.txt"
  cat > "$stage/manifest.json" <<EOF
{
  "schema_version": 1,
  "profile": "$PROFILE_ID",
  "description": "$DESCRIPTION",
  "version": "$version",
  "commit": "$commit",
  "build_time": "$build_time",
  "go_version": "$(go version | awk '{print $3}')",
  "target": "$target",
  "plugins": ["$(printf '%s' "$PLUGIN_IDS" | sed 's/,/", "/g')"],
  "protocol_version": "1",
  "yara_mode": "$yara_mode",
  "yara_version": "$(if [ "$yara_mode" = native-static ]; then printf 4.5.4; fi)",
  "binary": "$binary"
}
EOF
  (
    cd "$stage"
    if [ "$yara_mode" = "native-static" ]; then
      shasum -a 256 "$binary" manifest.json THIRD_PARTY_NOTICES.txt YARA-LICENSE > SHA256SUMS
    else
      shasum -a 256 "$binary" manifest.json THIRD_PARTY_NOTICES.txt > SHA256SUMS
    fi
  )
  if [ "$target_os" = "windows" ]; then
    (cd "$bundle_root" && zip -q -r "scan-kernel-$profile-$version-$target_name.zip" "$target_name")
  else
    (cd "$bundle_root" && tar -czf "scan-kernel-$profile-$version-$target_name.tar.gz" "$target_name")
  fi
done
IFS="$old_ifs"

(cd "$bundle_root" && shasum -a 256 scan-kernel-* > SHA256SUMS)
printf 'bundles written to %s\n' "$bundle_root"
