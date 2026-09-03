# syntax=docker/dockerfile:1
FROM golang:1.26.1-alpine AS scanner-builder

ARG YARA_VERSION=4.5.4
ARG YARA_SHA256=586c9c21878f8b4d1b9423b89ac937f21f8057b03e3e9706f310549d453966fa
ARG SCAN_KERNEL_VERSION=1.0.0
ARG SCAN_KERNEL_COMMIT=unknown
ARG SCAN_KERNEL_BUILD_TIME=unknown
ARG SCAN_KERNEL_BUILD_TAGS=netgo,osusergo,custom_plugins,plugin_agent_skill,yara_native

RUN apk add --no-cache \
    autoconf \
    automake \
    bison \
    build-base \
    curl \
    flex \
    libtool \
    openssl-dev \
    openssl-libs-static

WORKDIR /tmp
RUN curl -fsSL "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" -o yara.tar.gz \
    && echo "${YARA_SHA256}  yara.tar.gz" | sha256sum -c - \
    && tar -xzf yara.tar.gz \
    && cd "yara-${YARA_VERSION}" \
    && ./bootstrap.sh \
    && ./configure --prefix=/usr/local --disable-shared --enable-static --disable-proc-scan \
    && make -j"$(getconf _NPROCESSORS_ONLN)" \
    && make install

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 \
    CGO_LDFLAGS="-lyara -lm -lcrypto -ldl -pthread" \
    PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
    go build -trimpath \
      -tags "${SCAN_KERNEL_BUILD_TAGS}" \
      -ldflags "-s -w -linkmode external -extldflags=-static \
        -X gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/buildinfo.Version=${SCAN_KERNEL_VERSION} \
        -X gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/buildinfo.Commit=${SCAN_KERNEL_COMMIT} \
        -X gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/buildinfo.BuildTime=${SCAN_KERNEL_BUILD_TIME}" \
      -o /out/scan-kernel-engine ./cmd/scankernel

FROM scratch AS export
COPY --from=scanner-builder /out/scan-kernel-engine /scan-kernel-engine
