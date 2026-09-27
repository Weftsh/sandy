# syntax=docker/dockerfile:1.26@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# Weft Sandboxes egress gateway. Build from the repository root:
#
#   docker build -f crates/egress-gateway/Dockerfile -t weft-egress-gateway .
#
# Base images are pinned by digest (tag kept for readability); bump both together.

FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
# The image's toolchain is the one rust-toolchain.toml pins; naming it
# explicitly stops rustup from downloading extra components during the build.
ENV RUSTUP_TOOLCHAIN=1.94.1 \
    CARGO_TERM_COLOR=never \
    CARGO_INCREMENTAL=0
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=egress-gateway-target,target=/src/target \
    cargo build --release --locked -p weft-egress-gateway \
 && install -D -m 0755 target/release/weft-egress-gateway /out/weft-egress-gateway \
 && /out/weft-egress-gateway --version

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG VERSION=0.0.0-dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="weft-sandboxes-egress-gateway" \
      org.opencontainers.image.description="Weft Sandboxes egress gateway: per-sandbox egress policy and credential injection" \
      org.opencontainers.image.source="https://github.com/Weftsh/sandy" \
      org.opencontainers.image.licenses="FSL-1.1-ALv2" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build --chown=0:0 --chmod=0755 /out/weft-egress-gateway /usr/local/bin/weft-egress-gateway
COPY --chown=0:0 NOTICE LICENSE.md LICENSES/ /usr/share/doc/weft-sandboxes/
USER 65532:65532
# GET /health on 15080 answers 200; distroless has no shell or HTTP client
# for an in-image probe, and ECS tracks the process itself.
# checkov:skip=CKV_DOCKER_2: health endpoint on 15080 is probed externally; no in-image client in distroless
HEALTHCHECK NONE
# 15000: PROXY protocol v2 connections from hosts. 15080: GET /health.
EXPOSE 15000 15080
ENTRYPOINT ["/usr/local/bin/weft-egress-gateway"]
