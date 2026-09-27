# syntax=docker/dockerfile:1.26@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# Weft Sandboxes control plane (api, edge and worker roles; WEFT_ROLES picks).
# Build from the repository root:
#
#   docker build -f packages/control-plane/Dockerfile -t weft-control-plane .
#
# Base images are pinned by digest (tag kept for readability); bump both together.

FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS build
ENV CI=true \
    PNPM_HOME=/pnpm \
    npm_config_store_dir=/pnpm/store \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0
WORKDIR /src
# pnpm at the version in package.json's packageManager field. Corepack checks
# the npm registry signature of what it downloads.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN corepack enable && pnpm --version
# Dependencies first, from the lockfile alone, so they cache as a layer.
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm fetch --frozen-lockfile
COPY tsconfig.base.json ./
COPY packages/ packages/
# Build the control plane and its workspace dependencies (the license client),
# then assemble a self-contained production tree in /out.
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm install --offline --frozen-lockfile --filter "@weftsh/sandbox-control-plane..." \
 && pnpm --filter "@weftsh/sandbox-control-plane..." run build \
 && pnpm --filter @weftsh/sandbox-control-plane deploy --prod --legacy --offline /out \
 && test -f /out/dist/main.js \
 && chmod -R u=rwX,go=rX /out

FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:13593b7570658e8477de39e2f4a1dd25db2f836d68a0ba771251572d23bb4f8e
ARG VERSION=0.0.0-dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="weft-sandboxes-control-plane" \
      org.opencontainers.image.description="Weft Sandboxes control plane: E2B-compatible API, edge proxy and worker" \
      org.opencontainers.image.source="https://github.com/Weftsh/sandy" \
      org.opencontainers.image.licenses="FSL-1.1-ALv2" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
ENV NODE_ENV=production \
    WEFT_VERSION=${VERSION}
WORKDIR /app
# Root-owned and read-only to the runtime user; the container runs with a
# read-only root filesystem and a writable /tmp volume.
COPY --from=build --chown=0:0 /out/ /app/
COPY --chown=0:0 NOTICE LICENSE.md LICENSES/ /usr/share/doc/weft-sandboxes/
USER 65532:65532
# Health is checked by the load balancer (api: GET /health on 3000, edge:
# GET /healthz on 3001) and the worker has no listener, so one image-level
# check cannot fit all three roles; distroless has no shell for one anyway.
# checkov:skip=CKV_DOCKER_2: role-specific health checks live in the load balancer target groups
HEALTHCHECK NONE
EXPOSE 3000 3001
ENTRYPOINT ["/nodejs/bin/node", "dist/main.js"]
