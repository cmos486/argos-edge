# syntax=docker/dockerfile:1.7

# ---------- Stage 1: build the frontend ----------
FROM node:20-alpine AS frontend-build
WORKDIR /frontend

# Install deps against the lockfile first for better layer caching.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
# Same 2 vCPU reasoning as the Go stage below: esbuild is a Go binary
# spawned by vite and honours GOMAXPROCS (checked in node_modules: the
# only esbuild env knobs are ESBUILD_BINARY_PATH / _MAX_BUFFER /
# _WORKER_THREADS, the last one for the sync API vite does not use).
ENV GOMAXPROCS=1 UV_THREADPOOL_SIZE=1
RUN npm run build

# ---------- Stage 2: build the Go binary with the embedded SPA ----------
# Bumped from 1.24 to 1.25 when the OIDC feature pulled in go-oidc v3
# which requires Go 1.23+ but brings its own transitive toolchain
# directive; keeping the builder in sync with go.mod avoids the
# "go: downloading go1.25" noise at every docker build.
FROM golang:1.25-alpine AS backend-build
WORKDIR /src

RUN apk add --no-cache git

COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./

# Drop in the real frontend build on top of the repo placeholders so
# go:embed picks up index.html plus hashed assets from Vite.
COPY --from=frontend-build /frontend/dist/ ./static/

# Build-time version metadata. Defaults preserve the source-tree
# fallback in main.go so a plain `docker build .` still produces a
# runnable binary; the make build-prod-image target supplies real
# values so the panel header pill + /api/system/version surface the
# actual deployed build.
ARG ARGOS_VERSION=
ARG ARGOS_COMMIT=
ARG ARGOS_BUILT_AT=

# v1.3.38.2: the prod LXC has 2 vCPU and the panel keeps serving during
# a deploy. BuildKit on this Docker version exposes no --cpu-quota for
# `docker build`, so the cap lives here: one compile worker (GOMAXPROCS
# for the toolchain itself, -p 1 for package parallelism). Override with
# --build-arg GO_BUILD_PARALLELISM=N on a bigger builder.
ARG GO_BUILD_PARALLELISM=1
RUN GOMAXPROCS=${GO_BUILD_PARALLELISM} CGO_ENABLED=0 GOOS=linux go build \
    -p ${GO_BUILD_PARALLELISM} \
    -trimpath \
    -ldflags="-s -w \
      ${ARGOS_VERSION:+-X main.argosVersion=${ARGOS_VERSION}} \
      ${ARGOS_COMMIT:+-X main.argosCommit=${ARGOS_COMMIT}} \
      ${ARGOS_BUILT_AT:+-X main.argosBuiltAt=${ARGOS_BUILT_AT}}" \
    -o /out/argos \
    ./cmd/argos

# ---------- Stage 3: fetch CRS for the /api/crs/rules catalog ----------
# The panel parses the rule files at startup so the exclusions UI can
# autocomplete by CRS id. Keeping it in the argos image avoids sharing
# the caddy volume just for catalog reads.
FROM alpine:3.20 AS crs
ARG CRS_VERSION=v4.25.0
RUN apk add --no-cache curl tar \
    && mkdir -p /etc/coraza/crs \
    && curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" \
       -o /tmp/crs.tar.gz \
    && tar -xzf /tmp/crs.tar.gz -C /tmp \
    && mv /tmp/coreruleset-*/rules /etc/coraza/crs/rules \
    && rm -rf /tmp/crs.tar.gz /tmp/coreruleset-*

# ---------- Stage 4: minimal runtime ----------
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata wget \
    && mkdir -p /data /data/backups /data/caddy /data/geoip /data/manual-certs \
    && chown -R nobody:nobody /data

COPY --from=backend-build /out/argos /argos
COPY --from=crs /etc/coraza/crs/rules /etc/coraza/crs/rules

USER nobody
EXPOSE 8080
ENTRYPOINT ["/argos"]
