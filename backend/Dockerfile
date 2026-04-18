# syntax=docker/dockerfile:1.7

# ---------- Stage 1: build the frontend ----------
FROM node:20-alpine AS frontend-build
WORKDIR /frontend

# Install deps against the lockfile first for better layer caching.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ---------- Stage 2: build the Go binary with the embedded SPA ----------
FROM golang:1.24-alpine AS backend-build
WORKDIR /src

RUN apk add --no-cache git

COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./

# Drop in the real frontend build on top of the repo placeholders so
# go:embed picks up index.html plus hashed assets from Vite.
COPY --from=frontend-build /frontend/dist/ ./static/

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
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
    && mkdir -p /data \
    && chown nobody:nobody /data

COPY --from=backend-build /out/argos /argos
COPY --from=crs /etc/coraza/crs/rules /etc/coraza/crs/rules

USER nobody
EXPOSE 8080
ENTRYPOINT ["/argos"]
