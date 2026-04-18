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
FROM golang:1.23-alpine AS backend-build
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

# ---------- Stage 3: minimal runtime ----------
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata wget \
    && mkdir -p /data \
    && chown nobody:nobody /data

COPY --from=backend-build /out/argos /argos

USER nobody
EXPOSE 8080
ENTRYPOINT ["/argos"]
