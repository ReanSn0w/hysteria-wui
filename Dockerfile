# syntax=docker/dockerfile:1.7

ARG HYSTERIA_IMAGE=tobyxdd/hysteria:v2.12.2@sha256:9725222899831fd80ca802c4f6984b5f6ad96672248a25dd7d8f781f5029f87c

FROM --platform=$BUILDPLATFORM node:24-alpine AS assets
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY scripts ./scripts
RUN npm run build:assets

FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine3.23 AS controller
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=assets /src/internal/panel/assets/vendor ./internal/panel/assets/vendor
RUN test "$TARGETOS/$TARGETARCH" = "linux/amd64" && \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/hysteria-wui ./cmd/hysteria-wui

FROM ${HYSTERIA_IMAGE}
RUN install -d -m 0700 /var/lib/hysteria-wui
COPY --from=controller --chown=root:root /out/hysteria-wui /usr/local/bin/hysteria-wui
EXPOSE 80/tcp 443/tcp 443/udp
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:9090/readyz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/hysteria-wui"]
