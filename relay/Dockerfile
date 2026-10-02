# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine3.23 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY cmd/hysteria-relay ./cmd/hysteria-relay
COPY internal/relay ./internal/relay
RUN test "$TARGETOS/$TARGETARCH" = "linux/amd64" && \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/hysteria-relay ./cmd/hysteria-relay

FROM scratch
USER 65532:65532
COPY --from=build --chown=65532:65532 /out/hysteria-relay /hysteria-relay
EXPOSE 8443/udp
ENTRYPOINT ["/hysteria-relay"]
