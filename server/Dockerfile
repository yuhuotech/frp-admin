# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY contracts/go.mod contracts/go.sum ./contracts/
COPY server/go.mod server/go.sum ./server/
RUN --mount=type=cache,target=/go/pkg/mod cd server && GOWORK=off go mod download
COPY contracts ./contracts
COPY server ./server
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd server && GOWORK=off CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -ldflags="-s -w" -o /out/frp-admin-server ./cmd/frp-admin-server

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
RUN addgroup -S frpadmin && adduser -S -G frpadmin -h /app frpadmin \
    && apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/frp-admin-server /usr/local/bin/frp-admin-server
RUN install -d -o frpadmin -g frpadmin -m 0700 /app/data
USER frpadmin
EXPOSE 8080 8443
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O - http://127.0.0.1:8080/health/ready || exit 1
ENTRYPOINT ["/usr/local/bin/frp-admin-server"]
