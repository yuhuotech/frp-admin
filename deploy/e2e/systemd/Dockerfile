FROM golang:1.26.5-bookworm AS build
WORKDIR /src
COPY contracts ./contracts
COPY agent ./agent
RUN cd agent && go build -trimpath -ldflags='-s -w' -o /out/frp-agent ./cmd/frp-agent
RUN cd agent && go build -trimpath -ldflags='-s -w' -o /out/frp-agent-helper ./cmd/frp-agent-helper
RUN cd agent && go build -trimpath -ldflags='-s -w' -o /out/frp-agent-load ./cmd/frp-agent-load
RUN cd agent && go test -c -o /out/frp-agent-systemd-e2e ./e2e

FROM ubuntu:24.04
ARG TARGETARCH
ARG FRP_VERSION=0.70.0
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl iproute2 openssl systemd systemd-sysv dbus passwd && \
    rm -rf /var/lib/apt/lists/*
RUN case "$TARGETARCH" in \
      amd64) FRP_SHA256=281cb31e6b915113179c6ebb65b5977a5d9d7fb96f9a70867be83dee3b657721 ;; \
      arm64) FRP_SHA256=9dd282fd8d1b90a8ee760702ac5b876748b519c6bdfac7c68418f62a05d805c6 ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac && \
    archive="frp_${FRP_VERSION}_linux_${TARGETARCH}.tar.gz" && \
    curl --fail --location --proto '=https' --tlsv1.2 \
      "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${archive}" \
      -o /tmp/frp.tar.gz && \
    echo "${FRP_SHA256}  /tmp/frp.tar.gz" | sha256sum --check --strict && \
    tar -xzf /tmp/frp.tar.gz -C /tmp && \
    install -d -m 0755 /opt/frp/bin && \
    install -m 0755 "/tmp/frp_${FRP_VERSION}_linux_${TARGETARCH}/frpc" /opt/frp/bin/frpc && \
    install -m 0755 "/tmp/frp_${FRP_VERSION}_linux_${TARGETARCH}/frps" /opt/frp/bin/frps && \
    install -d -m 0700 /opt/frp-admin-e2e && \
    install -m 0600 /tmp/frp.tar.gz /opt/frp-admin-e2e/frp.tar.gz && \
    rm -rf /tmp/frp*

COPY --from=build /out/frp-agent /usr/local/bin/frp-agent
COPY --from=build /out/frp-agent-helper /usr/local/libexec/frp-agent-helper
COPY --from=build /out/frp-agent-load /usr/local/bin/frp-agent-load
COPY --from=build /out/frp-agent-systemd-e2e /usr/local/bin/frp-agent-systemd-e2e
COPY agent/packaging/systemd/frp-agent.service /etc/systemd/system/frp-agent.service
COPY agent/packaging/systemd/frp-agent-helper.service /etc/systemd/system/frp-agent-helper.service
COPY agent/packaging/systemd/frp-agent-helper.socket /etc/systemd/system/frp-agent-helper.socket
COPY deploy/e2e/systemd/frpc.service /etc/systemd/system/frpc.service
COPY deploy/e2e/systemd/frps.service /etc/systemd/system/frps.service
COPY deploy/e2e/systemd/frp-e2e-prestart /usr/local/libexec/frp-e2e-prestart
COPY deploy/e2e/systemd/setup.sh /opt/frp-admin-e2e/setup.sh
COPY deploy/e2e/systemd/run.sh /opt/frp-admin-e2e/run.sh
RUN chmod 0755 /usr/local/libexec/frp-e2e-prestart /opt/frp-admin-e2e/setup.sh /opt/frp-admin-e2e/run.sh && \
    groupadd --system frp-agent && useradd --system --gid frp-agent --home-dir /var/lib/frp-agent --shell /usr/sbin/nologin frp-agent && \
    chown -R root:root /opt/frp/bin

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
