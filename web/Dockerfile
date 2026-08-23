# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS build
WORKDIR /src
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY web/ ./
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.31.2-alpine3.23@sha256:6320020c7da8714feab524e02c08c5a1958675c4e68700e93a2fd8970b065786
USER root
RUN apk upgrade --no-cache
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
USER 101
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O - http://127.0.0.1:8080/healthz || exit 1
