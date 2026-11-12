# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION
WORKDIR /src
RUN apk add --no-cache ca-certificates && mkdir /empty-data && chown 10001:10001 /empty-data
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w ${VERSION:+-X github.com/blagodaren/mirulesets/internal/version.Version=$VERSION}" -o /out/mirulesets ./cmd/mirulesets

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/mirulesets /mirulesets
COPY --from=build --chown=10001:10001 /empty-data /data
USER 10001:10001
WORKDIR /data
ENV MI_ADDR=:8080 MI_DATA_DIR=/data
EXPOSE 8080 8443
ENTRYPOINT ["/mirulesets"]
