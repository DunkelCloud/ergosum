# The builder stage runs on the native build platform; Go cross-compiles via
# GOARCH, so no emulation is needed for other target platforms.
# Pinned by digest. The Go version matches the toolchain in go.mod, so that
# the image carries the bytes that scripts/build.sh produces elsewhere.
FROM --platform=$BUILDPLATFORM golang:1.26.11-alpine@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG TARGETARCH

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN GOOS=linux GOARCH=${TARGETARCH} VERSION=${VERSION} COMMIT=${COMMIT} \
    sh scripts/build.sh /out/usr/bin ergosum

# The state directory (journal, control socket) belongs to the unprivileged
# user, so that a named volume mounted there inherits the ownership.
RUN mkdir -p /out/var/lib/ergosum-authority /out/etc/ergosum \
 && chown 65532:65532 /out/var/lib/ergosum-authority \
 && chmod 0700 /out/var/lib/ergosum-authority

FROM scratch

COPY --from=builder /out/ /

USER 65532:65532
VOLUME ["/var/lib/ergosum-authority"]
EXPOSE 7432 7434 7435

ENTRYPOINT ["/usr/bin/ergosum"]
CMD ["serve", "--config", "/etc/ergosum/serve.yaml"]
