# The builder stage runs on the native build platform; Go cross-compiles via
# GOARCH, so no emulation is needed for other target platforms.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG TARGETARCH

WORKDIR /build

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w \
      -X github.com/DunkelCloud/ergosum/internal/version.Version=${VERSION} \
      -X github.com/DunkelCloud/ergosum/internal/version.Commit=${COMMIT}" \
    -o /out/usr/bin/ergosum ./cmd/ergosum

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
