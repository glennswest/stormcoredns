# Build with podman on the dev box:
#   podman build -t stormcoredns:latest .
# The result is FROM scratch: one static binary plus CA roots.

FROM docker.io/library/rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler musl-tools && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
WORKDIR /src
COPY . .
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      arm64) T=aarch64-unknown-linux-musl ;; \
      *)     T=x86_64-unknown-linux-musl ;; \
    esac && \
    cargo build --release --target "$T" && \
    cp "target/$T/release/stormcoredns" /stormcoredns

FROM scratch
COPY --from=build /stormcoredns /coredns
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 53 53/udp
ENTRYPOINT ["/coredns"]
