# syntax=docker/dockerfile:1.28
FROM --platform=$BUILDPLATFORM rust:1.99.1-slim-trixie AS build
ARG TARGETARCH
WORKDIR /build
RUN case "$TARGETARCH" in \
      amd64) compiler=gcc-x86-64-linux-gnu; rust_target=x86_64-unknown-linux-musl ;; \
      arm64) compiler=gcc-aarch64-linux-gnu; rust_target=aarch64-unknown-linux-musl ;; \
      *) exit 1 ;; \
    esac \
    && rustup target add "$rust_target" \
    && if [ "$(dpkg --print-architecture)" != "$TARGETARCH" ]; then \
         apt-get update \
         && apt-get install -y --no-install-recommends "$compiler" \
         && rm -rf /var/lib/apt/lists/*; \
       fi
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN case "$TARGETARCH" in \
      amd64) rust_target=x86_64-unknown-linux-musl ;; \
      arm64) rust_target=aarch64-unknown-linux-musl ;; \
      *) exit 1 ;; \
    esac \
    && export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-gnu-gcc \
              CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
    && cargo build --locked --release --target "$rust_target" \
    && install -D -m 0755 "target/$rust_target/release/ghostun" /out/usr/local/bin/ghostun

FROM alpine:3.24.3
RUN apk add --no-cache iproute2-minimal nftables
COPY --from=build /out/ /
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/ghostun"]
