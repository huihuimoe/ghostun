# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM rust:1.99.1-slim-trixie AS build
ARG TARGETARCH
WORKDIR /build
RUN case "$TARGETARCH" in \
      amd64) compiler=gcc-x86-64-linux-gnu; rust_target=x86_64-unknown-linux-gnu ;; \
      arm64) compiler=gcc-aarch64-linux-gnu; rust_target=aarch64-unknown-linux-gnu ;; \
      *) exit 1 ;; \
    esac \
    && if [ "$(dpkg --print-architecture)" != "$TARGETARCH" ]; then \
         apt-get update \
         && apt-get install -y --no-install-recommends "$compiler" \
         && rustup target add "$rust_target" \
         && rm -rf /var/lib/apt/lists/*; \
       fi
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN case "$TARGETARCH" in \
      amd64) rust_target=x86_64-unknown-linux-gnu ;; \
      arm64) rust_target=aarch64-unknown-linux-gnu ;; \
      *) exit 1 ;; \
    esac \
    && export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
              CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    && cargo build --locked --release --target "$rust_target" \
    && install -D -m 0755 "target/$rust_target/release/ghostun" /out/usr/local/bin/ghostun

FROM cgr.dev/chainguard/wolfi-base
RUN apk add --no-cache iproute2 nftables
COPY --from=build /out/ /
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/ghostun"]
