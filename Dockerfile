# syntax=docker/dockerfile:1.28
FROM --platform=$BUILDPLATFORM rust:1.99.1-slim-trixie AS build
ARG TARGETARCH
ENV RUSTFLAGS="-C linker=rust-lld"
WORKDIR /build
RUN case "$TARGETARCH" in \
      amd64) rust_target=x86_64-unknown-linux-musl ;; \
      arm64) rust_target=aarch64-unknown-linux-musl ;; \
      *) exit 1 ;; \
    esac \
    && rustup target add "$rust_target"
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN case "$TARGETARCH" in \
      amd64) rust_target=x86_64-unknown-linux-musl ;; \
      arm64) rust_target=aarch64-unknown-linux-musl ;; \
      *) exit 1 ;; \
    esac \
    && cargo build --locked --release --target "$rust_target" \
    && install -D -m 0755 "target/$rust_target/release/ghostun" /out/usr/local/bin/ghostun

FROM cgr.dev/chainguard/static:latest
COPY --from=build /out/ /
STOPSIGNAL SIGTERM
USER root
ENTRYPOINT ["ghostun"]
