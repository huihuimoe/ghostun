FROM cgr.dev/chainguard/rust:latest-dev AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM cgr.dev/chainguard/wolfi-base
RUN apk add --no-cache iproute2 nftables
COPY --from=build /src/target/release/ghostun /usr/local/bin/ghostun
ENTRYPOINT ["/usr/local/bin/ghostun"]
