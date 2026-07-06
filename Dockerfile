# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/surge

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/src/surge/target \
    cargo build --locked --release --package surge-server \
    && install -Dm755 target/release/surge-server /usr/local/bin/surge-server

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system surge \
    && useradd --system --gid surge --no-create-home --home-dir /nonexistent surge

COPY --from=builder /usr/local/bin/surge-server /usr/local/bin/surge-server

USER surge

ENV SURGE_BIND=0.0.0.0:3000

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/surge-server"]
CMD ["serve"]
