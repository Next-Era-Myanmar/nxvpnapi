# syntax=docker/dockerfile:1

FROM rust:1.87-bookworm AS builder
WORKDIR /app

# Cache dependencies first
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY admin-panel ./admin-panel
COPY diesel.toml ./diesel.toml

RUN cargo build --release

FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/nxvpnapi /usr/local/bin/nxvpnapi
COPY --from=builder /app/admin-panel ./admin-panel
COPY --from=builder /app/migrations ./migrations
COPY --from=builder /app/diesel.toml ./diesel.toml

EXPOSE 8080

ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8080

CMD ["nxvpnapi"]
