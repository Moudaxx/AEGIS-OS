# ─── Stage 1: Build ───
FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
RUN cargo build --release

# ─── Stage 2: Runtime ───
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/aegis-os .
COPY aegis.toml .
EXPOSE 8400 8401 8402
ENTRYPOINT ["./aegis-os"]
CMD ["version"]