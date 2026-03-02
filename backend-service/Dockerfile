# Stage 1: Build
FROM rust:1.85-bookworm AS builder

WORKDIR /app

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
# Set SQLX_OFFLINE to skip compile-time DB checks
ENV SQLX_OFFLINE=true
RUN cargo build --release || true

# Now copy real source
COPY src/ src/
COPY migrations/ migrations/

# Touch main.rs to invalidate the dummy
RUN touch src/main.rs

# Build the real binary
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false appuser

WORKDIR /app

COPY --from=builder /app/target/release/runthedev-api ./
COPY --from=builder /app/migrations/ ./migrations/

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 4000

CMD ["./runthedev-api"]
