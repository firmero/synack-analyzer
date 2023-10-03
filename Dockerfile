FROM rust:1.70.0-slim-buster as builder
RUN apt-get update && apt-get install -y libpcap0.8-dev && rm -rf /var/lib/apt/lists/*
RUN cargo search --limit 0
WORKDIR /usr/src/synack-analyzer
COPY Cargo.* .
COPY src ./src
RUN cargo install --path .

FROM debian:buster-slim
RUN apt-get update && apt-get install -y libcap2-bin libpcap0.8-dev && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/synack-analyzer /usr/local/bin/synack-analyzer
ENTRYPOINT ["/usr/local/bin/synack-analyzer"]
CMD ["--help"]

