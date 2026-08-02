# Runtime image for the released binaries. The Release workflow builds the
# per-arch binaries on native runners and assembles a build context of
# amd64/<binaries> and arm64/<binaries> next to config.example.toml; this
# file only selects and installs them, it does not compile anything.
#
#   docker buildx build --platform linux/amd64,linux/arm64 -f Dockerfile <ctx>
FROM debian:bookworm-slim

# rustls loads the system trust store (rustls-native-certs), so outbound TLS
# (e.g. streaming a snapshot download) needs CA roots present.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
COPY --chmod=0755 ${TARGETARCH}/ /usr/local/bin/
COPY config.example.toml /etc/tron/config.example.toml

# Working directory doubles as the state volume: tron-node auto-loads
# ./config.toml, so a config mounted into /data is picked up with no flags.
WORKDIR /data
VOLUME /data

# P2P 18889, HTTP REST 8091, JSON-RPC 8546, gRPC 50052.
EXPOSE 18889 8091 8546 50052

ENTRYPOINT ["tron-node"]
CMD ["start", "--data-dir", "/data"]
