# syntax=docker/dockerfile:1
# Base images are pinned by digest; update the tag and digest together.
FROM rust:1.94.1-slim-trixie@sha256:cf09adf8c3ebaba10779e5c23ff7fe4df4cccdab8a91f199b0c142c53fef3e1a AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release --workspace --features tls --bins

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 spry \
    && useradd --uid 10001 --gid spry --home-dir /data --no-create-home spry \
    && install -d -o spry -g spry -m 0700 /data /data/tls
COPY --from=build /src/target/release/spry-turn /usr/local/bin/spry-turn
COPY --from=build /src/target/release/spry-node /usr/local/bin/spry-node
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY LICENSE NOTICE THIRD_PARTY_LICENSES.txt /usr/share/doc/spry-turn/
LABEL org.opencontainers.image.licenses=MIT \
      org.opencontainers.image.source=https://github.com/forgesworn/spry-turn \
      org.opencontainers.image.description="Standalone owner-operated Spry pairing and STUN/TURN service"
ENV SPRY_RELAY_BINARY=/usr/local/bin/spry-turn \
    SPRY_STATE_FILE=/data/pairings.json
USER spry
WORKDIR /data
EXPOSE 3744/tcp 3478/tcp 3478/udp 5349/tcp
EXPOSE 49160-49191/udp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh", "/usr/local/bin/spry-node"]
