FROM alpine:3.15 AS builder
COPY . /trojan
RUN apk add --no-cache \
        boost-dev \
        build-base \
        cmake \
        mariadb-connector-c-dev \
        openssl-dev \
    && (cd /trojan && cmake . && make -j $(nproc) && strip -s trojan)

FROM alpine:3.15
RUN apk add --no-cache \
        boost-program_options \
        boost-system \
        libstdc++ \
        mariadb-connector-c
COPY --from=builder /trojan/trojan /usr/local/bin/trojan

WORKDIR /config
ENTRYPOINT ["/usr/local/bin/trojan", "/config/config.json"]
