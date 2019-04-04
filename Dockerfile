FROM alpine:3.9

LABEL maintainer="mritd <mritd1234@gmail.com>"

ARG TZ='Asia/Shanghai'

ENV TZ ${TZ}
ENV LINUX_HEADERS_DOWNLOAD_URL=http://dl-cdn.alpinelinux.org/alpine/v3.7/main/x86_64/linux-headers-4.4.6-r2.apk

COPY . /trojan

WORKDIR /trojan

RUN set -ex \
    && apk upgrade \
    && apk add bash tzdata\
    && apk add --virtual .build-deps \
        build-base \
        boost-dev \
        curl \
        cmake \
        mariadb-dev \
        tar \
        git \
    && curl -sSL ${LINUX_HEADERS_DOWNLOAD_URL} > /linux-headers-4.4.6-r2.apk \
    && apk add --virtual .build-deps-kernel /linux-headers-4.4.6-r2.apk \
    && mkdir -p build /usr/local/etc/trojan \
    && (cd build && cmake .. && make && make install ) \
    && ln -sf /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo ${TZ} > /etc/timezone \
    && runDeps="$( \
        scanelf --needed --nobanner /usr/local/bin/trojan \
            | awk '{ gsub(/,/, "\nso:", $2); print "so:" $2 }' \
            | xargs -r apk info --installed \
            | sort -u \
        )" \
    && apk add --virtual .run-deps $runDeps \
    && apk del .build-deps .build-deps-kernel \
    && rm -rf /linux-headers-4.4.6-r2.apk \
        /trojan \
        /var/cache/apk/*

EXPOSE 80 443

CMD ["trojan"]
