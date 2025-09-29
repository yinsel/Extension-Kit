FROM hub.mirrorify.net/kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    sed -i "s@http.kali.org@mirrors.tuna.tsinghua.edu.cn@g" /etc/apt/sources.list && \
    sed -i "s@kali.download@mirrors.tuna.tsinghua.edu.cn@g" /etc/apt/sources.list && \
    apt update -y && \
    apt install -y --no-install-recommends \
        make \
        mingw-w64 \
        gcc \
        g++ \
        python3 && \
    apt clean -y && \
    rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/apt/*

WORKDIR /src

CMD ["make"]