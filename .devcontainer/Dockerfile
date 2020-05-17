FROM ubuntu

RUN cp /etc/apt/sources.list /etc/apt/source.list.backup \
    && apt-get update && apt-get install -y \
    apt-utils \
    build-essential \
    cmake \
    cppcheck \
    valgrind \
    libboost-system-dev \
    libboost-program-options-dev \
    libssl-dev default-libmysqlclient-dev \
    net-tools \
    iputils-ping \
    vim \
    git \
    && apt-get autoremove -y \
    && apt-get clean -y

    # && sed -i '1i deb https://mirrors.ustc.edu.cn/ubuntu/ bionic main restricted universe multiverse \ndeb-src https://mirrors.ustc.edu.cn/ubuntu/ bionic main restricted universe multiverse \ndeb https://mirrors.ustc.edu.cn/ubuntu/ bionic-updates main restricted universe multiverse \ndeb-src https://mirrors.ustc.edu.cn/ubuntu/ bionic-updates main restricted universe multiverse \ndeb https://mirrors.ustc.edu.cn/ubuntu/ bionic-backports main restricted universe multiverse \ndeb-src https://mirrors.ustc.edu.cn/ubuntu/ bionic-backports main restricted universe multiverse \ndeb https://mirrors.ustc.edu.cn/ubuntu/ bionic-security main restricted universe multiverse \ndeb-src https://mirrors.ustc.edu.cn/ubuntu/ bionic-security main restricted universe multiverse \ndeb https://mirrors.ustc.edu.cn/ubuntu/ bionic-proposed main restricted universe multiverse \ndeb-src https://mirrors.ustc.edu.cn/ubuntu/ bionic-proposed main restricted universe multiverse \n' sources.list \
    # && sed -i '1i deb http://mirrors.ustc.edu.cn/kali kali-rolling main non-free contrib \ndeb-src http://mirrors.ustc.edu.cn/kali kali-rolling main non-free contrib \ndeb http://mirrors.aliyun.com/kali kali-rolling main non-free contrib \ndeb-src http://mirrors.aliyun.com/kali kali-rolling main non-free contrib \ndeb http://mirrors.tuna.tsinghua.edu.cn/kali kali-rolling main contrib non-free \ndeb-src https://mirrors.tuna.tsinghua.edu.cn/kali kali-rolling main contrib non-free \n' sources.list \
    # && (cd trojan && cmake . && make -j $(nproc) && strip -s trojan \
    # && mv trojan /usr/local/bin) \
    # && rm -rf trojan \
    # && apt del .build-deps \
    # && apt -y install --no-cache --virtual .trojan-rundeps \
    #     libstdc++ \
    #     boost-system \
    #     boost-program_options \
    #     mariadb-connector-c

# WORKDIR /config
# CMD ["trojan", "config.json"]
