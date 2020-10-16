FROM gitpod/workspace-full

USER gitpod

RUN sudo apt-get update && \
    sudo apt-get install -y \
        build-essential \
        cmake \
        libboost-system-dev \
        libboost-program-options-dev \
        libssl-dev \
        default-libmysqlclient-dev
