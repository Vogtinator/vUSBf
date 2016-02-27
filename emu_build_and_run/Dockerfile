FROM debian:jessie

RUN apt-get update && \
    apt-get install -qq -y --no-install-recommends \
    build-essential \
    openssh-client \
    openssl \
    ca-certificates \
    git \
    curl \
    python \
    unzip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt

RUN git clone https://github.com/gcc-mirror/gcc.git
RUN git clone https://github.com/SPICE/usbredir
RUN git clone https://github.com/qemu/qemu.git
RUN git clone https://github.com/Fuzion24/linux.git

# GCC dependencies
RUN apt-get update && apt-get install -y -qq \
       libgmp3-dev \
       libmpfr-dev \
       libmpc-dev  \
       gcc-multilib \
       flex \
       zip \
       texinfo

RUN cd /opt/gcc && \
    ./configure && \
    make -j8 && \
    make install && \
    git clean -d -f

#USB redir dependencies
RUN apt-get update && apt-get install -y -qq \
            autotools-dev \
            automake \
            libtool \
            pkg-config \
            libusb-1.0-0 \
            libusb-1.0-0-dev

RUN cd /opt/usbredir && \
             aclocal && \
             autoconf && \
             autoheader && \
             ./autogen.sh && \
             automake --add-missing && \
             make -j8 && \
             make install

RUN apt-get install -y -qq \
      zlib1g-dev \
      libglib2.0-dev

RUN cd /opt/qemu && \
    git submodule init && \
    git submodule update && \
    ./configure --enable-usb-redir --enable-libusb && \
    make -j8 && \
    make install

RUN apt-get install -y -qq \
      bc

RUN cd /opt/linux && \
    git checkout kcov && \
    mv fuzz_config .config && \
#make defconfig
    make -j8

ADD scripts/ /scripts/

RUN apt-get install -y -qq \
    debootstrap

#RUN cd /opt/ && \
#    /scripts/make_debian_image.sh

#ENTRYPOINT ./start_qemu.sh
