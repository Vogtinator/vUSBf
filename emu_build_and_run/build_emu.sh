#! /bin/sh

DOCKER_NAME=virtual_usb_qemu

docker build -t $DOCKER_NAME . && \
docker run --rm -v $(pwd):/build $DOCKER_NAME
