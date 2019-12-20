ARG NODE_IMAGE_VERSION=10.16.0

FROM node:${NODE_IMAGE_VERSION}

RUN mkdir -p ~/ui

WORKDIR /home/node/ui

COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
