# The default "base" sandbox template: a general-purpose Ubuntu image with
# Python 3, Node.js 24 (LTS), git and build tools, and a `user` account with
# sudo, like the base template E2B SDK users expect.
#
# The host agent adds envd and the sandbox init when it builds the template;
# nothing Weft-specific is baked in here.
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash ca-certificates curl wget git openssh-client sudo less nano vim-tiny \
      procps psmisc iputils-ping dnsutils net-tools unzip zip xz-utils jq \
      build-essential pkg-config \
      python3 python3-pip python3-venv python3-dev python-is-python3 \
 && rm -rf /var/lib/apt/lists/*

# Node.js from the official release, not Ubuntu's archive (which carries an
# end-of-life Node 18). The hash is the one in the release's SHASUMS256.txt,
# whose signature was checked against the Node.js release keys when this pin
# was set. Update both together.
ARG NODE_VERSION=24.21.0
ARG NODE_SHA256=fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6
RUN curl -fsSLo /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
 && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
 && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --no-same-owner \
 && rm /tmp/node.tar.xz \
 && node --version && npm --version

RUN useradd --create-home --shell /bin/bash --uid 1000 --user-group user 2>/dev/null \
      || (userdel -r ubuntu 2>/dev/null; useradd --create-home --shell /bin/bash --uid 1000 --user-group user) \
 && echo "user ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/user \
 && chmod 0440 /etc/sudoers.d/user

ENV PIP_BREAK_SYSTEM_PACKAGES=1
WORKDIR /home/user
