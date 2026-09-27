# The default "base" sandbox template: a general-purpose Ubuntu image with
# Python, Node.js, git and build tools, and a `user` account with sudo, like
# the base template E2B SDK users expect.
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
      nodejs npm \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash --uid 1000 --user-group user 2>/dev/null \
      || (userdel -r ubuntu 2>/dev/null; useradd --create-home --shell /bin/bash --uid 1000 --user-group user) \
 && echo "user ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/user \
 && chmod 0440 /etc/sudoers.d/user

ENV PIP_BREAK_SYSTEM_PACKAGES=1
WORKDIR /home/user
