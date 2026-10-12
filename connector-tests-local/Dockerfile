# Disposable "local PC" for the Connector Test Lab: the real bridge with an
# empty $HOME, sharing the PC's network (--network host) so loopback OAuth
# redirects from the PC's Chrome reach CLIs running here.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 TODOFORAI_NO_AUTO_UPDATE=1
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq unzip xz-utils gnupg sudo procps \
      python3 python3-pip python3-venv pipx \
 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL https://bun.sh/install | BUN_INSTALL=/usr/local bash \
 && curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh
COPY todoforai-bridge /usr/local/bin/todoforai-bridge
WORKDIR /root
CMD ["todoforai-bridge"]
