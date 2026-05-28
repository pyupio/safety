FROM python:3.8-alpine

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apk add --no-cache \
    git \
    curl \
    wget \
    zsh \
    jq \
    sudo \
    docker \
    docker-compose \
    bash \
    grep \
    sed \
    nodejs \
    npm \
    # Build dependencies for Python packages
    gcc \
    musl-dev \
    python3-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    rust \
    make && npm install -g pyright

RUN pip install --no-cache-dir uv \
    && uv pip install --system hatch hatch-containers

ARG USERNAME=developer
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN addgroup -g $USER_GID $USERNAME \
    && adduser -u $USER_UID -G $USERNAME -s /bin/zsh -D $USERNAME \
    && echo "$USERNAME ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    && addgroup $USERNAME docker

RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

RUN sed -i 's|/bin/ash|/bin/zsh|' /etc/passwd

RUN cp -r /root/.oh-my-zsh /home/$USERNAME/ \
    && cp /root/.zshrc /home/$USERNAME/ \
    && chown -R $USERNAME:$USERNAME /home/$USERNAME/.oh-my-zsh \
    && chown $USERNAME:$USERNAME /home/$USERNAME/.zshrc

USER $USERNAME

CMD ["zsh"]