FROM mcr.microsoft.com/devcontainers/python:1-3.12-bullseye

ARG USERNAME=vscode
ARG NODE_VERSION=20

ENV DEBIAN_FRONTEND=noninteractive

# ── System packages ───────────────────────────────────────────────────────────
RUN rm -f /etc/apt/sources.list.d/yarn.list /etc/apt/sources.list.d/yarnpkg.list \
    && find /etc/apt/sources.list.d -maxdepth 1 -type f \( -name '*yarn*' \) -delete 2>/dev/null || true \
    && apt-get update && apt-get install -y --no-install-recommends \
    jq curl wget unzip gnupg2 zsh fontconfig tmux openssh-client \
    postgresql-client \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Node.js (for frontend dev) ────────────────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── uv (Python package manager used by backend) ──────────────────────────────
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# ── Docker CLI (for running compose services from within the container) ───────
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
    https://download.docker.com/linux/debian bullseye stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Persistent shell history ──────────────────────────────────────────────────
RUN mkdir /commandhistory \
    && touch /commandhistory/.bash_history \
    && touch /commandhistory/.zsh_history \
    && chown -R $USERNAME /commandhistory \
    && echo 'export HISTFILE=/commandhistory/.bash_history' >> "/home/$USERNAME/.bashrc"

# ── zsh + Oh My Zsh + Powerlevel10k + plugins ────────────────────────────────
USER root
RUN rm -rf "/home/${USERNAME}/.oh-my-zsh" \
    && rm -f "/home/${USERNAME}/.zshrc" "/home/${USERNAME}/.zshrc.pre-oh-my-zsh"
USER $USERNAME
ENV HOME=/home/$USERNAME
ENV SHELL=/bin/bash
RUN RUNZSH=no CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended \
    && git clone --depth=1 https://github.com/romkatv/powerlevel10k.git "${HOME}/.oh-my-zsh/custom/themes/powerlevel10k" \
    && git clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions "${HOME}/.oh-my-zsh/custom/plugins/zsh-autosuggestions" \
    && git clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting.git "${HOME}/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting" \
    && curl -fsSL https://raw.githubusercontent.com/romkatv/powerlevel10k/master/config/p10k-rainbow.zsh -o "${HOME}/.p10k.zsh" \
    && { \
        echo 'typeset -g POWERLEVEL9K_DISABLE_CONFIGURATION_WIZARD=true'; \
        echo ''; \
        echo 'if [[ -r "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh" ]]; then'; \
        echo '  source "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh"'; \
        echo 'fi'; \
        echo ''; \
        cat "${HOME}/.zshrc"; \
    } > "${HOME}/.zshrc.new" && mv "${HOME}/.zshrc.new" "${HOME}/.zshrc" \
    && sed -i 's/^ZSH_THEME=.*/ZSH_THEME="powerlevel10k\/powerlevel10k"/' "${HOME}/.zshrc" \
    && sed -i 's/^plugins=(git)/plugins=(git docker zsh-autosuggestions zsh-syntax-highlighting)/' "${HOME}/.zshrc" \
    && printf '\nexport HISTFILE=/commandhistory/.zsh_history\n' >> "${HOME}/.zshrc"

USER root
RUN chsh -s /bin/zsh $USERNAME

# ── Claude Code config directory ─────────────────────────────────────────────
RUN mkdir -p /home/$USERNAME/.claude && chown -R $USERNAME /home/$USERNAME/.claude
