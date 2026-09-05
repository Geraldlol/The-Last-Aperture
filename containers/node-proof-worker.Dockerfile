FROM node@sha256:c601a46abb4d2ab80a9dc3da208d50d1122642d53f17a101926ace71e5a9bf1c

WORKDIR /opt/rta

# Only lockfile-bound dependency metadata enters this image. Lifecycle scripts
# stay disabled during the networked preparation phase; repository source runs
# later in a separate --network=none proof container.
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund \
    && mkdir -p node_modules/.vite \
    && chmod -R a+rX /opt/rta

LABEL dev.red-team-audit.proof-worker="docker-proof-v1"
