FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# Barretenberg prover, pinned to the version the circuit was built with
RUN curl -fsSL https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash \
 && /root/.bb/bbup -v 5.0.0-nightly.20260522
ENV BB_BIN=/root/.bb/bb
WORKDIR /app
COPY package.json yarn.lock ./
RUN corepack enable && yarn install --frozen-lockfile
COPY tsconfig.json ./
COPY src ./src
COPY circuit ./circuit
RUN yarn build
ENV CIRCUIT_JSON=/app/circuit/pvium_identity.json VK_PATH=/app/circuit/vk WORK_DIR=/dev/shm PORT=8787 DB_PATH=/app/data/prover.db
# The outbox (undelivered callback jobs + their attestations) must outlive the container.
VOLUME /app/data
EXPOSE 8787
CMD ["node", "dist/server.js"]
