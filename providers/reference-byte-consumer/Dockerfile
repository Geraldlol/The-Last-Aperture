ARG NODE_IMAGE
FROM ${NODE_IMAGE}

COPY --chown=65532:65532 adapter.mjs isolation-probes.mjs /opt/red-team-audit/

USER 65532:65532
WORKDIR /work
ENTRYPOINT ["node", "/opt/red-team-audit/adapter.mjs"]
