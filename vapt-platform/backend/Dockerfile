# ---- Stage 1: download and verify the web-scanning toolchain ----------------------------
# Every artifact is pinned to a release at least two weeks old and checked against its SHA-256.
FROM python:3.11-slim AS tools

ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG KATANA_VERSION=1.8.0
ARG KATANA_SHA256=cb027ae99d0757061b70c07a15c7a80f62c5a535ab52c4a329f80c4b0a7309d2
ARG DALFOX_VERSION=3.2.4
ARG DALFOX_SHA256=c11cfd2f8261973f0a2a2a1eba5a147ce77712a29acfa6343f9847fb8bb7eca2
ARG TESTSSL_VERSION=3.2.4
ARG TESTSSL_SHA256=98528f8a0ac07f1e226efaa8ead438247df8efcb8fee4e056a937ab82a305490
ARG SQLMAP_VERSION=1.10.10
ARG SQLMAP_SHA256=7dd690c62fb1ae58bd8555b91012896863c47fc245dc6d39ba300362a3368d17

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /dl
RUN set -eux; \
    curl -fsSL -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"; \
    echo "${NUCLEI_SHA256}  nuclei.zip" | sha256sum -c -; \
    curl -fsSL -o katana.zip "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip"; \
    echo "${KATANA_SHA256}  katana.zip" | sha256sum -c -; \
    curl -fsSL -o dalfox.tgz "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-v${DALFOX_VERSION}-linux-x86_64-musl.tar.gz"; \
    echo "${DALFOX_SHA256}  dalfox.tgz" | sha256sum -c -; \
    curl -fsSL -o testssl.tgz "https://github.com/testssl/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz"; \
    echo "${TESTSSL_SHA256}  testssl.tgz" | sha256sum -c -; \
    curl -fsSL -o sqlmap.tgz "https://github.com/sqlmapproject/sqlmap/archive/refs/tags/${SQLMAP_VERSION}.tar.gz"; \
    echo "${SQLMAP_SHA256}  sqlmap.tgz" | sha256sum -c -; \
    mkdir -p /out/bin /out/opt; \
    unzip -o nuclei.zip nuclei -d /out/bin; \
    unzip -o katana.zip katana -d /out/bin; \
    tar -xzf dalfox.tgz -C /tmp; find /tmp -maxdepth 3 -type f -name dalfox -exec cp {} /out/bin/dalfox \; ; \
    tar -xzf testssl.tgz -C /out/opt; mv /out/opt/testssl.sh-* /out/opt/testssl; \
    tar -xzf sqlmap.tgz -C /out/opt; mv /out/opt/sqlmap-* /out/opt/sqlmap; \
    chmod +x /out/bin/*; \
    /out/bin/nuclei -version; /out/bin/katana -version; /out/bin/dalfox --version || /out/bin/dalfox version

# Nuclei templates: a pinned, checksum-verified release of projectdiscovery/nuclei-templates,
# baked in so scans work offline and results are reproducible. Bump the version to refresh.
ARG NUCLEI_TEMPLATES_VERSION=10.5.1
ARG NUCLEI_TEMPLATES_SHA256=30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb
RUN set -eux;     curl -fsSL -o /dl/templates.tgz "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz";     echo "${NUCLEI_TEMPLATES_SHA256}  /dl/templates.tgz" | sha256sum -c -;     tar -xzf /dl/templates.tgz -C /out/opt; mv /out/opt/nuclei-templates-* /out/opt/nuclei-templates;     rm -rf /out/opt/nuclei-templates/.github;     test "$(find /out/opt/nuclei-templates -name '*.yaml' | wc -l)" -gt 10000


# ---- Stage 2: the API ----------------------------------------------------------------
FROM python:3.11-slim

# nmap: network engine. bsdextrautils/dnsutils/procps/openssl: needed by testssl.sh.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    nmap \
    libpq-dev \
    bsdextrautils \
    dnsutils \
    procps \
    openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=tools /out/bin/ /usr/local/bin/
COPY --from=tools /out/opt/testssl /opt/testssl
COPY --from=tools /out/opt/sqlmap /opt/sqlmap
COPY --from=tools /out/opt/nuclei-templates /opt/nuclei-templates
RUN ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
    && printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap

ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=120 --retries 10 -r requirements.txt

COPY app ./app
COPY bin ./bin

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
