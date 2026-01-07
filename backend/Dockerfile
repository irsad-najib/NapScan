FROM golang:latest

# Install tools (nmap, ffuf, zap, sslyze, nuclei)
RUN apt-get update && apt-get install -y \
    nmap \
    ffuf \
    curl \
    bash \
    ca-certificates \
    python3 \
    python3-pip \
    pipx \
    openjdk-21-jre \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.local/bin:$PATH"

RUN pipx install sslyze

# Create a non-root user used specifically for gvm-cli (gvm-tools forbids root)
RUN useradd -m -s /bin/bash napscan

# gvm-tools provides gvm-cli for talking to gvmd (OpenVAS/GMP)
# Use pipx into a shared bin dir so `runuser -u napscan -- gvm-cli ...` works
ENV PIPX_HOME=/opt/pipx
ENV PIPX_BIN_DIR=/usr/local/bin
RUN pipx install gvm-tools

RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 

WORKDIR /app

RUN wget -O ZAP_2.17.0_Linux.tar.gz "https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz" \
    && tar -zxvf ZAP_2.17.0_Linux.tar.gz \
    && chmod +x ZAP_2.17.0/zap.sh \
    && rm ZAP_2.17.0_Linux.tar.gz

# Copy go files first (biar cache)
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build binary
RUN go build -o napscan .

EXPOSE 5000

# IMPORTANT: run as root (needed for nmap)
CMD ["sh", "-c", "\
  /app/ZAP_2.17.0/zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true & \
  echo 'Waiting for ZAP...' && \
  until curl -s http://localhost:8080/JSON/core/view/version/ >/dev/null; do sleep 2; done && \
  echo 'ZAP ready' && \
  /app/napscan \
    "]
