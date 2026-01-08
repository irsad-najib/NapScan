FROM golang:latest

# Install tools (nmap, ffuf, zap, sslyze, nuclei, gvm-tools)
RUN apt-get update && apt-get install -y     nmap     ffuf     curl     bash     ca-certificates     python3     python3-pip     pipx     openjdk-21-jre     && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.local/bin:$PATH"

# Install SSLyze via pipx
RUN pipx install sslyze

# Create a non-root user used specifically for gvm-cli (gvm-tools forbids root)
RUN useradd -m -s /bin/bash napscan

# gvm-tools provides gvm-cli for talking to gvmd (OpenVAS/GMP)
# Use pipx into a shared bin dir so `runuser -u napscan -- gvm-cli ...` works
ENV PIPX_HOME=/opt/pipx
ENV PIPX_BIN_DIR=/usr/local/bin
RUN pipx install gvm-tools

# Install Nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 

# Install Swag for generating API docs
RUN go install github.com/swaggo/swag/cmd/swag@v1.16.3

WORKDIR /app

# Install ZAP
RUN wget -O ZAP_2.17.0_Linux.tar.gz "https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz"     && tar -zxvf ZAP_2.17.0_Linux.tar.gz     && chmod +x ZAP_2.17.0/zap.sh     && rm ZAP_2.17.0_Linux.tar.gz

# Copy go files first (for cache)
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Generate Swagger Docs
RUN swag init -d ./cmd/server,./internal/handler,./internal/routes,./pkg/response,./internal/service,./internal/models -o ./docs

# Build binary (Point to the new main.go location)
RUN go build -o napscan ./cmd/server/main.go

EXPOSE 5000

# Run ZAP daemon + Napscan app
# IMPORTANT: run as root (needed for nmap)
CMD ["sh", "-c", "  /app/ZAP_2.17.0/zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true &   echo 'Waiting for ZAP...' &&   until curl -s http://localhost:8080/JSON/core/view/version/ >/dev/null; do sleep 2; done &&   echo 'ZAP ready' &&   /app/napscan     "]
