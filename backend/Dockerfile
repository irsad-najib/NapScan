FROM golang:1.25.2

# Node.js and frida-compile are no longer needed


# Install tools (nmap, ffuf, zap, sslyze, nuclei, gvm-tools)
RUN apt-get update && apt-get install -y \
    nmap \
    ffuf \
    curl \
    bash \
    ca-certificates \
    python3 \
    python3-pip \
    pipx \
    default-jre \
    android-tools-adb \
    xz-utils \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*


ENV PIPX_HOME=/opt/pipx
ENV PIPX_BIN_DIR=/usr/local/bin

# Install SSLyze and Frida via pipx
RUN pipx install sslyze  && pipx install frida-tools

# Create a non-root user used specifically for gvm-cli (gvm-tools forbids root)
RUN useradd -m -s /bin/bash napscan

# gvm-tools provides gvm-cli for talking to gvmd (OpenVAS/GMP)
# Use pipx into a shared bin dir so `runuser -u napscan -- gvm-cli ...` works
RUN pipx install gvm-tools

# Install Nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.2.9

# Install Swag for generating API docs
RUN go install github.com/swaggo/swag/cmd/swag@v1.16.3

WORKDIR /app

# Install ZAP
RUN wget -O ZAP_2.17.0_Linux.tar.gz "https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz" && tar -zxvf ZAP_2.17.0_Linux.tar.gz && chmod +x ZAP_2.17.0/zap.sh     && rm ZAP_2.17.0_Linux.tar.gz

# Download Frida Server
RUN wget -O frida-server.xz "https://github.com/frida/frida/releases/download/17.5.2/frida-server-17.5.2-android-x86_64.xz" && unxz frida-server.xz

# Copy go files first (for cache)
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Frida script is now pre-built as agent.js (ES module/CommonJS hybrid not needed, single file)


# Generate Swagger Docs
RUN swag init -d ./cmd/server,./internal/handler,./internal/routes,./pkg/response,./internal/service,./internal/models -o ./docs

# Build binary (Point to the new main.go location)
RUN go build -o napscan ./cmd/server/main.go

EXPOSE 5000

# Entrypoint
ENTRYPOINT ["./entrypoint.sh"]