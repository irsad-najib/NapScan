# 🛡️ NapScan - Enterprise Vulnerability Scanning Platform

**Production-grade vulnerability scanning backend system integrating multiple security tools**

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://golang.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-13+-336791?style=flat&logo=postgresql)](https://www.postgresql.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Documentation](#documentation)
- [API Reference](#api-reference)
- [Scanner Support](#scanner-support)
- [Database Schema](#database-schema)
- [Development](#development)
- [Production Deployment](#production-deployment)
- [Contributing](#contributing)

## 🎯 Overview

NapScan is a modular, extensible vulnerability scanning platform that:

- ✅ Integrates 6+ security scanning tools (Nmap, Nuclei, SSLyze, FFUF, ZAP, OpenVAS)
- ✅ Executes scans in parallel with worker pool pattern
- ✅ Normalizes findings into unified vulnerability schema
- ✅ Generates comprehensive security reports with risk scoring
- ✅ Provides RESTful API for automation
- ✅ Persists results in PostgreSQL for historical analysis
- ✅ Supports three scan modes: all tools, single tool, or custom selection

## ✨ Features

### Core Capabilities

🔹 **Multi-Scanner Integration**

- Unified interface for all security tools
- Easy to add new scanners
- Runtime scanner validation

🔹 **Parallel Execution**

- Configurable worker pool (default: 10 workers)
- Context-based timeout and cancellation
- Failure isolation (one tool failure doesn't stop others)

🔹 **Unified Vulnerability Schema**

- Standardized severity levels (critical → info)
- CVE, CWE, CVSS scoring
- Affected asset tracking
- Evidence and remediation guidance

🔹 **Advanced Reporting**

- Risk score calculation (0-100)
- Vulnerability deduplication via fingerprinting
- Tool coverage analysis
- Compliance impact assessment
- Actionable recommendations

🔹 **Production Features**

- JWT authentication
- User-scoped data access
- Audit logging
- Database persistence
- RESTful API
- Real-time status tracking

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Layer                           │
│         Web UI / Mobile / CLI / API Clients                 │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTPS REST API
┌───────────────────────▼─────────────────────────────────────┐
│                   API Gateway (Fiber)                       │
│          Auth • CORS • Logging • Rate Limiting              │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│              Batch Orchestrator (Worker Pool)               │
│    Job Scheduler │ Scanner Registry │ Result Aggregator    │
└───────────┬───────────────────────────────┬─────────────────┘
            │                               │
            │ Parallel Execution            │ Report Generation
            ▼                               ▼
┌──────────────────────────┐  ┌──────────────────────────────┐
│   Security Scanners      │  │    Report Aggregator         │
│  Nmap │ Nuclei │ SSLyze  │  │  Risk Scoring │ Deduplication│
│  FFUF │  ZAP   │ OpenVAS │  │  Normalization│ Recommendations│
└──────────┬───────────────┘  └──────────────┬───────────────┘
           │                                  │
           └──────────────┬───────────────────┘
                          │
┌─────────────────────────▼─────────────────────────────────┐
│              Repository Layer (Data Access)                │
│        Batch Repo │ Vulnerability Repo │ Report Repo      │
└─────────────────────────┬─────────────────────────────────┘
                          │
┌─────────────────────────▼─────────────────────────────────┐
│                 PostgreSQL Database                        │
│   Batches │ Jobs │ Vulnerabilities │ Reports │ Audit Log  │
└───────────────────────────────────────────────────────────┘
```

See [DIAGRAMS.md](DIAGRAMS.md) for detailed architecture diagrams.

## 🚀 Quick Start

### Prerequisites

```bash
# Required
- Go 1.25+
- PostgreSQL 13+
- Nmap 7.80+

# Optional (for full scanner support)
- Nuclei
- SSLyze
- FFUF
- OWASP ZAP
- OpenVAS
```

### Installation

```bash
# 1. Clone repository
git clone https://github.com/yourusername/napscan.git
cd napscan

# 2. Setup database
createdb napscan
psql napscan < backend/internal/repository/schema.sql

# 3. Configure environment
cat > .env << EOF
DATABASE_URL=postgresql://user:pass@localhost:5432/napscan
JWT_SECRET=your-super-secret-key-change-this
PORT=8080
MAX_WORKERS=10
EOF

# 4. Install Go dependencies
cd backend
go mod download

# 5. Install security tools
sudo apt-get install nmap
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# 6. Run server
go run cmd/server/main.go
```

### First Scan

```bash
# 1. Register user
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SecurePass123!","email":"admin@example.com"}'

# 2. Login
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SecurePass123!"}' | jq -r '.token')

# 3. Start scan
BATCH_ID=$(curl -s -X POST http://localhost:8080/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","scan_type":"single","tool_names":["nmap"]}' \
  | jq -r '.batch_id')

# 4. Check status
curl -s http://localhost:8080/api/scans/$BATCH_ID \
  -H "Authorization: Bearer $TOKEN" | jq

# 5. Get report (after completion)
curl -s http://localhost:8080/api/scans/$BATCH_ID/report \
  -H "Authorization: Bearer $TOKEN" | jq > report.json
```

## 📚 Documentation

### Core Documentation

- [**ARCHITECTURE.md**](ARCHITECTURE.md) - System design and components
- [**API_EXAMPLES.md**](API_EXAMPLES.md) - Complete API usage with examples
- [**DIAGRAMS.md**](DIAGRAMS.md) - Visual architecture diagrams
- [**MIGRATION_GUIDE.md**](MIGRATION_GUIDE.md) - Migration from existing systems
- [**IMPLEMENTATION_SUMMARY.md**](IMPLEMENTATION_SUMMARY.md) - What's implemented

### Code Examples

- [**examples/complete_initialization.go**](backend/examples/complete_initialization.go) - Full server setup

## 🔌 API Reference

### Authentication

**Register User**

```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "string",
  "password": "string",
  "email": "string"
}
```

**Login**

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "string",
  "password": "string"
}

Response: { "token": "jwt-token", "user_id": "...", "expires_at": "..." }
```

### Scan Operations

**Create Scan**

```http
POST /api/scans
Authorization: Bearer {token}
Content-Type: application/json

{
  "target": "192.168.1.1",
  "scan_type": "all|single|custom",
  "tool_names": ["nmap", "nuclei"],  // for single/custom
  "timeout": 20,  // minutes
  "options": {
    "nmap": {"ports": "1-1000"},
    "nuclei": {"severity": "high,critical"}
  }
}

Response: { "batch_id": "uuid", "status": "processing", ... }
```

**Get Batch Status**

```http
GET /api/scans/:batchId
Authorization: Bearer {token}

Response: {
  "batch_id": "...",
  "status": "processing|completed|failed",
  "expected_jobs": 6,
  "completed_jobs": 4,
  "jobs": [...]
}
```

**Get Comprehensive Report**

```http
GET /api/scans/:batchId/report
Authorization: Bearer {token}

Response: {
  "summary": {...},
  "vulnerability_stats": {...},
  "vulnerabilities": [...],
  "risk_assessment": {...},
  "recommendations": [...]
}
```

**List Batches**

```http
GET /api/scans?limit=10&offset=0
Authorization: Bearer {token}

Response: { "batches": [...], "count": 10 }
```

### Utility Endpoints

**Health Check**

```http
GET /health

Response: {
  "status": "healthy",
  "database": "connected",
  "available_tools": ["nmap", "nuclei"],
  "unavailable_tools": ["openvas"]
}
```

**List Scanners**

```http
GET /api/scanners
Authorization: Bearer {token}

Response: {
  "scanners": [
    {"name": "nmap", "available": true},
    {"name": "openvas", "available": false, "error": "..."}
  ]
}
```

See [API_EXAMPLES.md](API_EXAMPLES.md) for complete examples with cURL, Python, and Node.js.

## 🛠️ Scanner Support

### Implemented Scanners

| Scanner       | Status      | Purpose                               | Normalization                     |
| ------------- | ----------- | ------------------------------------- | --------------------------------- |
| **Nmap**      | ✅ Complete | Port scanning, service detection      | High-risk ports, service versions |
| **Nuclei**    | ✅ Complete | Template-based vulnerability scanning | CVE, severity mapping             |
| **SSLyze**    | ⏳ Template | SSL/TLS configuration analysis        | -                                 |
| **FFUF**      | ⏳ Template | Web fuzzing, directory discovery      | -                                 |
| **OWASP ZAP** | ⏳ Template | Web application security              | -                                 |
| **OpenVAS**   | ⏳ Template | Comprehensive vulnerability scanner   | -                                 |

### Adding New Scanners

```go
// 1. Implement Scanner interface
type MyScanner struct{}

func (s *MyScanner) Name() string { return "myscanner" }

func (s *MyScanner) Execute(ctx context.Context, config scanner.ScanConfig) (interface{}, error) {
    // Execute your tool
    cmd := exec.CommandContext(ctx, "mytool", config.Target)
    output, err := cmd.CombinedOutput()
    return parseOutput(output), err
}

func (s *MyScanner) Normalize(rawResult interface{}) ([]scanner.Vulnerability, error) {
    // Convert to unified vulnerability schema
    return []scanner.Vulnerability{
        {
            Title: "Found Issue",
            Severity: scanner.SeverityHigh,
            AffectedAsset: []string{config.Target},
            SourceTool: "myscanner",
            // ...
        },
    }, nil
}

func (s *MyScanner) Validate() error {
    return exec.Command("mytool", "--version").Run()
}

// 2. Register scanner
registry.MustRegister(&MyScanner{})
```

## 💾 Database Schema

### Key Tables

**batches** - Scan batch tracking

- `id`, `batch_id`, `user_id`, `target`, `status`
- `expected_job_count`, `completed_job_count`, `failed_job_count`
- Timestamps: `created_at`, `updated_at`, `completed_at`

**scan_jobs** - Individual scanner executions

- `id`, `batch_id`, `tool_name`, `status`
- `start_time`, `end_time`, `duration_ms`
- `raw_result` (JSONB), `error_message`

**vulnerabilities** - Normalized findings

- `id`, `batch_id`, `scan_job_id`
- `title`, `severity`, `description`
- `affected_asset` (JSONB), `source_tool`
- `evidence`, `remediation`
- `cve`, `cwe`, `cvss`
- `fingerprint`, `is_duplicate`, `duplicate_of`

See [schema.sql](backend/internal/repository/schema.sql) for complete schema.

## 🔧 Development

### Project Structure

```
backend/
├── cmd/server/main.go           # Entry point
├── internal/
│   ├── scanner/                 # Scanner interface
│   │   ├── interface.go
│   │   └── registry.go
│   ├── scanners/                # Scanner implementations
│   │   ├── nmap_scanner.go
│   │   └── nuclei_scanner.go
│   ├── orchestrator/            # Batch execution
│   │   └── batch_orchestrator.go
│   ├── aggregator/              # Report generation
│   │   └── report_aggregator.go
│   ├── repository/              # Data access
│   │   ├── schema.sql
│   │   ├── batch_repository.go
│   │   └── vulnerability_repository.go
│   ├── handler/                 # HTTP handlers
│   │   └── scan_handler.go
│   ├── middleware/              # HTTP middleware
│   └── models/                  # Data models
└── examples/                    # Example code
```

### Running Tests

```bash
# Unit tests
go test ./internal/... -v

# Integration tests (requires database)
export DATABASE_URL="postgresql://localhost/napscan_test"
go test ./internal/repository -v

# Coverage
go test ./internal/... -cover
```

### Code Generation

```bash
# Generate swagger docs
swag init -g cmd/server/main.go

# Generate mocks (if using mockgen)
mockgen -source=internal/scanner/interface.go -destination=internal/mocks/scanner_mock.go
```

## 🚢 Production Deployment

### Docker Deployment

```dockerfile
# Dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN go build -o napscan ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates nmap
COPY --from=builder /app/napscan /napscan
EXPOSE 8080
CMD ["/napscan"]
```

```yaml
# docker-compose.yml
version: "3.8"
services:
  db:
    image: postgres:13
    environment:
      POSTGRES_DB: napscan
      POSTGRES_USER: napscan
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backend/internal/repository/schema.sql:/docker-entrypoint-initdb.d/schema.sql

  api:
    build: ./backend
    ports:
      - "8080:8080"
    environment:
      DATABASE_URL: postgresql://napscan:${DB_PASSWORD}@db:5432/napscan
      JWT_SECRET: ${JWT_SECRET}
    depends_on:
      - db
    volumes:
      - /usr/bin/nmap:/usr/bin/nmap

volumes:
  postgres_data:
```

### Environment Variables

```bash
# Required
DATABASE_URL=postgresql://user:pass@host:5432/napscan
JWT_SECRET=your-secret-key

# Optional
PORT=8080
MAX_WORKERS=10
DB_MAX_OPEN_CONNS=25
DB_MAX_IDLE_CONNS=5
CORS_ORIGINS=*
LOG_LEVEL=info
```

### Monitoring

```bash
# Prometheus metrics endpoint
GET /metrics

# Key metrics
- napscan_scans_total{status="completed|failed"}
- napscan_scan_duration_seconds{tool="nmap"}
- napscan_vulnerabilities_total{severity="critical|high|medium|low|info"}
```

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Adding New Scanner

1. Implement `scanner.Scanner` interface
2. Add normalization logic
3. Add tests
4. Update documentation
5. Register in `cmd/server/main.go`

See [ARCHITECTURE.md](ARCHITECTURE.md) for design guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) file

## 🙏 Acknowledgments

- Built with [Fiber](https://gofiber.io/) web framework
- Uses security tools: Nmap, Nuclei, SSLyze, FFUF, OWASP ZAP, OpenVAS
- PostgreSQL for data persistence

## 📞 Support

- 📖 Documentation: See `/docs` folder
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/napscan/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/yourusername/napscan/discussions)

---

**Built with ❤️ for the security community**
