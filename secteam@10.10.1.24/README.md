# NapScan Backend

Backend API untuk NapScan - Security Scanning & Analysis Platform

## Features

### 🔐 Authentication

- JWT-based authentication
- User registration and login
- Protected routes with middleware

### 🔍 Security Scanners

- **Nmap**: Network scanning (TCP/UDP)
- **Nuclei**: Vulnerability scanning
- **ZAP**: Web application security testing
- **SSLyze**: SSL/TLS configuration analysis
- **OpenVAS**: Comprehensive vulnerability assessment
- **MobSF**: Mobile security framework
- **FFuf**: Web fuzzing

### 📊 Batch Analysis & Reporting

**NEW!** Sistem analisis batch yang dapat:

- Menerima hasil scan dari multiple sources
- Menganalisis hasil Nmap secara otomatis
- Generate comprehensive security report
- Risk assessment & scoring
- Vulnerability detection
- Security recommendations

[📖 Batch Analysis Documentation](docs/BATCH_ANALYSIS.md)

## Quick Start

### 1. Set Environment Variables

Create `.env` file:

```bash
PORT=8080
JWT_SECRET=your-secret-key-here
```

Or export directly:

```bash
export PORT=8080
export JWT_SECRET=your-secret-key-here
```

### 2. Install Dependencies

```bash
go mod download
```

### 3. Run Server

```bash
# Development
go run cmd/server/main.go

# Production build
go build -o napscan cmd/server/main.go
./napscan
```

## API Endpoints

### Health Check

- `GET /health` - Server health status
- `GET /health/test` - Detailed health test

### Authentication

- `POST /auth/register` - Register new user
- `POST /auth/login` - User login

### Scanners

- `POST /api/nmap/scan` - Run Nmap scan
- `POST /api/nuclei/scan` - Run Nuclei scan
- `POST /api/zap/scan` - Run ZAP scan
- `POST /api/sslyze/scan` - Run SSLyze scan
- `POST /api/openvas/scan` - Run OpenVAS scan
- `POST /api/mobsf/upload` - Upload APK for analysis
- `POST /api/ffuf/scan` - Run FFuf fuzzing

### Batch Analysis 🆕

- `POST /api/batch/nmap` - Submit Nmap results for analysis
- `POST /api/a` - Submit scan part A
- `POST /api/b` - Submit scan part B
- `POST /api/c` - Submit scan part C
- `POST /api/d` - Submit scan part D
- `POST /api/e` - Submit scan part E
- `GET /api/analysis/{batch_id}` - Get analysis status
- `GET /api/report/{batch_id}` - Get security report

## Usage Example

### Complete Scan & Analysis Workflow

```bash
# 1. Login
TOKEN=$(curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}' \
  | jq -r '.token')

# 2. Run Nmap Scan
BATCH_ID="scan-$(date +%s)"
NMAP_RESULTS=$(curl -X POST http://localhost:8080/api/nmap/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}')

# 3. Submit for Analysis
curl -X POST http://localhost:8080/api/batch/nmap \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Batch-ID: $BATCH_ID" \
  -H "Content-Type: application/json" \
  -d "$NMAP_RESULTS"

# 4. Get Security Report
curl -X GET http://localhost:8080/api/report/$BATCH_ID \
  -H "Authorization: Bearer $TOKEN" | jq '.'
```

### Test Script

```bash
./scripts/test_batch_analysis.sh
```

## Security Report Features

The generated report includes:

### 📈 Summary

- Total hosts scanned
- Total open ports
- Service count
- Risk breakdown (High/Medium/Low)

### 🌐 Network Analysis

- Host details with risk levels
- Port analysis with risk assessment
- Service inventory

### 🚨 Vulnerabilities

- Identified vulnerabilities
- Severity ratings
- Affected ports/services
- CVE information (when available)

### 💡 Recommendations

- Prioritized security recommendations
- Remediation steps
- Best practices

### 🎯 Risk Score

- Overall risk score (0-100)
- Based on:
  - High risk ports (+15 each)
  - Medium risk ports (+5 each)
  - Vulnerabilities (severity-based)

## Example Report

See [example_report.json](docs/example_report.json) for a complete example.

```json
{
  "summary": {
    "total_hosts": 1,
    "total_open_ports": 8,
    "high_risk_ports": 3,
    "medium_risk_ports": 3,
    "low_risk_ports": 2
  },
  "risk_score": 75,
  "vulnerabilities": [...],
  "recommendations": [...]
}
```

## Development

### Project Structure

```
backend/
├── cmd/
│   └── server/         # Main application
├── internal/
│   ├── handler/        # HTTP handlers
│   ├── service/        # Business logic
│   ├── models/         # Data models
│   ├── middleware/     # Auth, CORS, etc.
│   └── routes/         # Route definitions
├── pkg/
│   └── response/       # Response helpers
├── docs/               # Documentation
└── scripts/            # Utility scripts
```

### Adding New Scanner

1. Create handler in `internal/handler/`
2. Create service in `internal/service/`
3. Add models in `internal/models/`
4. Register routes in `internal/routes/`
5. Update `report_analyzer.go` for analysis integration

## Docker Support

```bash
# Build
docker build -t napscan-backend .

# Run
docker run -p 8080:8080 napscan-backend
```

Or use docker-compose from root:

```bash
docker-compose up backend
```

## Testing

```bash
# Run tests
go test ./...

# With coverage
go test -cover ./...

# Specific package
go test ./internal/service/...
```

## Documentation

- [Batch Analysis Guide](docs/BATCH_ANALYSIS.md)
- [API Documentation](docs/swagger.json) - Swagger/OpenAPI
- [Example Report](docs/example_report.json)

## Swagger/OpenAPI

Access Swagger UI at: `http://localhost:8080/swagger/index.html`

Generate/update swagger docs:

```bash
swag init -g cmd/server/main.go
```

## Dependencies

- **Fiber** - Web framework
- **JWT-Go** - Authentication
- **Swaggo** - API documentation
- **Nmap** - Network scanning (must be installed on system)

## Environment Requirements

### System Tools Required

- `nmap` - For network scanning
- `nuclei` - For vulnerability scanning (optional)
- Other scanner tools as needed

Install on Ubuntu/Debian:

```bash
sudo apt-get install nmap
```

## License

MIT

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request
