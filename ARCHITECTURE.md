# NapScan - Production-Grade Vulnerability Scanning Backend

## Architecture Overview

NapScan is a modular, extensible vulnerability scanning system that integrates multiple security tools into a unified platform.

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        API Layer (Fiber)                         │
├─────────────────────────────────────────────────────────────────┤
│                     Batch Orchestrator                           │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                │
│  │ Worker Pool │  │ Job Queue  │  │ Scheduler  │                │
│  └────────────┘  └────────────┘  └────────────┘                │
├─────────────────────────────────────────────────────────────────┤
│                    Scanner Registry                              │
│  ┌──────┐ ┌────────┐ ┌──────┐ ┌────────┐ ┌────────┐           │
│  │ Nmap │ │ Nuclei │ │ FFUF │ │ SSLyze │ │  ZAP   │ ...       │
│  └──────┘ └────────┘ └──────┘ └────────┘ └────────┘           │
├─────────────────────────────────────────────────────────────────┤
│                   Report Aggregator                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                │
│  │ Normalizer │  │ Deduplicator│  │  Analyzer  │                │
│  └────────────┘  └────────────┘  └────────────┘                │
├─────────────────────────────────────────────────────────────────┤
│                   Repository Layer                               │
│  ┌──────────────┐  ┌──────────────────┐                         │
│  │ Batch Repo   │  │ Vulnerability Repo│                         │
│  └──────────────┘  └──────────────────┘                         │
├─────────────────────────────────────────────────────────────────┤
│                      PostgreSQL Database                         │
│  ┌─────────┐ ┌──────────┐ ┌────────────────┐ ┌──────────┐     │
│  │ Batches │ │ ScanJobs │ │ Vulnerabilities │ │ Reports  │     │
│  └─────────┘ └──────────┘ └────────────────┘ └──────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
backend/
├── cmd/
│   └── server/
│       └── main.go                 # Application entry point
├── internal/
│   ├── scanner/                    # Scanner interface & registry
│   │   ├── interface.go           # Core scanner interface
│   │   └── registry.go            # Scanner registry implementation
│   ├── scanners/                   # Scanner implementations
│   │   ├── nmap_scanner.go
│   │   ├── nuclei_scanner.go
│   │   ├── sslyze_scanner.go
│   │   ├── ffuf_scanner.go
│   │   ├── zap_scanner.go
│   │   └── openvas_scanner.go
│   ├── orchestrator/               # Batch execution orchestrator
│   │   └── batch_orchestrator.go  # Parallel scan execution
│   ├── aggregator/                 # Report generation
│   │   └── report_aggregator.go   # Unified report builder
│   ├── repository/                 # Database layer
│   │   ├── schema.sql             # Database schema
│   │   ├── batch_repository.go    # Batch operations
│   │   └── vulnerability_repository.go
│   ├── handler/                    # HTTP handlers
│   │   └── scan_handler.go        # REST API endpoints
│   ├── service/                    # Business logic (legacy)
│   └── models/                     # Data models
└── pkg/
    └── response/                   # API responses
```

## Key Features

### 1. Modular Scanner Interface

All scanners implement a common interface:

```go
type Scanner interface {
    Name() string
    Execute(ctx context.Context, config ScanConfig) (interface{}, error)
    Normalize(rawResult interface{}) ([]Vulnerability, error)
    Validate() error
}
```

### 2. Parallel Execution

- Worker pool pattern for concurrent scans
- Configurable max workers (default: 10)
- Context-based cancellation
- Individual tool failures don't cancel batch

### 3. Unified Vulnerability Schema

```go
type Vulnerability struct {
    ID              string
    Title           string
    Severity        Severity  // info, low, medium, high, critical
    Description     string
    AffectedAsset   []string
    SourceTool      string
    Evidence        string
    Remediation     string
    CVE             string
    CWE             string
    CVSS            float64
    Metadata        map[string]interface{}
}
```

### 4. Database Schema

**Key Tables:**

- `batches` - Scan batch tracking
- `scan_jobs` - Individual scanner executions
- `vulnerabilities` - Normalized findings
- `batch_reports` - Aggregated reports
- `audit_log` - Compliance trail

### 5. Three Scan Modes

**All Scanners:**

```bash
curl -X POST /api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"scan_type": "all", "target": "192.168.1.1"}'
```

**Single Scanner:**

```bash
curl -X POST /api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"scan_type": "single", "tool_names": ["nmap"], "target": "example.com"}'
```

**Custom Selection:**

```bash
curl -X POST /api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"scan_type": "custom", "tool_names": ["nmap", "nuclei", "sslyze"], "target": "example.com"}'
```

## Setup Instructions

### 1. Database Setup

```bash
# Create PostgreSQL database
createdb napscan

# Run schema
psql napscan < internal/repository/schema.sql
```

### 2. Environment Configuration

```bash
# .env
DATABASE_URL=postgresql://user:pass@localhost:5432/napscan
JWT_SECRET=your-secret-key
PORT=8080
MAX_WORKERS=10
DEFAULT_TIMEOUT=10m
```

### 3. Install Security Tools

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y nmap

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# FFUF
go install github.com/ffuf/ffuf@latest

# SSLyze
pip install sslyze

# OWASP ZAP (requires Java)
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz
tar -xvf ZAP_2.14.0_Linux.tar.gz
```

### 4. Build and Run

```bash
# Build
go build -o napscan ./cmd/server

# Run
./napscan
```

## Example Usage

### Initialize System

```go
package main

import (
    "database/sql"
    "log"

    "napscan-be/internal/scanner"
    "napscan-be/internal/scanners"
    "napscan-be/internal/orchestrator"
    "napscan-be/internal/aggregator"
    "napscan-be/internal/repository"

    _ "github.com/lib/pq"
)

func main() {
    // Connect to database
    db, err := sql.Open("postgres", "postgresql://localhost/napscan")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Initialize repositories
    batchRepo := repository.NewBatchRepository(db)
    vulnRepo := repository.NewVulnerabilityRepository(db)

    // Create scanner registry
    registry := scanner.NewRegistry()

    // Register all scanners
    registry.MustRegister(scanners.NewNmapScanner())
    registry.MustRegister(scanners.NewNucleiScanner())
    registry.MustRegister(scanners.NewSSLyzeScanner())
    registry.MustRegister(scanners.NewFfufScanner())
    registry.MustRegister(scanners.NewZAPScanner())
    registry.MustRegister(scanners.NewOpenVASScanner())

    // Validate scanners
    errors := registry.ValidateAll()
    for name, err := range errors {
        log.Printf("WARNING: Scanner %s validation failed: %v", name, err)
    }

    // Create orchestrator
    orch := orchestrator.NewBatchOrchestrator(registry, batchRepo, vulnRepo)

    // Create report aggregator
    agg := aggregator.NewReportAggregator(batchRepo, vulnRepo)

    // Ready to handle requests
    log.Println("NapScan initialized successfully")
}
```

### Execute Batch Scan

```go
// Execute a batch scan
req := &orchestrator.BatchRequest{
    UserID:   "user123",
    BatchID:  "batch-" + uuid.NewString(),
    Target:   "192.168.1.100",
    ScanType: orchestrator.ScanTypeAll,
    Timeout:  15 * time.Minute,
    Options: map[string]interface{}{
        "nmap": map[string]interface{}{
            "ports": "1-1000",
        },
        "nuclei": map[string]interface{}{
            "severity": "high,critical",
        },
    },
}

result, err := orch.ExecuteBatch(context.Background(), req)
if err != nil {
    log.Printf("Batch execution failed: %v", err)
    return
}

log.Printf("Batch %s completed: %d vulnerabilities found",
    result.BatchID, result.TotalVulns)
```

### Generate Report

```go
// Generate comprehensive report
report, err := agg.GenerateReport(
    context.Background(),
    batchID,
    userID,
)

if err != nil {
    log.Printf("Report generation failed: %v", err)
    return
}

// Access report data
fmt.Printf("Risk Level: %s\n", report.RiskAssessment.RiskLevel)
fmt.Printf("Critical Vulns: %d\n", report.VulnerabilityStats.Critical)
fmt.Printf("High Vulns: %d\n", report.VulnerabilityStats.High)

// Print top recommendations
for i, rec := range report.Recommendations {
    fmt.Printf("%d. %s\n", i+1, rec)
}
```

## Adding New Scanners

### 1. Implement Scanner Interface

```go
package scanners

import (
    "context"
    "napscan-be/internal/scanner"
)

type MyCustomScanner struct{}

func NewMyCustomScanner() *MyCustomScanner {
    return &MyCustomScanner{}
}

func (s *MyCustomScanner) Name() string {
    return "mycustom"
}

func (s *MyCustomScanner) Execute(ctx context.Context, config scanner.ScanConfig) (interface{}, error) {
    // Execute your tool
    // Return raw results
}

func (s *MyCustomScanner) Normalize(rawResult interface{}) ([]scanner.Vulnerability, error) {
    // Convert tool output to Vulnerability structs
}

func (s *MyCustomScanner) Validate() error {
    // Check if tool is available
}
```

### 2. Register Scanner

```go
registry.MustRegister(scanners.NewMyCustomScanner())
```

That's it! The scanner is now integrated into the system.

## Performance Considerations

### Database Indexing

Key indexes are automatically created:

- Batch lookups by user_id and status
- Vulnerability queries by batch_id and severity
- Job tracking by batch_id and status

### Parallel Execution

- Default: 10 concurrent workers
- Adjustable via MAX_WORKERS env var
- Each worker handles one scanner at a time
- Prevents resource exhaustion

### Result Storage

- Raw results stored as JSONB in database
- Supports efficient querying
- Normalized vulnerabilities indexed separately
- Deduplication via fingerprinting

## Security Best Practices

1. **Authentication**: All endpoints require JWT tokens
2. **Authorization**: Users can only access their own batches
3. **Input Validation**: Targets and options are validated
4. **Rate Limiting**: Implement per-user scan limits
5. **Audit Logging**: All actions logged to audit_log table
6. **Tool Isolation**: Scanners run in isolated contexts with timeouts

## Monitoring & Observability

### Metrics to Track

- Scan completion rate
- Average scan duration per tool
- Vulnerability discovery rate
- Tool failure rate
- Database query performance

### Logging

All components log to structured output:

```
[INFO] Batch abc123 created for user user456
[INFO] Starting scan with nmap for target 192.168.1.1
[WARN] Scanner sslyze failed: connection timeout
[INFO] Batch abc123 completed: 15 vulns found
```

## Compliance & Reporting

The system supports compliance requirements:

- **PCI DSS**: Quarterly vulnerability scans
- **HIPAA**: Security risk assessments
- **SOC 2**: Continuous monitoring
- **ISO 27001**: Security testing evidence

Reports include:

- Executive summary with risk scores
- Detailed vulnerability listings
- Tool coverage and success rates
- Compliance impact assessment
- Actionable remediation priorities

## License

MIT License - See LICENSE file for details
