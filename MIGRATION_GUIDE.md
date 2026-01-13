# Migration & Integration Guide

## Overview

This guide helps you migrate from your current implementation to the new production-grade architecture.

## Current vs New Architecture

### Current Implementation ❌

```
✗ In-memory batch storage (sync.Map)
✗ No database persistence
✗ Hardcoded scanner execution
✗ No parallel execution control
✗ Simple aggregation without normalization
✗ No deduplication
✗ No proper error isolation
```

### New Implementation ✅

```
✓ PostgreSQL database with full schema
✓ Scanner interface for modularity
✓ Worker pool for parallel execution
✓ Unified vulnerability schema
✓ Sophisticated report aggregation
✓ Fingerprint-based deduplication
✓ Fault-tolerant execution
✓ RESTful API with proper status codes
```

---

## Migration Strategy

### Phase 1: Database Setup (Day 1) 🗄️

#### Step 1.1: Install PostgreSQL

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib

# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### Step 1.2: Create Database

```bash
# Switch to postgres user
sudo -u postgres psql

# Create database and user
CREATE DATABASE napscan;
CREATE USER napscan_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE napscan TO napscan_user;
\q
```

#### Step 1.3: Run Schema

```bash
psql -U napscan_user -d napscan -f backend/internal/repository/schema.sql
```

#### Step 1.4: Verify Tables

```bash
psql -U napscan_user -d napscan

\dt  # List all tables
# Should show: batches, scan_jobs, vulnerabilities, batch_reports, etc.

\d batches  # Describe batches table
\q
```

#### Step 1.5: Add Database Driver to go.mod

```bash
cd backend
go get github.com/lib/pq
```

#### Step 1.6: Update .env

```bash
cat >> .env << EOF
DATABASE_URL=postgresql://napscan_user:secure_password@localhost:5432/napscan?sslmode=disable
EOF
```

---

### Phase 2: Integrate Repositories (Day 2) 🔌

#### Step 2.1: Initialize Database Connection

Update `cmd/server/main.go`:

```go
import (
    "database/sql"
    _ "github.com/lib/pq"
)

func main() {
    // Load env
    godotenv.Load()

    // Connect to database
    db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Test connection
    if err := db.Ping(); err != nil {
        log.Fatal(err)
    }

    log.Println("✅ Database connected")

    // Continue with app setup...
}
```

#### Step 2.2: Replace BatchService

**OLD** (`internal/service/batch_service.go`):

```go
type BatchService struct {
    batches  sync.Map  // In-memory storage
    analyzer *ReportAnalyzer
}
```

**NEW** - Use repositories:

```go
import (
    "napscan-be/internal/repository"
    "napscan-be/internal/orchestrator"
)

// Initialize in main.go
batchRepo := repository.NewBatchRepository(db)
vulnRepo := repository.NewVulnerabilityRepository(db)

// Use orchestrator instead of BatchService
registry := scanner.NewRegistry()
orch := orchestrator.NewBatchOrchestrator(registry, batchRepo, vulnRepo)
```

#### Step 2.3: Update Handlers

**OLD** Handler:

```go
func (h *BatchHandler) HandleScanPartA(c *fiber.Ctx) error {
    batchService.AddResult(userID, batchID, "api_a", data)
    // ...
}
```

**NEW** Handler:

```go
// Use new ScanHandler with orchestrator
scanHandler := handler.NewScanHandler(db, registry)

app.Post("/api/scans", scanHandler.CreateScan)
app.Get("/api/scans/:batchId", scanHandler.GetBatchStatus)
app.Get("/api/scans/:batchId/report", scanHandler.GetBatchReport)
```

---

### Phase 3: Implement Scanner Interface (Day 3-4) 🔧

#### Step 3.1: Wrap Existing Nmap Service

**OLD** (`internal/service/nmap_service.go`):

```go
type NmapService struct{}

func (s *NmapService) ExecuteScan(target string, scanType string) (models.NmapRun, error) {
    // Implementation
}
```

**NEW** - Implement Scanner Interface:

```go
// Already created: internal/scanners/nmap_scanner.go

type NmapScanner struct{}

func (s *NmapScanner) Name() string { return "nmap" }

func (s *NmapScanner) Execute(ctx context.Context, config scanner.ScanConfig) (interface{}, error) {
    // Use existing NmapService logic here
}

func (s *NmapScanner) Normalize(rawResult interface{}) ([]scanner.Vulnerability, error) {
    // Convert NmapRun to []Vulnerability
}

func (s *NmapScanner) Validate() error {
    // Check if nmap is available
}
```

#### Step 3.2: Wrap Other Services

Repeat for each scanner:

- ✅ Nmap (already done)
- ✅ Nuclei (already done)
- ⏳ SSLyze (TODO)
- ⏳ FFUF (TODO)
- ⏳ ZAP (TODO)
- ⏳ OpenVAS (TODO)

Template for wrapping:

```go
package scanners

import (
    "context"
    "napscan-be/internal/scanner"
    "napscan-be/internal/service" // Your old service
)

type MyToolScanner struct {
    service *service.MyToolService // Wrap existing service
}

func NewMyToolScanner() *MyToolScanner {
    return &MyToolScanner{
        service: service.NewMyToolService(),
    }
}

func (s *MyToolScanner) Name() string {
    return "mytool"
}

func (s *MyToolScanner) Execute(ctx context.Context, config scanner.ScanConfig) (interface{}, error) {
    // Call your existing service
    return s.service.ExecuteScan(config.Target)
}

func (s *MyToolScanner) Normalize(rawResult interface{}) ([]scanner.Vulnerability, error) {
    // Convert tool-specific output to Vulnerability structs
    // This is the new part you need to implement
}

func (s *MyToolScanner) Validate() error {
    // Check if tool is available
    cmd := exec.Command("mytool", "--version")
    return cmd.Run()
}
```

#### Step 3.3: Register All Scanners

In `cmd/server/main.go`:

```go
registry := scanner.NewRegistry()

// Register all scanners
registry.MustRegister(scanners.NewNmapScanner())
registry.MustRegister(scanners.NewNucleiScanner())
registry.MustRegister(scanners.NewSSLyzeScanner())
registry.MustRegister(scanners.NewFfufScanner())
registry.MustRegister(scanners.NewZAPScanner())
registry.MustRegister(scanners.NewOpenVASScanner())

// Validate
errors := registry.ValidateAll()
for name, err := range errors {
    log.Printf("⚠️  Scanner %s unavailable: %v", name, err)
}
```

---

### Phase 4: Update API Routes (Day 5) 🛣️

#### Step 4.1: Remove Old Routes

**REMOVE** these old batch endpoints:

```go
// OLD - Remove these
app.Post("/a", batchHandler.HandleScanPartA)
app.Post("/b", batchHandler.HandleScanPartB)
app.Post("/c", batchHandler.HandleScanPartC)
app.Post("/d", batchHandler.HandleScanPartD)
app.Post("/e", batchHandler.HandleScanPartE)
app.Get("/result/:batchID", batchHandler.GetResult)
```

#### Step 4.2: Add New Routes

```go
// NEW - Add these
scanHandler := handler.NewScanHandler(db, registry)

api := app.Group("/api", middleware.AuthMiddleware())

// Scan management
api.Post("/scans", scanHandler.CreateScan)
api.Get("/scans", scanHandler.ListBatches)
api.Get("/scans/:batchId", scanHandler.GetBatchStatus)
api.Get("/scans/:batchId/report", scanHandler.GetBatchReport)

// Scanner info
api.Get("/scanners", func(c *fiber.Ctx) error {
    return c.JSON(fiber.Map{
        "scanners": registry.List(),
    })
})
```

#### Step 4.3: Update Frontend API Calls

**OLD** Frontend:

```javascript
// Multiple separate calls
await fetch("/a", { method: "POST", body: dataA });
await fetch("/b", { method: "POST", body: dataB });
await fetch("/c", { method: "POST", body: dataC });
// ... wait for all to complete
const result = await fetch(`/result/${batchId}`);
```

**NEW** Frontend:

```javascript
// Single call to start scan
const response = await fetch("/api/scans", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    target: "192.168.1.1",
    scan_type: "all", // or 'single', 'custom'
    timeout: 20,
  }),
});

const { batch_id } = await response.json();

// Poll for status
const checkStatus = setInterval(async () => {
  const status = await fetch(`/api/scans/${batch_id}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = await status.json();

  if (data.status === "completed") {
    clearInterval(checkStatus);

    // Get full report
    const report = await fetch(`/api/scans/${batch_id}/report`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const reportData = await report.json();

    displayReport(reportData);
  }
}, 5000);
```

---

### Phase 5: Testing & Validation (Day 6-7) ✅

#### Step 5.1: Unit Tests

Create `internal/orchestrator/batch_orchestrator_test.go`:

```go
package orchestrator

import (
    "testing"
    "context"
    "napscan-be/internal/scanner"
)

type mockScanner struct{}

func (m *mockScanner) Name() string { return "mock" }
func (m *mockScanner) Execute(ctx context.Context, config scanner.ScanConfig) (interface{}, error) {
    return map[string]string{"result": "success"}, nil
}
func (m *mockScanner) Normalize(raw interface{}) ([]scanner.Vulnerability, error) {
    return []scanner.Vulnerability{}, nil
}
func (m *mockScanner) Validate() error { return nil }

func TestBatchOrchestrator(t *testing.T) {
    // Setup
    registry := scanner.NewRegistry()
    registry.Register(&mockScanner{})

    // Test batch execution
    // ...
}
```

#### Step 5.2: Integration Tests

```bash
# Test database connection
go test ./internal/repository -v

# Test orchestrator
go test ./internal/orchestrator -v

# Test handlers (requires test database)
go test ./internal/handler -v
```

#### Step 5.3: Manual API Testing

```bash
# 1. Start server
go run cmd/server/main.go

# 2. Health check
curl http://localhost:8080/health

# 3. Login
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"pass"}' | jq -r '.token')

# 4. Create scan
BATCH_ID=$(curl -s -X POST http://localhost:8080/api/scans \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"target":"scanme.nmap.org","scan_type":"single","tool_names":["nmap"]}' \
    | jq -r '.batch_id')

# 5. Check status
curl -s http://localhost:8080/api/scans/$BATCH_ID \
    -H "Authorization: Bearer $TOKEN" | jq

# 6. Get report (after completion)
curl -s http://localhost:8080/api/scans/$BATCH_ID/report \
    -H "Authorization: Bearer $TOKEN" | jq
```

---

## Rollback Plan 🔄

If migration fails, you can quickly rollback:

### Rollback Steps

1. Switch git branch back to old version
2. Restore old environment variables
3. Remove database changes (optional)
4. Restart server

```bash
# Rollback commands
git checkout main  # or your stable branch
cp .env.backup .env
sudo systemctl restart napscan
```

### Keep Old Code Running During Migration

Run both versions simultaneously:

```bash
# Old version on port 8080
cd old-backend && go run main.go

# New version on port 8081
cd new-backend && PORT=8081 go run cmd/server/main.go
```

Use nginx to route gradually:

```nginx
upstream napscan {
    server localhost:8080 weight=9;  # 90% to old
    server localhost:8081 weight=1;  # 10% to new
}
```

---

## Common Issues & Solutions 🔧

### Issue 1: Database Connection Failed

```
Error: failed to connect to database
```

**Solution:**

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Check credentials
psql -U napscan_user -d napscan
# If fails, reset password:
sudo -u postgres psql
ALTER USER napscan_user WITH PASSWORD 'new_password';
```

### Issue 2: Scanner Not Found

```
Error: nmap not found or not executable
```

**Solution:**

```bash
# Install missing tools
sudo apt-get install nmap

# Check PATH
which nmap

# If not in PATH, use full path in scanner
cmd := exec.Command("/usr/bin/nmap", args...)
```

### Issue 3: Migration Too Slow

```
Batch takes too long to complete
```

**Solution:**

```bash
# Increase worker pool size
export MAX_WORKERS=20

# Increase database connections
export DB_MAX_OPEN_CONNS=50

# Add indexes (if missing)
CREATE INDEX CONCURRENTLY idx_batch_user ON batches(user_id);
```

### Issue 4: Out of Memory

```
Error: runtime: out of memory
```

**Solution:**

```bash
# Limit concurrent scans
export MAX_WORKERS=5

# Add pagination to report generation
# Limit vulnerabilities returned per page
```

---

## Performance Tuning 🚀

### Database Optimization

```sql
-- Enable query logging for slow queries
ALTER DATABASE napscan SET log_min_duration_statement = 1000;

-- Analyze tables for better query plans
ANALYZE batches;
ANALYZE scan_jobs;
ANALYZE vulnerabilities;

-- Create additional indexes if needed
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity, created_at DESC);
CREATE INDEX idx_jobs_tool ON scan_jobs(tool_name, status);
```

### Application Optimization

```go
// Increase worker pool for more parallelism
orch := orchestrator.NewBatchOrchestrator(registry, batchRepo, vulnRepo)
orch.SetMaxWorkers(20)  // Add this method

// Add caching for scanner validation
type CachedRegistry struct {
    *DefaultRegistry
    validationCache map[string]error
    cacheTTL        time.Duration
}

// Use connection pooling
db.SetMaxOpenConns(50)
db.SetMaxIdleConns(10)
db.SetConnMaxLifetime(time.Hour)
```

---

## Monitoring Setup 📊

### Add Prometheus Metrics

```go
import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    scansTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "napscan_scans_total",
            Help: "Total number of scans",
        },
        []string{"status"},
    )

    scanDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "napscan_scan_duration_seconds",
            Help: "Scan duration in seconds",
        },
        []string{"tool"},
    )
)

func init() {
    prometheus.MustRegister(scansTotal)
    prometheus.MustRegister(scanDuration)
}

// In handler
app.Get("/metrics", adaptor.HTTPHandler(promhttp.Handler()))
```

### Add Logging

```go
import "github.com/sirupsen/logrus"

log := logrus.New()
log.SetFormatter(&logrus.JSONFormatter{})
log.SetLevel(logrus.InfoLevel)

// In orchestrator
log.WithFields(logrus.Fields{
    "batch_id": batchID,
    "user_id": userID,
    "tools": toolNames,
}).Info("Starting batch scan")
```

---

## Checklist Before Going Live ✓

- [ ] Database schema deployed
- [ ] All scanners implemented and registered
- [ ] Environment variables configured
- [ ] Security scanners installed and validated
- [ ] Database backups configured
- [ ] Monitoring and logging setup
- [ ] API documentation updated
- [ ] Frontend updated to use new endpoints
- [ ] Load testing completed
- [ ] Rollback plan documented
- [ ] Team trained on new system
- [ ] Error handling tested
- [ ] Rate limiting configured
- [ ] HTTPS/TLS enabled
- [ ] Authentication working
- [ ] Authorization tested

---

## Support & Troubleshooting 💬

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=debug
go run cmd/server/main.go
```

### Database Queries for Debugging

```sql
-- Check batch status
SELECT batch_id, status, expected_job_count, completed_job_count
FROM batches
ORDER BY created_at DESC
LIMIT 10;

-- Check failed jobs
SELECT b.batch_id, sj.tool_name, sj.error_message
FROM scan_jobs sj
JOIN batches b ON sj.batch_id = b.id
WHERE sj.status = 'failed'
ORDER BY sj.created_at DESC;

-- Vulnerability summary
SELECT source_tool, severity, COUNT(*)
FROM vulnerabilities
WHERE is_duplicate = FALSE
GROUP BY source_tool, severity;
```

### Common Log Messages

```
✅ "Scan created: abc-123" - Normal
✅ "Job completed: nmap" - Normal
⚠️  "Scanner validation failed: sslyze" - Warning, tool not available
❌ "Database connection failed" - Critical, check DB
❌ "Context deadline exceeded" - Timeout, increase limit
```

---

This migration guide provides a structured approach to transitioning to the production architecture while minimizing risk and downtime.
