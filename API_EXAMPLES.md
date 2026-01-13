# NapScan API Usage Examples

## Authentication

### Register a new user

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "security_admin",
    "password": "SecurePass123!",
    "email": "admin@example.com"
  }'
```

### Login

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "security_admin",
    "password": "SecurePass123!"
  }'
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user_id": "user123",
  "expires_at": "2026-01-14T10:30:00Z"
}
```

Save the token for subsequent requests:

```bash
export TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## Health Check

```bash
curl http://localhost:8080/health
```

Response:

```json
{
  "status": "healthy",
  "timestamp": "2026-01-13T10:00:00Z",
  "database": "connected",
  "available_tools": ["nmap", "nuclei", "sslyze"],
  "unavailable_tools": ["openvas"]
}
```

## Scanner Information

```bash
curl http://localhost:8080/api/scanners \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "scanners": [
    {
      "name": "nmap",
      "available": true
    },
    {
      "name": "nuclei",
      "available": true
    },
    {
      "name": "openvas",
      "available": false,
      "error": "openvas not found or not executable"
    }
  ],
  "total": 6
}
```

## Scan Operations

### 1. Run All Scanners

```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.100",
    "scan_type": "all",
    "timeout": 20
  }'
```

Response:

```json
{
  "batch_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "processing",
  "message": "Scan batch created successfully. Use the batch_id to check progress.",
  "created_at": "2026-01-13T10:05:00Z"
}
```

### 2. Run Single Scanner

```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scan_type": "single",
    "tool_names": ["nmap"],
    "timeout": 10,
    "options": {
      "ports": "1-1000",
      "scan_type": "-sV"
    }
  }'
```

### 3. Run Custom Scanner Selection

```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "scan_type": "custom",
    "tool_names": ["nuclei", "sslyze", "zap"],
    "timeout": 30,
    "options": {
      "nuclei": {
        "severity": "high,critical",
        "templates": "cves/"
      },
      "sslyze": {
        "scan_type": "full"
      }
    }
  }'
```

### 4. Check Scan Status

```bash
BATCH_ID="550e8400-e29b-41d4-a716-446655440000"

curl http://localhost:8080/api/scans/$BATCH_ID \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "batch_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "processing",
  "target": "192.168.1.100",
  "expected_jobs": 6,
  "completed_jobs": 4,
  "failed_jobs": 1,
  "created_at": "2026-01-13T10:05:00Z",
  "updated_at": "2026-01-13T10:15:00Z",
  "completed_at": null,
  "jobs": [
    {
      "tool_name": "nmap",
      "status": "success",
      "start_time": "2026-01-13T10:05:05Z",
      "end_time": "2026-01-13T10:07:30Z",
      "duration_ms": 145000,
      "error": null
    },
    {
      "tool_name": "nuclei",
      "status": "running",
      "start_time": "2026-01-13T10:05:05Z",
      "end_time": null,
      "duration_ms": 0,
      "error": null
    },
    {
      "tool_name": "sslyze",
      "status": "success",
      "start_time": "2026-01-13T10:05:05Z",
      "end_time": "2026-01-13T10:06:10Z",
      "duration_ms": 65000,
      "error": null
    },
    {
      "tool_name": "openvas",
      "status": "failed",
      "start_time": "2026-01-13T10:05:05Z",
      "end_time": "2026-01-13T10:05:06Z",
      "duration_ms": 1000,
      "error": "Scanner not found: openvas not found"
    }
  ]
}
```

### 5. Get Comprehensive Report

Wait for batch status to be "completed", then:

```bash
curl http://localhost:8080/api/scans/$BATCH_ID/report \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "batch_id": "550e8400-e29b-41d4-a716-446655440000",
  "generated_at": "2026-01-13T10:20:00Z",
  "summary": {
    "target": "192.168.1.100",
    "scan_duration": 900000000000,
    "total_tools": 6,
    "successful_tools": 5,
    "failed_tools": 1,
    "total_vulnerabilities": 15,
    "unique_vulnerabilities": 15
  },
  "vulnerability_stats": {
    "critical": 2,
    "high": 5,
    "medium": 6,
    "low": 2,
    "info": 0
  },
  "tool_coverage": {
    "tools_executed": [
      {
        "tool_name": "nmap",
        "status": "success",
        "duration": 145000000000,
        "vulnerabilities_found": 8
      },
      {
        "tool_name": "nuclei",
        "status": "success",
        "duration": 320000000000,
        "vulnerabilities_found": 3
      },
      {
        "tool_name": "sslyze",
        "status": "success",
        "duration": 65000000000,
        "vulnerabilities_found": 4
      }
    ],
    "tools_failed": [
      {
        "tool_name": "openvas",
        "status": "failed",
        "duration": 1000000000,
        "vulnerabilities_found": 0,
        "error_message": "Scanner not found"
      }
    ]
  },
  "vulnerabilities": [
    {
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "title": "High-risk service exposed: telnet",
      "severity": "high",
      "severity_score": 4,
      "description": "Telnet - Unencrypted remote access is exposed on 192.168.1.100:23",
      "affected_assets": ["192.168.1.100:23"],
      "source_tools": ["nmap"],
      "evidence": "Port 23/tcp is open, service: telnet",
      "remediation": "Review the necessity of telnet service exposure. Consider firewall rules or VPN access.",
      "cve": "",
      "cwe": "",
      "cvss": 0,
      "first_detected": "2026-01-13T10:07:30Z",
      "metadata": {
        "port": "23",
        "protocol": "tcp",
        "service": "telnet"
      }
    },
    {
      "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "title": "TLS 1.0 Enabled",
      "severity": "medium",
      "severity_score": 3,
      "description": "Server supports outdated TLS 1.0 protocol",
      "affected_assets": ["192.168.1.100:443"],
      "source_tools": ["sslyze"],
      "evidence": "TLS 1.0 is enabled on HTTPS service",
      "remediation": "Disable TLS 1.0 and enforce minimum TLS 1.2",
      "cve": "",
      "cwe": "CWE-327",
      "cvss": 5.3,
      "first_detected": "2026-01-13T10:06:10Z",
      "metadata": {}
    }
  ],
  "risk_assessment": {
    "overall_risk_score": 82,
    "risk_level": "high",
    "top_risks": [
      "2 critical vulnerabilities require immediate attention",
      "5 high-severity vulnerabilities found"
    ],
    "compliance_impact": "High compliance risk - immediate remediation required"
  },
  "recommendations": [
    "URGENT: Address all critical vulnerabilities within 24 hours",
    "Implement incident response procedures for critical findings",
    "High priority: Remediate high-severity vulnerabilities within 7 days",
    "Warning: 1 security tools failed to execute - verify tool configuration",
    "Schedule regular security scans (weekly recommended)",
    "Implement a vulnerability management program",
    "Conduct security awareness training for development team"
  ]
}
```

### 6. List All Batches

```bash
curl "http://localhost:8080/api/scans?limit=10&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "batches": [
    {
      "batch_id": "550e8400-e29b-41d4-a716-446655440000",
      "target": "192.168.1.100",
      "status": "completed",
      "expected_jobs": 6,
      "completed_jobs": 6,
      "failed_jobs": 1,
      "created_at": "2026-01-13T10:05:00Z",
      "completed_at": "2026-01-13T10:20:00Z"
    },
    {
      "batch_id": "a3bb189e-8bf9-3888-9912-ace4e6543002",
      "target": "example.com",
      "status": "processing",
      "expected_jobs": 1,
      "completed_jobs": 0,
      "failed_jobs": 0,
      "created_at": "2026-01-13T09:30:00Z",
      "completed_at": null
    }
  ],
  "limit": 10,
  "offset": 0,
  "count": 2
}
```

## Python Example

```python
import requests
import time
import json

BASE_URL = "http://localhost:8080"

class NapScanClient:
    def __init__(self, username, password):
        self.base_url = BASE_URL
        self.token = None
        self.login(username, password)

    def login(self, username, password):
        response = requests.post(
            f"{self.base_url}/api/auth/login",
            json={"username": username, "password": password}
        )
        response.raise_for_status()
        self.token = response.json()["token"]

    def headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def create_scan(self, target, scan_type="all", tool_names=None, options=None):
        payload = {
            "target": target,
            "scan_type": scan_type,
            "timeout": 20
        }

        if tool_names:
            payload["tool_names"] = tool_names
        if options:
            payload["options"] = options

        response = requests.post(
            f"{self.base_url}/api/scans",
            json=payload,
            headers=self.headers()
        )
        response.raise_for_status()
        return response.json()["batch_id"]

    def get_status(self, batch_id):
        response = requests.get(
            f"{self.base_url}/api/scans/{batch_id}",
            headers=self.headers()
        )
        response.raise_for_status()
        return response.json()

    def get_report(self, batch_id):
        response = requests.get(
            f"{self.base_url}/api/scans/{batch_id}/report",
            headers=self.headers()
        )
        response.raise_for_status()
        return response.json()

    def wait_for_completion(self, batch_id, interval=5, timeout=600):
        """Wait for scan to complete"""
        start_time = time.time()

        while time.time() - start_time < timeout:
            status = self.get_status(batch_id)

            if status["status"] == "completed":
                return True
            elif status["status"] == "failed":
                raise Exception("Batch scan failed")

            print(f"Status: {status['status']} - "
                  f"{status['completed_jobs']}/{status['expected_jobs']} jobs completed")

            time.sleep(interval)

        raise TimeoutError("Scan did not complete in time")

# Usage
client = NapScanClient("security_admin", "SecurePass123!")

# Create and run a comprehensive scan
batch_id = client.create_scan(
    target="192.168.1.100",
    scan_type="custom",
    tool_names=["nmap", "nuclei", "sslyze"],
    options={
        "nmap": {"ports": "1-1000"},
        "nuclei": {"severity": "high,critical"}
    }
)

print(f"Scan created: {batch_id}")

# Wait for completion
client.wait_for_completion(batch_id)

# Get comprehensive report
report = client.get_report(batch_id)

print(f"\n=== Scan Report ===")
print(f"Risk Level: {report['risk_assessment']['risk_level'].upper()}")
print(f"Risk Score: {report['risk_assessment']['overall_risk_score']}/100")
print(f"\nVulnerabilities:")
print(f"  Critical: {report['vulnerability_stats']['critical']}")
print(f"  High: {report['vulnerability_stats']['high']}")
print(f"  Medium: {report['vulnerability_stats']['medium']}")
print(f"  Low: {report['vulnerability_stats']['low']}")

print(f"\nTop Recommendations:")
for i, rec in enumerate(report['recommendations'][:3], 1):
    print(f"{i}. {rec}")

# Export to file
with open(f"scan_report_{batch_id}.json", "w") as f:
    json.dump(report, f, indent=2)

print(f"\nFull report saved to scan_report_{batch_id}.json")
```

## cURL Script for Complete Workflow

```bash
#!/bin/bash

# Configuration
API_URL="http://localhost:8080"
USERNAME="security_admin"
PASSWORD="SecurePass123!"
TARGET="192.168.1.100"

# Login
echo "🔐 Logging in..."
TOKEN_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.token')

if [ "$TOKEN" == "null" ]; then
  echo "❌ Login failed"
  exit 1
fi

echo "✅ Logged in successfully"

# Create scan
echo "🚀 Creating scan for $TARGET..."
SCAN_RESPONSE=$(curl -s -X POST "$API_URL/api/scans" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"target\":\"$TARGET\",\"scan_type\":\"all\",\"timeout\":20}")

BATCH_ID=$(echo $SCAN_RESPONSE | jq -r '.batch_id')

echo "✅ Scan created: $BATCH_ID"

# Poll for completion
echo "⏳ Waiting for scan to complete..."
while true; do
  STATUS_RESPONSE=$(curl -s "$API_URL/api/scans/$BATCH_ID" \
    -H "Authorization: Bearer $TOKEN")

  STATUS=$(echo $STATUS_RESPONSE | jq -r '.status')
  COMPLETED=$(echo $STATUS_RESPONSE | jq -r '.completed_jobs')
  TOTAL=$(echo $STATUS_RESPONSE | jq -r '.expected_jobs')

  echo "Status: $STATUS ($COMPLETED/$TOTAL jobs completed)"

  if [ "$STATUS" == "completed" ]; then
    break
  elif [ "$STATUS" == "failed" ]; then
    echo "❌ Scan failed"
    exit 1
  fi

  sleep 5
done

echo "✅ Scan completed!"

# Get report
echo "📊 Generating report..."
REPORT=$(curl -s "$API_URL/api/scans/$BATCH_ID/report" \
  -H "Authorization: Bearer $TOKEN")

# Display summary
echo ""
echo "=== SCAN REPORT ==="
echo "Target: $(echo $REPORT | jq -r '.summary.target')"
echo "Risk Level: $(echo $REPORT | jq -r '.risk_assessment.risk_level' | tr '[:lower:]' '[:upper:]')"
echo ""
echo "Vulnerabilities:"
echo "  Critical: $(echo $REPORT | jq -r '.vulnerability_stats.critical')"
echo "  High:     $(echo $REPORT | jq -r '.vulnerability_stats.high')"
echo "  Medium:   $(echo $REPORT | jq -r '.vulnerability_stats.medium')"
echo "  Low:      $(echo $REPORT | jq -r '.vulnerability_stats.low')"

# Save full report
echo "$REPORT" | jq '.' > "scan_report_${BATCH_ID}.json"
echo ""
echo "📄 Full report saved to: scan_report_${BATCH_ID}.json"
```

## Node.js Example

```javascript
const axios = require("axios");

const API_URL = "http://localhost:8080";

class NapScanClient {
  constructor() {
    this.token = null;
  }

  async login(username, password) {
    const response = await axios.post(`${API_URL}/api/auth/login`, {
      username,
      password,
    });
    this.token = response.data.token;
  }

  getHeaders() {
    return { Authorization: `Bearer ${this.token}` };
  }

  async createScan(target, scanType = "all", toolNames = null, options = null) {
    const payload = { target, scan_type: scanType, timeout: 20 };
    if (toolNames) payload.tool_names = toolNames;
    if (options) payload.options = options;

    const response = await axios.post(`${API_URL}/api/scans`, payload, {
      headers: this.getHeaders(),
    });
    return response.data.batch_id;
  }

  async getStatus(batchId) {
    const response = await axios.get(`${API_URL}/api/scans/${batchId}`, {
      headers: this.getHeaders(),
    });
    return response.data;
  }

  async getReport(batchId) {
    const response = await axios.get(`${API_URL}/api/scans/${batchId}/report`, {
      headers: this.getHeaders(),
    });
    return response.data;
  }

  async waitForCompletion(batchId, interval = 5000, timeout = 600000) {
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      const status = await this.getStatus(batchId);

      if (status.status === "completed") {
        return true;
      } else if (status.status === "failed") {
        throw new Error("Batch scan failed");
      }

      console.log(
        `Status: ${status.status} - ${status.completed_jobs}/${status.expected_jobs} jobs completed`
      );
      await new Promise((resolve) => setTimeout(resolve, interval));
    }

    throw new Error("Scan did not complete in time");
  }
}

// Usage
(async () => {
  const client = new NapScanClient();
  await client.login("security_admin", "SecurePass123!");

  const batchId = await client.createScan("192.168.1.100");
  console.log(`Scan created: ${batchId}`);

  await client.waitForCompletion(batchId);

  const report = await client.getReport(batchId);
  console.log("\n=== Scan Report ===");
  console.log(`Risk Level: ${report.risk_assessment.risk_level.toUpperCase()}`);
  console.log(
    `Vulnerabilities: ${report.vulnerability_stats.critical} critical, ${report.vulnerability_stats.high} high`
  );
})();
```
