# Nuclei Async API Documentation

## 🚀 Overview

Nuclei scan sekarang support **Async mode** untuk menghindari timeout pada long-running scans.

---

## 📡 Endpoints

### 1. **Start Async Scan** (Recommended)

**POST** `/api/nuclei/scan/async`

Memulai scan secara asynchronous. Response instant dengan `task_id`.

**Request:**

```json
{
  "target": "cms.ayolari.net",
  "batch_id": "392855d4-73f6-408c-99bf-957a670add50"
}
```

**Response (202 Accepted):**

```json
{
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "pending",
  "message": "Scan started. Use /nuclei/scan/async/{task_id} to check status",
  "target": "cms.ayolari.net"
}
```

---

### 2. **Check Scan Status**

**GET** `/api/nuclei/scan/async/{task_id}`

Cek progress dan status scan.

**Response (Running):**

```json
{
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "target": "cms.ayolari.net",
  "batch_id": "392855d4-73f6-408c-99bf-957a670add50",
  "status": "running",
  "progress": 50,
  "started_at": "2026-01-15T07:50:00Z",
  "updated_at": "2026-01-15T07:52:00Z"
}
```

**Response (Completed):**

```json
{
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "target": "cms.ayolari.net",
  "batch_id": "392855d4-73f6-408c-99bf-957a670add50",
  "status": "completed",
  "progress": 100,
  "result_count": 23,
  "message": "Scan completed. Use /nuclei/scan/async/{taskId}/result to get results",
  "started_at": "2026-01-15T07:50:00Z",
  "updated_at": "2026-01-15T07:54:00Z"
}
```

**Response (Failed):**

```json
{
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "failed",
  "error": "nuclei execution failed: ...",
  "started_at": "2026-01-15T07:50:00Z",
  "updated_at": "2026-01-15T07:52:00Z"
}
```

---

### 3. **Get Scan Result**

**GET** `/api/nuclei/scan/async/{task_id}/result?compact=true`

Ambil hasil scan setelah selesai.

**Query Parameters:**

- `compact=true` (default): Compact summary (recommended)
- `compact=false`: Full results (max 100 findings)

**Response:**

```json
{
  "success": true,
  "message": "Scan result retrieved",
  "data": {
    "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "target": "cms.ayolari.net",
    "batch_id": "392855d4-73f6-408c-99bf-957a670add50",
    "compact": true,
    "summary": {
      "total_findings": 23,
      "severity_count": {
        "critical": 2,
        "high": 5,
        "medium": 10,
        "low": 6
      },
      "findings": [
        {
          "template_id": "CVE-2021-12345",
          "matched_at": "https://cms.ayolari.net/login",
          "name": "SQL Injection Vulnerability",
          "severity": "critical",
          "tags": ["cve", "sqli", "injection"]
        }
      ]
    }
  }
}
```

---

## 🔄 Workflow

### Frontend Implementation:

```javascript
// 1. Start scan
const response = await fetch("/api/nuclei/scan/async", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    target: "cms.ayolari.net",
    batch_id: batchId,
  }),
});

const { task_id } = await response.json();

// 2. Poll status every 5 seconds
const pollStatus = setInterval(async () => {
  const statusResponse = await fetch(`/api/nuclei/scan/async/${task_id}`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  const status = await statusResponse.json();

  if (status.status === "completed") {
    clearInterval(pollStatus);

    // 3. Get results
    const resultResponse = await fetch(
      `/api/nuclei/scan/async/${task_id}/result?compact=true`,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    const result = await resultResponse.json();
    console.log("Scan completed:", result);
  } else if (status.status === "failed") {
    clearInterval(pollStatus);
    console.error("Scan failed:", status.error);
  } else {
    console.log(`Progress: ${status.progress}%`);
  }
}, 5000); // Poll every 5 seconds
```

---

## 📊 Task Lifecycle

```
1. POST /nuclei/scan/async
   ↓
   Status: pending → running
   ↓
2. GET /nuclei/scan/async/{task_id}
   ↓
   Poll until status = completed/failed
   ↓
3. GET /nuclei/scan/async/{task_id}/result
   ↓
   Get scan results
```

---

## ⏱️ Task Expiration

- Tasks expire after **30 minutes** of inactivity
- Completed results are available for 30 minutes
- After expiration, task_id will return 404

---

## ✅ Benefits vs Sync Endpoint

| Feature           | Sync `/scan`    | Async `/scan/async`  |
| ----------------- | --------------- | -------------------- |
| Response Time     | 4+ minutes      | < 1 second           |
| Nginx Timeout     | ❌ Yes          | ✅ No                |
| Progress Tracking | ❌ No           | ✅ Yes               |
| User Experience   | ❌ Hang/Loading | ✅ Real-time updates |
| Scalability       | ❌ Limited      | ✅ Unlimited         |
| Production Ready  | ⚠️ No           | ✅ Yes               |

---

## 🔐 Security

- All endpoints require authentication (Bearer token)
- Users can only access their own tasks
- Task ownership is validated on every request
- Tasks are automatically cleaned up after expiration

---

## 🎯 Recommendation

**Use Async Endpoints for Production!**

Sync endpoint (`/nuclei/scan`) masih tersedia untuk backward compatibility, tapi **tidak direkomendasikan** karena timeout issues.
