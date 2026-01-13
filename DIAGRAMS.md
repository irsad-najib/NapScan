# NapScan System Architecture Diagrams

## 1. High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │  Web UI  │  │  Mobile  │  │   CLI    │  │  Python  │            │
│  │ (React)  │  │   App    │  │   Tool   │  │  Client  │            │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘            │
│       │             │             │             │                    │
│       └─────────────┴─────────────┴─────────────┘                    │
│                           │                                          │
│                           │ HTTPS / REST API                         │
└───────────────────────────┼──────────────────────────────────────────┘
                            │
┌───────────────────────────┼──────────────────────────────────────────┐
│                    API GATEWAY LAYER                                 │
│                           │                                          │
│  ┌────────────────────────▼──────────────────────────┐              │
│  │         Fiber HTTP Server (Go)                    │              │
│  │  ┌──────────┐ ┌──────────┐ ┌───────────────┐     │              │
│  │  │   CORS   │ │  Logger  │ │ Auth Middleware│    │              │
│  │  └──────────┘ └──────────┘ └───────────────┘     │              │
│  └───────────────────┬────────────────────────────────┘              │
│                      │                                               │
│       ┌──────────────┼──────────────┐                                │
│       │              │              │                                │
│  ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐                          │
│  │  Auth    │  │  Scan    │  │  Report  │                          │
│  │ Handler  │  │ Handler  │  │ Handler  │                          │
│  └──────────┘  └────┬─────┘  └────┬─────┘                          │
└─────────────────────┼──────────────┼────────────────────────────────┘
                      │              │
┌─────────────────────┼──────────────┼────────────────────────────────┐
│                BUSINESS LOGIC LAYER                                  │
│                     │              │                                 │
│  ┌──────────────────▼──────────────▼──────────────┐                 │
│  │         Batch Orchestrator                      │                 │
│  │  ┌──────────────┐  ┌──────────────────────┐    │                 │
│  │  │ Job Scheduler│  │   Worker Pool (10)   │    │                 │
│  │  └──────┬───────┘  └──────┬───────────────┘    │                 │
│  │         │                  │                    │                 │
│  │         │    ┌─────────────▼────────────┐       │                 │
│  │         │    │   Scanner Registry       │       │                 │
│  │         │    └─────────────┬────────────┘       │                 │
│  └─────────┼──────────────────┼────────────────────┘                 │
│            │                  │                                      │
│            │    ┌─────────────▼────────────┐                         │
│            │    │                          │                         │
│       ┌────▼────▼────┐  ┌──────────────────▼─────────┐              │
│       │   Report     │  │    Individual Scanners     │              │
│       │  Aggregator  │  │  ┌─────┐ ┌───────┐ ┌────┐ │              │
│       └──────────────┘  │  │Nmap │ │Nuclei │ │ZAP │ │              │
│                         │  └─────┘ └───────┘ └────┘ │              │
│                         │  ┌─────┐ ┌───────┐ ┌────┐ │              │
│                         │  │FFUF │ │SSLyze │ │ OV │ │              │
│                         │  └─────┘ └───────┘ └────┘ │              │
│                         └────────────┬───────────────┘              │
└──────────────────────────────────────┼──────────────────────────────┘
                                       │
┌──────────────────────────────────────┼──────────────────────────────┐
│                  DATA ACCESS LAYER                                   │
│                                      │                               │
│  ┌───────────────────┐  ┌───────────▼───────────┐                   │
│  │ Batch Repository  │  │ Vulnerability Repo    │                   │
│  └─────────┬─────────┘  └───────────┬───────────┘                   │
│            │                        │                               │
│            └────────────┬───────────┘                               │
└─────────────────────────┼─────────────────────────────────────────┘
                          │
┌─────────────────────────▼─────────────────────────────────────────┐
│                   PERSISTENCE LAYER                                │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │              PostgreSQL Database                             │ │
│  │  ┌─────────┐ ┌──────────┐ ┌────────────────┐ ┌──────────┐   │ │
│  │  │ Batches │ │ScanJobs  │ │Vulnerabilities │ │ Reports  │   │ │
│  │  └─────────┘ └──────────┘ └────────────────┘ └──────────┘   │ │
│  │  ┌──────────┐ ┌──────────┐                                   │ │
│  │  │Metadata  │ │AuditLog  │                                   │ │
│  │  └──────────┘ └──────────┘                                   │ │
│  └──────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────┘
```

## 2. Batch Scan Execution Flow

```
┌─────────┐
│  User   │
└────┬────┘
     │ 1. POST /api/scans
     │    {target, scan_type, tool_names}
     ▼
┌──────────────────┐
│  Scan Handler    │
└────┬─────────────┘
     │ 2. Create BatchRequest
     ▼
┌─────────────────────────┐
│  Batch Orchestrator     │
│  ┌──────────────────┐   │
│  │ 3. Validate      │   │
│  └────┬─────────────┘   │
│       │                 │
│  ┌────▼──────────────┐  │
│  │ 4. Create Batch   │  │
│  │    in Database    │  │
│  └────┬──────────────┘  │
│       │                 │
│  ┌────▼──────────────┐  │
│  │ 5. Create Jobs    │  │
│  │    (one per tool) │  │
│  └────┬──────────────┘  │
└───────┼─────────────────┘
        │
        │ 6. Dispatch to Worker Pool
        ▼
┌────────────────────────────────────────┐
│         Worker Pool (Parallel)         │
│  ┌────────┐ ┌────────┐ ┌────────┐     │
│  │Worker 1│ │Worker 2│ │Worker N│     │
│  └───┬────┘ └───┬────┘ └───┬────┘     │
│      │          │          │          │
│      │ 7. Get Scanner from Registry    │
│      ▼          ▼          ▼          │
│  ┌────────────────────────────────┐   │
│  │      Scanner Registry          │   │
│  └───┬────────────┬───────────┬───┘   │
└──────┼────────────┼───────────┼───────┘
       │            │           │
   8. Execute   Execute     Execute
       │            │           │
       ▼            ▼           ▼
   ┌──────┐    ┌────────┐  ┌───────┐
   │ Nmap │    │ Nuclei │  │ ZAP   │
   └──┬───┘    └───┬────┘  └───┬───┘
      │            │           │
      │ 9. Raw Results         │
      ▼            ▼           ▼
   ┌──────────────────────────────┐
   │  10. Normalize to            │
   │      Vulnerability Schema    │
   └───────────┬──────────────────┘
               │
               │ 11. Save to DB
               ▼
   ┌──────────────────────────────┐
   │  Vulnerability Repository    │
   │  - Check for duplicates      │
   │  - Generate fingerprint      │
   │  - Store vulnerabilities     │
   └───────────┬──────────────────┘
               │
               │ 12. Update Job Status
               ▼
   ┌──────────────────────────────┐
   │    Batch Repository          │
   │  - Mark job complete         │
   │  - Update batch progress     │
   │  - Check if all done         │
   └───────────┬──────────────────┘
               │
               │ 13. If all complete
               ▼
   ┌──────────────────────────────┐
   │  Mark Batch Complete         │
   └──────────────────────────────┘
```

## 3. Scanner Interface Implementation

```
┌─────────────────────────────────────────────────────────┐
│              Scanner Interface                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Name() string                                    │  │
│  │  Execute(ctx, config) (rawResult, error)         │  │
│  │  Normalize(rawResult) ([]Vulnerability, error)   │  │
│  │  Validate() error                                │  │
│  └───────────────────────────────────────────────────┘  │
└────────────────────┬────────────────────────────────────┘
                     │ implements
         ┌───────────┼───────────┐
         │           │           │
    ┌────▼────┐ ┌───▼─────┐ ┌──▼────────┐
    │  Nmap   │ │ Nuclei  │ │  SSLyze   │
    │ Scanner │ │ Scanner │ │  Scanner  │
    └────┬────┘ └───┬─────┘ └──┬────────┘
         │          │           │
         │          │           │
    Execute:   Execute:    Execute:
    │          │           │
    ▼          ▼           ▼
┌────────┐ ┌────────┐ ┌────────┐
│nmap    │ │nuclei  │ │sslyze  │
│-sV ... │ │-target │ │--json  │
└───┬────┘ └───┬────┘ └───┬────┘
    │          │           │
    ▼          ▼           ▼
  XML        JSONL       JSON
 Output      Output     Output
    │          │           │
    │          │           │
Normalize: Normalize: Normalize:
    │          │           │
    ▼          ▼           ▼
┌──────────────────────────────┐
│   []Vulnerability            │
│  {                           │
│    ID: "vuln-123",          │
│    Title: "...",            │
│    Severity: "high",        │
│    AffectedAsset: [...],    │
│    SourceTool: "nmap",      │
│    Evidence: "...",         │
│    Remediation: "...",      │
│    CVE: "CVE-2024-1234"     │
│  }                          │
└──────────────────────────────┘
```

## 4. Database Schema Relationships

```
┌─────────────────────────┐
│       batches           │
│  ┌──────────────────┐   │
│  │ id (PK)          │   │
│  │ batch_id (unique)│   │
│  │ user_id          │   │
│  │ target           │   │
│  │ status           │   │
│  │ expected_jobs    │   │
│  │ completed_jobs   │   │
│  │ failed_jobs      │   │
│  └────────┬─────────┘   │
└───────────┼─────────────┘
            │ 1
            │
            │ N
┌───────────▼─────────────┐
│      scan_jobs          │
│  ┌──────────────────┐   │
│  │ id (PK)          │   │
│  │ batch_id (FK)    │◄──┘
│  │ tool_name        │
│  │ status           │
│  │ start_time       │
│  │ end_time         │
│  │ raw_result JSONB │
│  │ error_message    │
│  └────────┬─────────┘
└───────────┼─────────────┘
            │ 1
            │
            │ N
┌───────────▼─────────────┐
│   vulnerabilities       │
│  ┌──────────────────┐   │
│  │ id (PK)          │   │
│  │ batch_id (FK)    │   │
│  │ scan_job_id (FK) │◄──┘
│  │ title            │
│  │ severity         │
│  │ description      │
│  │ affected_asset   │
│  │ source_tool      │
│  │ evidence         │
│  │ remediation      │
│  │ cve, cwe, cvss   │
│  │ fingerprint      │──┐
│  │ is_duplicate     │  │ deduplication
│  │ duplicate_of     │◄─┘
│  └──────────────────┘
└─────────────────────────┘
            │ N
            │
            │ 1
┌───────────▼─────────────┐
│    batch_reports        │
│  ┌──────────────────┐   │
│  │ id (PK)          │   │
│  │ batch_id (FK)    │   │
│  │ total_vulns      │   │
│  │ critical_count   │   │
│  │ high_count       │   │
│  │ risk_score       │   │
│  │ risk_level       │   │
│  │ report_data JSONB│   │
│  └──────────────────┘   │
└─────────────────────────┘
```

## 5. Request/Response Flow

```
Client Request
     │
     ▼
┌──────────────────────────────┐
│ POST /api/scans              │
│ {                            │
│   "target": "192.168.1.1",  │
│   "scan_type": "all",       │
│   "timeout": 20             │
│ }                            │
└───────────┬──────────────────┘
            │
            ▼
     ┌──────────────┐
     │ JWT Auth     │
     │ Middleware   │
     └──────┬───────┘
            │
            ▼
     ┌──────────────┐
     │ Validate     │
     │ Request      │
     └──────┬───────┘
            │
            ▼
     ┌──────────────┐
     │ Create       │
     │ Batch        │
     └──────┬───────┘
            │
            ▼
     ┌──────────────┐
     │ Start Async  │
     │ Execution    │
     └──────┬───────┘
            │
            ▼ Immediate Response (202 Accepted)
┌──────────────────────────────┐
│ {                            │
│   "batch_id": "uuid",       │
│   "status": "processing",   │
│   "message": "...",         │
│   "created_at": "..."       │
│ }                            │
└──────────────────────────────┘
            │
            │ Later: GET /api/scans/:batchId
            ▼
┌──────────────────────────────┐
│ {                            │
│   "status": "completed",    │
│   "completed_jobs": 6,      │
│   "expected_jobs": 6,       │
│   "jobs": [...]             │
│ }                            │
└──────────────────────────────┘
            │
            │ Finally: GET /api/scans/:batchId/report
            ▼
┌──────────────────────────────┐
│ {                            │
│   "summary": {...},         │
│   "vulnerability_stats": {  │
│     "critical": 2,          │
│     "high": 5               │
│   },                        │
│   "vulnerabilities": [...], │
│   "recommendations": [...]  │
│ }                            │
└──────────────────────────────┘
```

## 6. Component Interaction Matrix

```
┌──────────────┬────────┬────────┬──────────┬────────┬──────────┐
│              │Handler │Orchestr│Registry  │Scanner │Repository│
├──────────────┼────────┼────────┼──────────┼────────┼──────────┤
│Handler       │   -    │  Uses  │    -     │   -    │  Uses    │
├──────────────┼────────┼────────┼──────────┼────────┼──────────┤
│Orchestrator  │   -    │   -    │  Uses    │   -    │  Uses    │
├──────────────┼────────┼────────┼──────────┼────────┼──────────┤
│Registry      │   -    │   -    │    -     │ Manages│    -     │
├──────────────┼────────┼────────┼──────────┼────────┼──────────┤
│Scanner       │   -    │   -    │    -     │   -    │    -     │
├──────────────┼────────┼────────┼──────────┼────────┼──────────┤
│Repository    │   -    │   -    │    -     │   -    │    -     │
└──────────────┴────────┴────────┴──────────┴────────┴──────────┘

Legend:
  Uses     = Direct dependency
  Manages  = Owns and controls
  -        = No direct interaction
```

These diagrams illustrate the clean separation of concerns and modular design of the NapScan system.
