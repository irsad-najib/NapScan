# Backend Development Guide

This guide is intended for developers working on the NapScan backend. It covers setup, architecture, and workflows for adding new features.

## 🛠 Prerequisites

Before you start, ensure you have the following installed:

- **Go**: Version 1.22 or higher.
- **Docker**: For running containerized services (MySQL, scanners).
- **MySQL**: Local instance or via Docker.
- **Tools**:
  - `nmap` (Network scanning)
  - `nuclei` (Vulnerability scanning)
  - `openvas` (Vulnerability scanning)
  - `ffuf` (Fuzzing)
  - `zap` (Vulnerability scanning)
  - `mobsf` (Vulnerability scanning)
  - `sslyze` (Vulnerability scanning)
  - `frida` (Dynamic analysis)

## 🚀 Getting Started

### 1. Clone & Setup

```bash
git clone <repository-url>
cd NapScan/backend
```

### 2. Environment Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Ensure `.env` has the correct configuration, especially for the database:

```ini
PORT=5000
APP_ENV=development
MYSQL_DSN=user:password@tcp(127.0.0.1:3306)/napscan?charset=utf8mb4&parseTime=True&loc=Local
JWT_SECRET=your_secret_key
```

### 3. Running the Server

**Development Mode (Live Reload):**
If you have [Air](https://github.com/cosmtrek/air) installed:

```bash
air
```

**Standard Run:**

```bash
go run cmd/server/main.go
```

The server will start on port `5000` (or what's defined in `PORT`).
Swagger UI: `http://localhost:5000/api/swagger/index.html` (Development only)

## 🏗 Project Architecture

NapScan follows a **Clean Architecture** inspired structure:

```
backend/
├── cmd/
│   └── server/         # Application entry point
├── internal/
│   ├── handler/        # HTTP Handlers (Requests/Responses)
│   ├── service/        # Business Logic
│   ├── repository/     # Data Access Layer (DB interactions)
│   ├── models/         # Database Models & Structs
│   ├── routes/         # API Route definitions
│   └── middleware/     # Auth, Logging, CORS
├── pkg/                # Shared utilities
└── docs/               # Documentation & Swagger files
```

### Layer Responsibilities

1.  **Handler**: Parses request, validates input, calls `Service`, and formats response.
2.  **Service**: Contains business logic. Orchestrates calls to `Repository` or other Services.
3.  **Repository**: Performs direct database operations (CRUD).
4.  **Model**: Defines data structures.

## ➕ How to Add a New Scanner

1.  **Define Model**: Add a new struct in `internal/models/` for the scan result if needed.
2.  **Create Repository**: Add a method in `internal/repository/` to save results.
3.  **Implement Service**:
    - Create `internal/service/scanner_name_service.go`
    - Implement the scanning logic (e.g., executing a command).
4.  **Create Handler**:
    - Create `internal/handler/scanner_name_handler.go`
    - Add methods to trigger scan and retrieve results.
5.  **Register Route**:
    - Add a new group in `internal/routes/`.
    - Register it in `cmd/server/main.go`.

## 🧪 Testing

Run all tests:

```bash
go test ./...
```

Run with coverage:

```bash
go test -cover ./...
```

## 📝 API Documentation (Swagger)

We use `swaggo/swag` to generate API docs.

**Annotations:**
Add comments above your handler functions:

```go
// @Summary Run Nmap Scan
// @Description usage: runs nmap scan on target
// @Tags Nmap
// @Accept json
// @Produce json
// @Param request body models.ScanRequest true "Scan Request"
// @Success 200 {object} models.ScanResponse
// @Router /nmap/scan [post]
func (h *NmapHandler) Scan(c *fiber.Ctx) error { ... }
```

**Generate Docs:**

```bash
swag init -g cmd/server/main.go --output docs/
```

> **Note:** Swagger endpoint is disabled in production (`APP_ENV=production`).
