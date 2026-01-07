# Backend (Mock Server)

This is a small mock server example using Gin.

Quick start:

1. Set port (optional):

```bash
export PORT=8080
```

Alternatively you can create a `.env` file in the `backend` folder with the same variable:

```text
PORT=8080
```

To load `.env` into your shell you can run:

```bash
export $(cat .env | xargs)
# then
go run main.go
```

Or add runtime loading in Go using `github.com/joho/godotenv` and call `godotenv.Load()` at startup.

2. Run:

```bash
go run main.go
```

3. Endpoints:

- `GET /health` - health check
- `GET /api/v1/ping` - returns `pong`
- `GET /api/v1/items` - mock list
- `POST /api/v1/echo` - echoes JSON payload

Graceful shutdown is implemented (SIGINT/SIGTERM) with a 5s timeout.

Note: This file is only a simple example for development and testing.
