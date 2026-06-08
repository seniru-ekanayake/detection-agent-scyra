# Stage 1: Build httpx binary
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Stage 2: Python runtime
FROM python:3.11-slim

WORKDIR /app

# Copy httpx binary from builder
COPY --from=builder /go/bin/httpx /usr/local/bin/httpx

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
