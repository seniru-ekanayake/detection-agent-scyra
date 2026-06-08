# Stage 1: Build subfinder binary
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Stage 2: Python runtime
FROM python:3.11-slim

WORKDIR /app

# Copy subfinder binary from builder
COPY --from=builder /go/bin/subfinder /usr/local/bin/subfinder

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
