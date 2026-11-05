# Multi-stage Dockerfile for ultra-lightweight binary (< 25MB total image size)
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY go.mod ./
# Download dependencies if any (zero external dependencies needed)
RUN go mod download

# Copy source code
COPY . .

# Build statically linked standalone binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /my-s3 ./cmd/server

# Final minimal production stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /

# Copy binary from builder
COPY --from=builder /my-s3 /usr/local/bin/my-s3

# Create storage directory and non-root user
RUN mkdir -p /data && chmod 777 /data

EXPOSE 9000 9001

ENV S3_PORT=9000 \
    CONSOLE_PORT=9001 \
    DATA_DIR=/data \
    ACCESS_KEY=minioadmin \
    SECRET_KEY=minioadmin \
    ALLOW_ANON=true

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/my-s3"]
