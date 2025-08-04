# Build stage
FROM golang:1.24-alpine AS builder

# Build arguments for version information
ARG VERSION=latest
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY *.go ./
COPY tracking ./tracking/

# Build the binary with version information
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    -ldflags="-w -s \
    -X main.version=${VERSION} \
    -X main.commit=${COMMIT} \
    -X main.date=${BUILD_DATE}" \
    -o flink .

# Final stage
FROM alpine:3.22

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/flink .

# Create non-root user
RUN addgroup -g 1001 -S flink && \
    adduser -u 1001 -S flink -G flink

USER flink

EXPOSE 8080

CMD ["./flink"]