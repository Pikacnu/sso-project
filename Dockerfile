# Multi-stage build for SSO server

# Stage 1: Build frontend (Astro)
FROM node:20-alpine AS frontend-builder
WORKDIR /app/web

COPY web/package.json web/package-lock.json* web/yarn.lock* ./
RUN npm install --frozen-lockfile || npm install

COPY web . 
RUN npm run build

# Stage 2: Build backend (Go)
FROM golang:1.25.6-alpine AS backend-builder
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=frontend-builder /app/web/dist ./web/dist

# Build the Go application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o sso-server .

# Stage 3: Runtime image
FROM alpine:latest
WORKDIR /root

# Install runtime dependencies
RUN apk add --no-cache ca-certificates postgresql-client

# Copy binary from builder
COPY --from=backend-builder /app/sso-server .

# Copy templates from builder (if needed for email templates)
COPY --from=backend-builder /app/templates ./templates

# Copy frontend assets from builder
COPY --from=backend-builder /app/web/dist ./web/dist

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["./sso-server"]
