<img src="logo.svg" alt="Funktionslust Logo" width="120">

# fLINK

A lightweight HTTP redirect service with dynamic configuration support.

## Description

fLINK is a minimalistic redirect service that maps short IDs to full URLs. It supports both file-based and environment-based configuration with hot reloading capabilities. Perfect for URL shortening, link management, or redirect proxying.

## Features

- **Dynamic Configuration**: Load redirects from files or environment variables
- **Hot Reloading**: Automatically detects file changes and reloads configuration
- **Multiple Status Codes**: Support for 301, 302, 303, 307, and 308 redirects
- **Query Parameter Forwarding**: Automatically forwards query parameters to destination URLs
- **QR Code Generation**: Generate QR codes for any redirect by adding `/qr` suffix
- **Structured Logging**: Clear access logs with detailed request information
- **Thread-Safe**: Concurrent request handling with safe configuration updates
- **Input Validation**: Secure handling of IDs and URLs
- **Reverse Proxy Support**: Proper hostname detection from proxy headers

## Why Choose fLINK Over Alternatives?

Unlike complex URL shortening solutions like **Shlink**, **YOURLS**, **Polr**, or **Kutt**, fLINK follows the Unix philosophy: *do one thing and do it well*. 

| Feature | fLINK | Shlink | YOURLS | Polr | Others |
|---------|-------|--------|--------|------|--------|
| **No Frontend Required** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **No Database Required** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Single Binary** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **File-based Config** | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ |
| **Built-in QR Codes** | ✅ | ✅ | ❌ | ❌ | ⚠️ |
| **Zero Dependencies** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Memory Footprint** | < 10MB | > 100MB | > 50MB | > 30MB | Varies |

**Perfect for:**
- DevOps teams who need simple redirects without UI overhead
- Microservices architectures where each service should have a single responsibility  
- Situations where you don't need click analytics, user management, or web interfaces
- Container deployments where minimal resource usage matters
- Teams who prefer configuration-as-code over database management

## Installation

### Docker (Recommended)

```bash
docker pull funktionslust/flink:latest
docker run -p 8080:8080 -e REDIRECT_MAPPINGS="test=https://example.com" funktionslust/flink
```

### Using Go

```bash
go install github.com/funktionslust/fLINK@latest
```

### Building from Source

```bash
git clone https://github.com/funktionslust/fLINK.git
cd fLINK
go build -o flink main.go
```

## Usage

### Environment Variables

- `REDIRECT_MAPPINGS`: Either a file path or inline mapping string (required)
- `PORT`: Server port (default: 8080)

### Configuration Format

Mappings use the format `key=url` or `key=url,status=code`:

```
home=https://example.com
search=https://google.com,status=301
docs=https://docs.example.com/guide,status=307
```

**Note**: The default status code is 302 (temporary redirect). Use `status=301` for permanent redirects.

### File-based Configuration

Create a mappings file:

```bash
echo "test=https://example.com" > redirects.txt
REDIRECT_MAPPINGS=redirects.txt ./flink
```

The service automatically detects changes to the file and reloads the configuration without requiring a restart. This allows you to add, modify, or remove redirects on the fly.

### Inline Configuration

```bash
REDIRECT_MAPPINGS="test=https://example.com;demo=https://google.com,status=302" ./flink
```

### Docker Compose

```yaml
services:
  flink:
    image: funktionslust/flink:latest
    ports:
      - "8080:8080"
    environment:
      - REDIRECT_MAPPINGS=test=https://example.com;demo=https://google.com,status=302
```

### Making Requests

Once running, access redirects at `http://localhost:8080/{key}`:

```bash
curl -I http://localhost:8080/test  # Redirects to https://example.com
```

### Query Parameter Forwarding

Query parameters are automatically forwarded to the destination URL:

```bash
# Configuration: test=https://example.com
curl -I "http://localhost:8080/test?user=john&tab=profile"
# Redirects to: https://example.com?user=john&tab=profile

# Configuration: search=https://google.com/search?q=flink
curl -I "http://localhost:8080/search?lang=en"  
# Redirects to: https://google.com/search?q=flink&lang=en
```

### QR Code Generation

Generate QR codes for any configured redirect by adding `/qr` to the URL:

```bash
# View in browser
http://localhost:8080/test/qr

# Download via curl
curl http://localhost:8080/test/qr -o test-qr.png
```

The QR code contains the full short URL (including hostname and path prefix from reverse proxy headers) and can be scanned to access the redirect. When using reverse proxies like Traefik with path stripping, the QR code will include the original path prefix.

## Examples

See the `example/` directory for complete Docker Compose setups, including:
- Basic Docker Compose configuration
- Traefik 3 reverse proxy integration with SSL certificates

### Traefik 3 Integration

For production deployments with automatic SSL certificates:

```yaml
# traefik-docker-compose.yml
services:
  flink:
    image: funktionslust/flink:latest
    environment:
      - REDIRECT_MAPPINGS=test=https://example.com
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.flink.rule=Host(`links.example.com`)"
      - "traefik.http.routers.flink.entrypoints=websecure"
      - "traefik.http.routers.flink.tls.certresolver=letsencrypt"
```

## Logging

fLINK outputs structured access logs for all requests:

```
[2025-06-15T19:24:54Z] 203.0.113.1 GET /test → https://example.com (301) 500ns
[2025-06-15T19:25:03Z] 203.0.113.1 GET /test/qr → QR:https://example.com/test (200) 3.2ms
[2025-06-15T19:25:15Z] 203.0.113.2 GET /invalid ERROR: Invalid redirect ID (400) 250ns
```

On startup, fLINK displays all loaded redirect rules:
```
2025/06/15 19:24:50 Loaded 3 redirect rule(s):
2025/06/15 19:24:50   home → https://example.com (status: 301)
2025/06/15 19:24:50   search → https://google.com (status: 302)
2025/06/15 19:24:50   docs → https://docs.example.com/guide (status: 307)
```

## Security

- Only accepts GET requests
- Validates IDs (alphanumeric, hyphens, underscores only)
- Validates URLs must start with http:// or https://
- Restricts redirect status codes to standard values
- Limits ID length to 256 characters
- Limits URL length to 2048 characters
- Proper handling of reverse proxy headers
- No external dependencies except QR code library

## Testing

Run the comprehensive test suite:

```bash
go test -v                    # Run all tests
go test -race                 # Run with race detection
go test -coverprofile=coverage.out  # Generate coverage report
```

Current test coverage: **83.7%** with 25+ test functions covering:
- Input validation (IDs, URLs, status codes)
- Configuration parsing and file loading
- HTTP request handling (redirects, QR codes, errors)
- Concurrent access and thread safety
- Reverse proxy header handling
- Structured logging functionality

## Publishing & Distribution

### GitHub Repository
- **Source Code**: [github.com/funktionslust/fLINK](https://github.com/funktionslust/fLINK)
- **Issues & Support**: [GitHub Issues](https://github.com/funktionslust/fLINK/issues)
- **Releases**: [GitHub Releases](https://github.com/funktionslust/fLINK/releases)

### Docker Hub
- **Registry**: [hub.docker.com/r/funktionslust/flink](https://hub.docker.com/r/funktionslust/flink)
- **Pull Command**: `docker pull funktionslust/flink:latest`
- **Multi-platform**: Supports `linux/amd64` and `linux/arm64`

### Automated CI/CD
- ✅ **GitHub Actions**: Automated testing, building, and Docker image publishing
- ✅ **Multi-platform Builds**: AMD64 and ARM64 support
- ✅ **Automated Releases**: GoReleaser integration for cross-platform binaries
- ✅ **Code Coverage**: Integrated with Codecov

## Author

**fLINK** is developed and maintained by [Funktionslust GmbH](https://funktionslust.digital).

For professional consulting, custom development, or enterprise support, please contact us.

## License

MIT License - Copyright (c) 2025 Funktionslust GmbH