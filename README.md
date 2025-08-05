<img src="logo.svg" alt="Funktionslust Logo" width="120">

# fLINK - Production-Ready URL Redirector

**High-performance URL redirector with wildcard patterns, analytics integration, and QR code generation.**  
Battle-tested in production with minimal resource usage and excellent performance.

Designed as a simpler, more accessible alternative to Shlink, YOURLS, and Polr - no database, no complex setup, just a single binary or Docker container.

[![GitHub Release](https://img.shields.io/github/v/release/funktionslust/fLINK)](https://github.com/funktionslust/fLINK/releases/latest)
[![Docker Version](https://img.shields.io/docker/v/funktionslust/flink/latest?label=docker)](https://hub.docker.com/r/funktionslust/flink)
[![Docker Pulls](https://img.shields.io/docker/pulls/funktionslust/flink)](https://hub.docker.com/r/funktionslust/flink)
[![GitHub Stars](https://img.shields.io/github/stars/funktionslust/fLINK)](https://github.com/funktionslust/fLINK)
[![License](https://img.shields.io/github/license/funktionslust/fLINK)](https://github.com/funktionslust/fLINK/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/funktionslust/fLINK)](https://goreportcard.com/report/github.com/funktionslust/fLINK)

**[Docker Hub](https://hub.docker.com/r/funktionslust/flink)** | 
**[GitHub](https://github.com/funktionslust/fLINK)** | 
**[Website](https://funktionslust.digital/apps/flink)**

## Why fLINK?

### Core Features

- **Simple Deployment** - Single static binary, no database required
- **Hot Reload** - Configuration changes detected automatically (file watch or HTTP polling)
- **Wildcard Patterns** - Bulk redirect entire directory structures with `/*` patterns
- **Built-in QR Codes** - Automatic QR code generation at `/yourlink/qr` endpoints
- **Analytics Ready** - Matomo integration with full UTM and click ID preservation
- **High Performance** - Optimized for speed with concurrent-safe operations
- **Security** - Path traversal protection, trusted proxy support, security headers

## Quick Start

### Docker (Recommended)

```bash
# Using environment variables for inline mappings
docker run -d \
  -p 8080:8080 \
  -e REDIRECT_MAPPINGS="store=https://shop.example.com;contact=https://example.com/contact" \
  funktionslust/flink:latest
```

Your redirects are ready:
- `http://localhost:8080/store` → `https://shop.example.com`
- `http://localhost:8080/contact` → `https://example.com/contact`

### Using CLI Flags

```bash
# Build from source
go build -o flink .

# Run with inline mappings
./flink -mappings "store=https://shop.example.com;docs=https://docs.example.com" -port 8080

# Use a configuration file
./flink -mappings /etc/flink/redirects.txt

# Disable query parameter forwarding
./flink -mappings redirects.txt -forward-query-params=false

# With Matomo analytics tracking
./flink -mappings redirects.txt -matomo-url https://analytics.example.com -matomo-token your-api-token

# Custom trusted proxy configuration
./flink -mappings redirects.txt -trusted-proxies "10.0.0.0/8,192.168.1.0/24"
```

### Using a Configuration File

Create `redirects.txt`:
```
# Marketing campaigns
summer-sale=https://shop.com/promotions/summer
black-friday=https://shop.com/deals/black-friday

# Support links  
help=https://docs.example.com
status=https://status.example.com

# Permanent redirects for SEO (using named aliases)
old-product=https://shop.com/products/new-name,permanent
legacy-api=https://api.v2.example.com,status=301

# Wildcard patterns for bulk redirects
blog/*=https://newsite.com/posts/*,permanent
old-docs/*=https://docs.example.com/archive/*
```

Run with Docker:
```bash
docker run -d \
  -p 8080:8080 \
  -v ./redirects.txt:/app/redirects.txt \
  -e REDIRECT_MAPPINGS=/app/redirects.txt \
  funktionslust/flink:latest
```

### Using Remote Configuration (HTTP/HTTPS)

Load configuration from a web server - perfect for centralized management:
```bash
docker run -d \
  -p 8080:8080 \
  -e REDIRECT_MAPPINGS=https://config.example.com/redirects.txt \
  funktionslust/flink:latest
```

fLINK will fetch the configuration from the URL and refresh it every 10 minutes automatically.

## Real-World Examples

### Marketing Campaign Tracking

**Problem:** You need to advertise `https://shop.example.com/products/category/summer-collection-2025?utm_source=radio&utm_medium=audio&utm_campaign=summer25` on a radio ad.

**Solution:** Create a short, memorable redirect:
```
# redirects.txt
summer=https://shop.example.com/products/category/summer-collection-2025
```

**Now you can:**
- Say "Visit link.co/summer" on radio (easy to remember)
- Use `link.co/summer?utm_source=radio` for radio ads
- Use `link.co/summer?utm_source=billboard` for outdoor ads
- Use `link.co/summer?utm_source=tv` for TV commercials
- Track all campaigns in your analytics while keeping URLs short and memorable

### Dynamic QR Codes

```
# redirects.txt
menu=https://restaurant.com/current-menu.pdf
wifi=https://restaurant.com/wifi-instructions
```

Generate QR codes automatically:
- Menu QR: `https://link.restaurant.com/menu/qr`
- WiFi QR: `https://link.restaurant.com/wifi/qr`

Update the destination URLs anytime without reprinting QR codes!

### SEO-Friendly Domain Migration

Preserve search rankings with permanent redirects:
```
# Use status codes or named aliases
old-blog=https://newsite.com/blog,permanent
legacy-api=https://api.v2.example.com,status=301
old-shop=https://newshop.com,301

# Bulk redirect with wildcards
docs/*=https://newdocs.com/archive/*,permanent
blog/*=https://newsite.com/articles/*,301
```

## Production Deployment

### Docker Compose with Traefik

```yaml
services:
  flink:
    image: funktionslust/flink:latest
    volumes:
      - ./redirects.txt:/app/redirects.txt
    environment:
      - REDIRECT_MAPPINGS=/app/redirects.txt
      - TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.flink.rule=Host(`link.yourdomain.com`)"
      - "traefik.http.routers.flink.tls.certresolver=letsencrypt"
    restart: unless-stopped
```

### With Matomo Analytics

```yaml
services:
  flink:
    image: funktionslust/flink:latest
    environment:
      - REDIRECT_MAPPINGS=/app/redirects.txt
      - MATOMO_URL=https://analytics.example.com
      - MATOMO_TOKEN_FILE=/run/secrets/matomo_token
    secrets:
      - matomo_token
    restart: unless-stopped
```

**Analytics Features:**
- Automatic event tracking for all redirects
- Full UTM parameter preservation
- Click ID tracking (gclid, fbclid, msclkid)
- Respects visitor privacy settings

## Configuration

### Redirect Format

```
short-code=destination-url[,status=301|302|307|308|permanent|temporary]
```

- Default status: 302 (temporary)
- Use 301 or `permanent` for permanent redirects (SEO)
- Use 302 or `temporary` for temporary redirects
- Use 307 (`temporary-strict`) or 308 (`permanent-strict`) to preserve request method
- Use 303 (`see-other`) to change POST to GET

### Wildcard Patterns

Handle bulk redirects with wildcard patterns:

```
# Redirect entire directory structures
blog/*=https://newsite.com/articles/*
docs/*=https://documentation.site/*

# API versioning
api/v1/*=https://v1.api.com/*
api/v2/*=https://v2.api.com/*

# Catch-all (lowest priority)
/*=https://default.com/*
```

**Pattern Matching Rules:**
- Wildcards (`*`) must be at the end of the path
- Longer prefixes match first (more specific wins)
- Exact matches always beat wildcard patterns
- The captured suffix is preserved in the destination URL
- Pattern: `blog/*` → `https://new.com/posts/*`
- Request: `/blog/hello-world` → `https://new.com/posts/hello-world`

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-mappings` | File path, URL, or inline mappings | - |
| `-port` | Server port | 8080 |
| `-forward-query-params` | Forward query parameters to destination | true |
| `-trusted-proxies` | Comma-separated CIDR ranges of trusted proxies | Private networks |
| `-matomo-url` | Matomo analytics URL | - |
| `-matomo-token` | Matomo API token | - |
| `-help` | Show help message | - |
| `-version` | Show version information | - |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIRECT_MAPPINGS` | File path, URL, or inline mappings | - |
| `PORT` | Server port | 8080 |
| `FORWARD_QUERY_PARAMS` | Forward query parameters to destination | true |
| `TRUSTED_PROXIES` | Comma-separated CIDR ranges of trusted proxies | Private networks |
| `MATOMO_URL` | Analytics server URL | - |
| `MATOMO_TOKEN` | Analytics API token | - |

**Notes:** 
- CLI flags take precedence over environment variables
- All environment variables support `_FILE` suffix for Docker secrets
- Private network ranges are trusted by default (can be overridden)

## Security Features

### Built-in Protections

- **Path Traversal Prevention** - Blocks `../`, null bytes, and encoded attacks
- **Security Headers** - Automatic `X-Content-Type-Options`, `X-Frame-Options`
- **Trusted Proxy Support** - Configurable CIDR ranges for `X-Forwarded-*` headers
- **Request Validation** - Only GET/HEAD methods allowed
- **URL Validation** - Enforces `http://` or `https://` destinations

### Performance

- **Minimal Memory** - Lightweight memory footprint
- **Sub-millisecond Latency** - 7-18 microseconds for redirects in production
- **Zero Dependencies** - Single static binary
- **Instant Reload** - Hot configuration updates without downtime
- **Concurrent Safe** - Thread-safe rule updates

## Monitoring & Operations

### Health Checks

```bash
# Simple health check
curl http://localhost:8080/health

# Check specific redirect
curl -I http://localhost:8080/your-link
```

### Logging

All requests are logged with structured format:
```
[2025-01-15T10:30:45Z] 192.168.1.100 GET /campaign → https://shop.com (301) 1.2ms
[2025-01-15T10:30:46Z] 192.168.1.101 GET /menu/qr → QR:https://link.com/menu (200) 3.5ms
```

## Planned Features

- **Management API** - REST API for dynamic rule management
- **Google Analytics** - Native GA4 integration
- **Rule Validation** - Pre-flight configuration testing

## Support

- **Issues**: [GitHub Issues](https://github.com/funktionslust/fLINK/issues)
- **Docker Hub**: [funktionslust/flink](https://hub.docker.com/r/funktionslust/flink)
- **Support**: Available from [Funktionslust GmbH](https://funktionslust.digital)

## License

MIT License - Use it freely in your projects!

---

**Built by [Funktionslust GmbH](https://funktionslust.digital)**  
*Enterprise software development and consulting.*