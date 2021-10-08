# check_ssl_certificate2

Monitoring plugin to check ssl certificate expiration implemented with Go.

## Usage

```
Usage:
  check_ssl_certificate2 [OPTIONS]

Application Options:
      --timeout=    Timeout to wait for connection (default: 10s)
  -H, --hostname=   IP address or Host name (default: 127.0.0.1)
  -p, --port=       Port number (default: 443)
      --sni=        sepecify hostname for SNI
      --verify-sni  verify sni hostname
  -c, --critical=   The critical threshold in days before expiry (default: 14)
  -4                use tcp4 only
  -6                use tcp6 only
  -v, --version     Show version

Help Options:
  -h, --help        Show this help message
```

