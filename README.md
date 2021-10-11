# check_ssl_certificate2

Monitoring plugin to check ssl certificate expiration implemented with Go.

## Usage

```
Usage:
  check_ssl_certificate2 [OPTIONS]

Application Options:
      --timeout=       Timeout to wait for connection (default: 10s)
  -H, --hostname=      IP address or Host name (default: 127.0.0.1)
  -p, --port=          Port number (default: 443)
      --sni=           sepecify hostname for SNI
      --verify-sni     verify sni hostname
      --verify-chains  verify all certificate chains
  -c, --critical=      The critical threshold in days before expiry (default: 14)
  -4                   use tcp4 only
  -6                   use tcp6 only
  -v, --version        Show version

Help Options:
  -h, --help           Show this help message
```

## Example


OK

```
 ./check_ssl_certificate2  -H 104.154.89.105 -p 443 --sni badssl.com
SSL CERTIFICATE OK - 218 day(s) left for this certificate. end date is [2022-05-17 12:00:00 +0000 UTC] on 104.154.89.105 port 443 sni badssl.com|time=0.598756s;;;0.000000;10.000000
```

Expired

```
./check_ssl_certificate2  -H expired.badssl.com -p 443 --sni expired.badssl.com
SSL CERTIFICATE CRITICAL: this certificate expired 2373 day(s) ago. end date is [2015-04-12 23:59:59 +0000 UTC] on expired.badssl.com port 443 sni expired.badssl.com
```

Verify SNI

```
./check_ssl_certificate2  -H badssl.com -p 443 --sni wrong.host.badssl.com --verify-sni
SSL CERTIFICATE CRITICAL: failed verify hostname [x509: certificate is valid for *.badssl.com, badssl.com, not wrong.host.badssl.com] on badssl.com port 443 sni wrong.host.badssl.com
```


