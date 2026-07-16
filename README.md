# Password Strength API

Score passwords (0-4), estimate crack time, and generate strong passwords or passphrases. Passwords never logged. Zero-key.

**Live:** https://password-strength.techtenstein.com
**Docs:** https://password-strength.techtenstein.com/
**OpenAPI:** https://password-strength.techtenstein.com/openapi.json

## Endpoints
- GET /check?password=hunter2
- GET /generate?length=24&symbols=true&count=3
- GET /passphrase?words=5

## Example
```bash
curl https://password-strength.techtenstein.com/openapi.json
```

## Features
- Free, no API key
- CORS enabled
- OpenAPI 3.1 spec
- MIT licensed

Built with Cloudflare Workers.
