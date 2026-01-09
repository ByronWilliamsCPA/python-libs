# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Email the maintainer directly at: <byronawilliams@gmail.com>
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: Next release

## Security Best Practices

When using this library:

### API Key Security

- **Never** commit your `GEMINI_API_KEY` to version control
- Use environment variables or `.env` files (with `.gitignore`)
- Rotate API keys periodically
- Use separate keys for development and production

### Output Security

- Generated images may contain embedded metadata
- Review generated content before public distribution
- Be aware of prompt injection risks in user-provided prompts

### Dependencies

This package depends on:

- `google-genai`: Official Google Gemini SDK
- `tenacity`: Retry logic (no security-sensitive code)
- `structlog`: Structured logging

We monitor dependencies for known vulnerabilities using:

- GitHub Dependabot
- Safety check in CI/CD

## Acknowledgments

We appreciate responsible disclosure of security issues. Contributors who report
valid security vulnerabilities will be acknowledged (unless they prefer to remain
anonymous).
