# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ Current release |

## Reporting a Vulnerability

We take the security of ResiMantle seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities.
2. Email your findings to: **security@resimantle.dev** (or open a private security advisory on GitHub).
3. Include as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Assessment**: Within 7 days, we will assess the severity
- **Fix timeline**: Critical issues within 14 days, others within 30 days
- **Credit**: We will credit you in the release notes (unless you prefer anonymity)

### Scope

The following are in scope:
- The ResiMantle core library (`@resimantle/core`)
- The ResiMantle CLI (`resimantle`)
- Official plugins and integrations
- Documentation that could lead to insecure configurations

The following are out of scope:
- Third-party dependencies (report these to the respective maintainers)
- Issues in projects that ResiMantle is protecting (those are the project owner's responsibility)

## Security Best Practices

When using ResiMantle:
- Keep ResiMantle updated to the latest version
- Review generated policies before deploying to production
- Never commit your `.resimantle/` directory if it contains sensitive behavioral data
- Use environment variables for any sensitive configuration

## Ethical Commitment

ResiMantle is a defensive tool. We will never:
- Include offensive capabilities
- Generate functional exploits
- Facilitate unauthorized access
- Collect user data without consent

See our [Ethics Documentation](docs/ethics.md) for more details.
