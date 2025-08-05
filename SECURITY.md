# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take the security of Cyber-Zero seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Reporting Process

1. **Do not create a public GitHub issue** for the vulnerability
2. **Email us directly** at [opensource-security@amazon.com](mailto:opensource-security@amazon.com)
3. **Include detailed information** about the vulnerability:
   - Description of the issue
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Include in Your Report

Please provide as much information as possible:

- **Type of issue**: Buffer overflow, SQL injection, XSS, etc.
- **Component**: Which part of the codebase is affected
- **Version**: Version of Cyber-Zero where you found the issue
- **Environment**: OS, Python version, dependencies
- **Proof of concept**: Code or steps to reproduce
- **Impact assessment**: How this could be exploited

### Response Timeline

- **Initial response**: Within 48 hours
- **Status update**: Within 1 week
- **Resolution**: Depends on complexity and severity

### Disclosure Policy

- We will acknowledge receipt of your report within 48 hours
- We will keep you informed of our progress
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- We will coordinate disclosure with you

### Responsible Disclosure

We ask that you:

- Give us reasonable time to respond to issues before any disclosure
- Make a good faith effort to avoid privacy violations, destruction of data, and interruption of service
- Not exploit a security issue you discover for any reason

### Security Best Practices

When using Cyber-Zero:

1. **Keep dependencies updated**: Regularly update your Python packages
2. **Use secure LLM providers**: Ensure your LLM API keys are properly secured
3. **Validate inputs**: Always validate and sanitize any user inputs
4. **Monitor API usage**: Keep track of your LLM API usage and costs
5. **Secure configuration**: Store sensitive configuration in environment variables

### Security Features

Cyber-Zero includes several security features:

- **Input validation**: Comprehensive validation of all inputs
- **Error handling**: Secure error handling that doesn't leak sensitive information
- **Type safety**: Type hints and validation to prevent type-related vulnerabilities
- **Secure defaults**: Secure configuration defaults

### Contact Information

For security-related issues:

- **Email**: [opensource-security@amazon.com](mailto:opensource-security@amazon.com)
- **PGP Key**: [Available upon request]

For general support and non-security issues, please use the regular [GitHub issues](https://github.com/amazon-science/cyber-zero/issues).

Thank you for helping keep Cyber-Zero secure! 