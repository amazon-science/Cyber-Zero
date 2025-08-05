# Contributing to Cyber-Zero

Thank you for your interest in contributing to Cyber-Zero! This document provides guidelines and information for contributors.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)
- [Code of Conduct](#code-of-conduct)

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your feature or fix
4. Make your changes
5. Test your changes
6. Submit a pull request

## Development Setup

### Prerequisites

- Python 3.8+
- pip
- git

### Installation

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/cyber-zero.git
cd cyber-zero

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .
```

## Code Style

We follow PEP 8 style guidelines for Python code. Please ensure your code:

- Uses 4 spaces for indentation
- Has a maximum line length of 88 characters
- Includes proper docstrings for functions and classes
- Uses type hints where appropriate

### Pre-commit Hooks

We recommend using pre-commit hooks to ensure code quality:

```bash
pip install pre-commit
pre-commit install
```

## Testing

Before submitting changes, please ensure:

1. All existing tests pass
2. New tests are added for new functionality
3. Code coverage is maintained or improved

Run tests with:

```bash
python -m pytest tests/
```

## Submitting Changes

1. **Create a feature branch**: `git checkout -b feature/your-feature-name`
2. **Make your changes**: Write your code and tests
3. **Commit your changes**: Use clear, descriptive commit messages
4. **Push to your fork**: `git push origin feature/your-feature-name`
5. **Create a pull request**: Provide a clear description of your changes

### Commit Message Format

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Examples:
- `feat(trajectory): add support for new CTF challenge types`
- `fix(evaluation): resolve quality scoring bug`
- `docs(readme): update installation instructions`

## Reporting Issues

When reporting issues, please include:

1. **Description**: Clear description of the problem
2. **Steps to reproduce**: Detailed steps to reproduce the issue
3. **Expected behavior**: What you expected to happen
4. **Actual behavior**: What actually happened
5. **Environment**: OS, Python version, package versions
6. **Additional context**: Any other relevant information

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Questions?

If you have questions about contributing, please:

1. Check the [documentation](README.md)
2. Search existing [issues](https://github.com/amazon-science/cyber-zero/issues)
3. Create a new issue if your question isn't answered

Thank you for contributing to Cyber-Zero! 