# Support Guide

Thank you for using Cyber-Zero! This guide will help you get the support you need.

## Getting Help

### 📚 Documentation

Start with our comprehensive documentation:

- **[README.md](README.md)** - Quick start guide and overview
- **[Installation Guide](README.md#installation)** - Setup instructions
- **[Architecture](README.md#architecture)** - Understanding the framework
- **[Configuration](README.md#configuration)** - Customizing settings

### 🐛 Reporting Issues

Before reporting an issue, please:

1. **Check existing issues** - Search [GitHub issues](https://github.com/amazon-science/cyber-zero/issues) to see if your problem has already been reported
2. **Use the issue template** - Follow the provided template for bug reports
3. **Include details** - Provide as much information as possible

#### Issue Template

When creating a new issue, please include:

```markdown
**Description**
Brief description of the problem

**Steps to Reproduce**
1. Step 1
2. Step 2
3. Step 3

**Expected Behavior**
What you expected to happen

**Actual Behavior**
What actually happened

**Environment**
- OS: [e.g., Ubuntu 20.04, macOS 12.0]
- Python version: [e.g., 3.8.10]
- Cyber-Zero version: [e.g., 0.1.0]
- Dependencies: [output of `pip list`]

**Additional Context**
Any other relevant information, logs, screenshots, etc.
```

### 💬 Community Support

- **GitHub Discussions**: [Start a discussion](https://github.com/amazon-science/cyber-zero/discussions) for questions and general help
- **GitHub Issues**: For bug reports and feature requests
- **Email**: For private or sensitive matters

### 🔧 Common Issues

#### Installation Problems

**Problem**: `pip install` fails
**Solution**: 
- Ensure Python 3.8+ is installed
- Try: `pip install --upgrade pip`
- Check your Python environment

**Problem**: Import errors
**Solution**:
- Verify installation: `pip show cyber-zero`
- Check Python path: `python -c "import cyber_zero"`

#### Runtime Issues

**Problem**: LLM API errors
**Solution**:
- Check your API keys are set correctly
- Verify your LLM provider is supported
- Check API rate limits and quotas

**Problem**: Memory issues during generation
**Solution**:
- Reduce `--workers` parameter
- Process smaller batches
- Increase system memory if possible

**Problem**: Quality evaluation fails
**Solution**:
- Check model availability
- Verify input format
- Ensure sufficient API credits

### 🚀 Performance Tips

1. **Parallel Processing**: Use `--workers` parameter for faster generation
2. **Batch Processing**: Process multiple tasks together
3. **Model Selection**: Choose appropriate models for your use case
4. **Caching**: Reuse generated trajectories when possible

### 📊 Troubleshooting

#### Debug Mode

Enable debug logging:

```bash
export PYTHONPATH=.
python -u generate_trajectory.py --debug --sampled_flags_path data.jsonl
```

#### Check Dependencies

```bash
pip list | grep -E "(litellm|tqdm|transformers)"
```

#### Validate Configuration

```python
from cyber_zero import Config
config = Config()
print(config.models.MODEL_MAPPINGS)
```

### 🔒 Security Support

For security-related issues:

- **Do NOT** create public GitHub issues
- **Email**: [opensource-security@amazon.com](mailto:opensource-security@amazon.com)
- See [SECURITY.md](SECURITY.md) for details

### 📈 Feature Requests

We welcome feature requests! Please:

1. Check if the feature is already planned
2. Describe the use case clearly
3. Explain the expected benefit
4. Consider contributing the feature

### 🤝 Contributing

Want to help improve Cyber-Zero?

- Read [CONTRIBUTING.md](CONTRIBUTING.md)
- Check [open issues](https://github.com/amazon-science/cyber-zero/issues)
- Join discussions in [GitHub Discussions](https://github.com/amazon-science/cyber-zero/discussions)

### 📞 Contact Information

- **General Support**: [GitHub Issues](https://github.com/amazon-science/cyber-zero/issues)
- **Security Issues**: [opensource-security@amazon.com](mailto:opensource-security@amazon.com)
- **Community**: [GitHub Discussions](https://github.com/amazon-science/cyber-zero/discussions)
- **Documentation**: [README.md](README.md)

### 🎯 Quick Links

- [Installation](README.md#installation)
- [Quick Start](README.md#quick-start)
- [Configuration](README.md#configuration)
- [CLI Reference](README.md#cli-interface)
- [Architecture](README.md#architecture)
- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

Thank you for using Cyber-Zero! We're here to help you succeed with your cybersecurity research. 