# Contributing to Grype MCP Server

We love your input! We want to make contributing to the Grype MCP Server as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code  
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## 🚀 Development Process

We use GitHub to host code, track issues and feature requests, and accept pull requests.

1. **Fork the repo** and create your branch from `main`
2. **Make your changes** following our coding standards
3. **Add tests** if you've added code that should be tested
4. **Ensure the test suite passes** with `pytest`
5. **Make sure your code lints** with `ruff` and is formatted with `black`
6. **Update documentation** if needed
7. **Sign off your commits** using `git commit --signoff -m 'Awesome commit message'`
8. **Submit a pull request!**

## 🐛 Report Bugs Using GitHub Issues

We use GitHub Issues to track public bugs. Report a bug by [opening a new issue](https://github.com/anchore/grype-mcp/issues/new).

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## 💡 Suggest Features or Enhancements

We welcome feature suggestions! Please:

1. **Check existing issues** to see if someone else has already suggested it
2. **Open a new issue** with the "enhancement" label
3. **Describe the feature** in detail with use cases
4. **Explain why it would be useful** to the community

## 📝 Coding Standards

### Code Style

- **Python 3.10+** compatible code
- **Type hints** for all functions and methods
- **Docstrings** for all public functions using Google style
- **Black** for code formatting (120 character line length)
- **Ruff** for linting

### Commit Messages

Follow conventional commits format:

```
type(scope): description

Examples:
feat(tools): add container image scanning
fix(server): handle grype timeout errors  
docs(readme): update installation instructions
test(tools): add tests for vulnerability search
```

### Testing

- **Write tests** for all new functionality
- **Maintain test coverage** above 80%
- **Use pytest fixtures** for common test data
- **Mock external dependencies** (Grype CLI calls)

Example test structure:

```python
import pytest
from unittest.mock import AsyncMock, patch
from grype_mcp.server import scan_purl

@pytest.mark.asyncio
async def test_scan_purl_success():
    mock_output = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2021-44228", "severity": "critical"},
                "artifact": {"name": "log4j", "version": "2.14.1"}
            }
        ]
    }
    
    with patch('grype_mcp.server.GrypeRunner.run_grype_command', return_value=mock_output):
        result = await scan_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        # Assert expected behavior
```

## 🏗️ Development Environment

See [DEVELOPING.md](DEVELOPING.md) for detailed development setup instructions.

Quick start:

```bash
git clone https://github.com/anchore/grype-mcp.git
cd grype-mcp
uv venv && source .venv/bin/activate
uv sync --all-extras
pytest
```

## 📄 License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## 🎯 Areas We Need Help

### High Priority

- **Performance optimizations** - Caching, async improvements
- **Error handling** - Better error messages and recovery
- **Documentation** - Usage examples, tutorials

### Medium Priority  

- **Container registry auth** - Support for private registries
- **SARIF output** - Alternative output formats
- **Configuration** - User-configurable settings
- **Metrics** - Usage and performance tracking

### Low Priority

- **GUI tools** - Desktop applications
- **Alternative transports** - HTTP, WebSocket support
- **Plugin system** - Extensible architecture

## 🤝 Community Guidelines

### Be Respectful

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community

### Be Collaborative

- Help others learn and grow
- Share knowledge and experience
- Be patient with newcomers
- Assume good intentions

### Code of Conduct

This project adheres to the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## 📞 Getting Help

- **GitHub Discussions** - Ask questions, share ideas
- **GitHub Issues** - Bug reports, feature requests  
- **Anchore Community Discourse** - Join our community channels
- **Documentation** - Check existing docs first

## 🎉 Recognition

Contributors are recognized in:

- **Release notes** for significant contributions
- **Contributors list** in the repository
- **Community highlights** in Anchore communications

## 📋 Pull Request Process

1. **Update documentation** if you change APIs or add features
2. **Update tests** to cover your changes  
3. **Run the full test suite** and ensure it passes
4. **Check code quality** with linting tools
5. **Request review** from maintainers
6. **Address feedback** promptly and professionally
7. **Squash commits** if requested before merge

### PR Template

When opening a PR, please include:

- **What** this PR does
- **Why** this change is needed
- **How** to test the changes
- **Screenshots** if UI changes are involved
- **Breaking changes** if any

## 🔄 Release Process

Releases are managed by maintainers:

1. Version bumped in `pyproject.toml`
2. Changelog updated
3. GitHub release created with notes
4. PyPI package published automatically

## 🏷️ Issue Labels

- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Improvements or additions to docs
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention is needed
- `question` - Further information is requested

Thank you for contributing to the Grype MCP Server! 🙏