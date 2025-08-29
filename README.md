# Grype MCP Server

[![PyPI version](https://img.shields.io/pypi/v/grype-mcp.svg)](https://pypi.org/project/grype-mcp/)
[![Python Support](https://img.shields.io/pypi/pyversions/grype-mcp.svg)](https://pypi.org/project/grype-mcp/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Anchore MCP server for Grype vulnerability scanner**

Integrate [Grype](https://github.com/anchore/grype) vulnerability scanning directly into AI-assisted development workflows through the Model Context Protocol (MCP).

## 🚀 Quick Start

### Installation

Install using uvx (recommended):
```bash
uvx grype-mcp
```

Or using pipx:
```bash
pipx install grype-mcp
```

Or using pip:
```bash
pip install grype-mcp
```

### MCP Client Setup

#### Claude Desktop
Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "grype": {
      "command": "uvx",
      "args": ["grype-mcp"]
    }
  }
}
```

#### Other MCP Clients
For other MCP-compatible clients, add the server using:
- Command: `uvx`
- Args: `["grype-mcp"]`

Start using Grype's vulnerability scanning capabilities!

## 🛠️ Available Tools

The Grype MCP server provides these tools for AI assistants:

### System Management
- **`find_grype`** - Check if Grype is installed and get version info
- **`update_grype`** - Install or update Grype to the latest version
- **`get_db_info`** - Get vulnerability database status and version info
- **`update_db`** - Update the vulnerability database

### Vulnerability Scanning
- **`scan_dir`** - Scan project directories for vulnerabilities  
- **`scan_purl`** - Scan specific packages using PURL format (e.g., `pkg:npm/lodash@4.17.20`)
- **`scan_image`** - Scan container images for vulnerabilities

### Vulnerability Research
- **`search_vulns`** - Search the vulnerability database by CVE, package name, or CPE
- **`get_vuln_details`** - Get detailed information about specific CVEs

## 💡 Example Usage

Once configured, you can ask:

- *"Check if Grype is installed and up to date"*
- *"Scan my project directory for vulnerabilities"*  
- *"Is pkg:npm/lodash@4.17.20 vulnerable?"*
- *"Scan the nginx:latest Docker image"*
- *"Search for Log4j vulnerabilities"*
- *"Get details about CVE-2021-44228"*

## 🔧 Requirements

- **Python 3.10+**
- **Grype** (can be installed via the `update_grype` tool)
- **Docker** (optional, for container image scanning)

The MCP server can help install Grype if it's not already available using the `update_grype` tool.

## 📋 Supported Scanning Targets

- **Directories** - Scan entire projects with all their dependencies
- **Container Images** - Docker images from any registry
- **Package URLs** - Individual packages in PURL format
  - npm: `pkg:npm/package@version`
  - Python: `pkg:pypi/package@version`  
  - Go: `pkg:golang/package@version`
  - Java: `pkg:maven/group/artifact@version`
  - And many more ecosystems

## 🏗️ Architecture

The MCP server acts as a bridge between AI assistants and Grype:

```
AI Assistant ↔ MCP Server ↔ Grype CLI ↔ Vulnerability Database
```

- **Zero modifications** to Grype required
- **Structured JSON responses** optimized for AI consumption
- **Comprehensive error handling** with helpful messages
- **Automatic tool management** for easy setup

## 🤝 Contributing

We welcome contributions! Please see:

- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [DEVELOPING.md](DEVELOPING.md) - Development setup
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Community standards

## 📄 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## 🔗 Related Projects

- [Grype](https://github.com/anchore/grype) - Vulnerability scanner for container images and filesystems
- [Syft](https://github.com/anchore/syft) - SBOM generation tool
- [Model Context Protocol](https://modelcontextprotocol.io/) - Open protocol for AI assistant integrations
- [Anchore Enterprise](https://anchore.com/platform) - Commercial SBOM-powered security platform

## 📞 Support

- [GitHub Issues](https://github.com/anchore/grype-mcp/issues) - Bug reports and feature requests
- [Anchore Community Discourse](https://anchore.com/discourse/) - Community support and discussions
- [Documentation](https://github.com/anchore/grype-mcp#readme) - Full documentation

---

**Made with ❤️ by the Anchore team for the AI-assisted development community**