# Devlin - Local Pentesting Automation Tool

A comprehensive, local-only pentesting automation tool for Kali Linux, inspired by BloodHound but covering the entire pentest lifecycle.

## 🚀 Quick Start

```bash
./run.sh
```

This single command will:
- Start the FastAPI backend on port 8000
- Launch the React frontend on port 3000
- Open the GUI at http://localhost:3000

## ✨ Features

### Core Capabilities
- **Nmap Scan Engine**: Automated network discovery and service enumeration
- **AI-Powered Analysis**: Multi-provider AI integration (OpenAI, Claude, DeepSeek, Ollama)
- **Service Fingerprinting**: Automated CVE lookup and vulnerability assessment
- **Recon Modules**: Subdomain enumeration, directory fuzzing, technology detection
- **Exploit Helper**: Metasploit RPC integration with AI-guided exploitation
- **Real-time Reporting**: Live updates and comprehensive PDF/HTML reports

### Security & Privacy
- **100% Local**: Runs entirely on Kali Linux, offline-capable
- **Encrypted Storage**: SQLCipher-encrypted SQLite database
- **Secure API**: Token-based authentication for local endpoints
- **Stealth Mode**: Configurable scan aggressiveness and timing

## 🏗️ Architecture

```
devlin/
├── backend/           # FastAPI backend with WebSocket support
├── frontend/          # React.js dark-themed UI
├── modules/           # Modular tool integrations
├── data/             # Local encrypted database and scan results
├── templates/        # Report templates
├── run.sh           # Single-command startup script
└── settings.json    # Configuration file
```

## 📋 Requirements

- Kali Linux 2025+
- Python 3.9+
- Node.js 16+
- Standard Kali tools (nmap, metasploit, etc.)

## 🔧 Configuration

1. Copy `settings.example.json` to `settings.json`
2. Configure your AI provider API keys
3. Adjust tool paths if needed
4. Set your encryption key for the database

## 🎯 Usage

### Basic Workflow
1. **Target Setup**: Add target IP ranges or domains
2. **Discovery**: Run Nmap scans with AI analysis
3. **Reconnaissance**: Automated subdomain/directory enumeration
4. **Vulnerability Assessment**: CVE lookup and risk ranking
5. **Exploitation**: Metasploit integration with AI guidance
6. **Reporting**: Generate comprehensive reports

### Scan Types
- **Quick Scan**: `nmap -T4 -F` - Fast port discovery
- **Aggressive Scan**: `nmap -A` - Comprehensive service detection
- **Top Ports**: `nmap --top-ports 100` - Common services
- **Full TCP**: `nmap -p-` - Complete port range

## 🤖 AI Integration

Devlin uses AI for:
- **Service Analysis**: Identify services and suggest next steps
- **Vulnerability Explanation**: Technical and layman explanations
- **Attack Path Planning**: Strategic penetration testing guidance
- **Command Generation**: Automated tool execution
- **Report Generation**: Human-readable findings summaries

## 🛡️ Security Considerations

- All data stored locally with encryption
- No external data transmission (except optional AI APIs)
- Configurable stealth mode for operational security
- Token-based API authentication
- Audit logging for all actions

## 📊 Reporting

- **Real-time Dashboard**: Live scan progress and findings
- **Interactive Graphs**: Attack path visualization
- **Export Formats**: PDF, HTML, JSON
- **Custom Templates**: Configurable report layouts

## 🔌 Extensibility

Devlin is designed to be modular:
- Easy integration of new tools
- Plugin architecture for custom modules
- Configurable AI prompts and workflows
- Custom report templates

## 🐛 Troubleshooting

### Common Issues
- **Port conflicts**: Ensure ports 3000 and 8000 are available
- **Tool paths**: Verify tool locations in settings.json
- **Permissions**: Run with appropriate privileges for network scanning
- **Dependencies**: Install missing Python/Node packages

### Logs
- Backend logs: Check console output
- Frontend logs: Browser developer console
- Scan logs: `./data/scans/` directory

## 📝 License

This tool is for authorized penetration testing only. Users are responsible for compliance with applicable laws and regulations.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

**⚠️ Disclaimer**: This tool is intended for authorized security testing only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.
