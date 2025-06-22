# HunterNG

**Automated Penetration Testing Framework**

HunterNG is a comprehensive, modular penetration testing framework designed to automate reconnaissance, enumeration, and vulnerability assessment workflows for domain and subdomain targets. It provides beautiful HTML reports with detailed findings and AI-powered analysis.

## ✨ Features

- 🔄 **Modular Architecture** - Separate modules for recon, enumeration, assessment, and reporting
- 🤖 **AI-Powered Analysis** - Uses LLM to intelligently select high-value targets for vulnerability testing
- 📊 **Beautiful HTML Reports** - Professional, interactive reports with filtering and categorization
- ⚡ **Pipeline Execution** - Seamless data flow between modules with resume capability
- 🎨 **Rich CLI Interface** - Clean, colorful output with progress tracking
- 🔧 **Flexible Configuration** - YAML-based configuration with target-specific workflows

## 🏗️ Architecture

### Modules

| Module | Description | Key Features |
|--------|-------------|--------------|
| **Reconnaissance** | Information gathering and target analysis | WHOIS, DNS, subdomain enumeration, technology fingerprinting |
| **Enumeration** | Service discovery and content enumeration | Port scanning, directory bruteforcing, hidden parameter discovery |
| **Assessment** | Vulnerability scanning and security testing | Nuclei scanning, XSS detection, AI-powered target selection |
| **Report** | Professional HTML report generation | Interactive dashboards, vulnerability categorization |

### Primary Targets

- **Domains**: `example.com`
- **Subdomains**: `api.example.com`

## 🚀 Quick Start

### Prerequisites

**System Requirements:**
- Python 3.8+
- Linux/macOS (recommended)
- Internet connection for external tools

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/zwng0x/hunterNG.git
cd hunterNG
```

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

3. **Install required external tools:**

#### Core Security Tools
```bash
# Subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# HTTP probing
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# URL discovery
go install github.com/lc/gau/v2/cmd/gau@latest

# Web crawling
go install github.com/projectdiscovery/katana/cmd/katana@latest

# URL deduplication
go install github.com/s0md3v/uro@latest

# Directory bruteforcing
sudo apt install gobuster

# Vulnerability scanning
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# XSS scanning
go install github.com/hahwul/dalfox/v2@latest

# Parameter discovery
pipx install arjun

# Technology identification
sudo apt install whatweb
npm install -g wappalyzer-cli
```

#### Wordlists
```bash
# Install common wordlists
sudo apt install dirb
sudo apt install seclists
```

4. **Set up API keys (for AI features):**
```bash
export OPENAI_API_KEY="your_openai_api_key_here"
```

5. **Run nuclei template update:**
```bash
nuclei -update-templates
```

### Basic Usage

**Simple scan:**
```bash
python hunter.py -t example.com
```

**Scan subdomain:**
```bash
python hunter.py -t api.example.com
```

**Custom output directory:**
```bash
python hunter.py -t example.com -o my_scan_results
```

**Run only specific modules:**
```bash
python hunter.py -t example.com --only recon enumeration
```

**Skip specific modules:**
```bash
python hunter.py -t example.com --skip assessment
```

**Resume previous scan:**
```bash
python hunter.py --resume /path/to/previous/scan/directory
```

**Analyze target without scanning:**
```bash
python hunter.py -t example.com --analyze
```

## 📋 Usage Examples

### Target Analysis
```bash
# Analyze what HunterNG will do for your target (in development)
python hunter.py -t api.example.com --analyze
```

### Domain-Focused Scanning
```bash
# Focus on specific domain only (no subdomain discovery)
python hunter.py -t example.com --focus-domain
```

### Custom Workflows
```bash
# Custom pipeline order
python hunter.py -t example.com --pipeline recon assessment report

# Verbose output
python hunter.py -t example.com -v
```

### Resume Capabilities
```bash
# Resume from previous scan
python hunter.py --resume ./output/example_com_20241220120000

# Resume with different target (override)
python hunter.py --resume ./output/example_com_20241220120000 -t newexample.com
```

## 🔧 Configuration

### Main Configuration (`config/default_config.yaml`)

```yaml
general:
  default_output_directory: "output"
  verbose: false
  show_sample_count: 5

recon:
  subfinder:
    enabled: true
    command: "subfinder -silent -d {target}"
    timeout: 60
  
  httpx:
    enabled: true
    command: "httpx -mc 200,301,302,403 -threads 50"
    timeout: 60
```

### Workflow Configuration (`config/workflow_config.yaml`)

Defines which tasks run for domain and subdomain targets: (in development)

```yaml
domain:
  recon_config:
    whois: true
    enum_subdomains: true
    identify_tech: true
  enumeration_config:
    nmap: true
    content_discovery: true
  assessment_config:
    vuln_scan: true

subdomain:
  recon_config:
    whois: false
    enum_subdomains: false
    identify_tech: true
  enumeration_config:
    nmap: true
    content_discovery: true
  assessment_config:
    vuln_scan: true
```

## 📊 Output Structure

```
output/
└── example_com_20241220120000/
    ├── global_state.json
    ├── recon/
    │   ├── results.json
    │   ├── subdomains.txt
    │   ├── live_hosts.txt
    │   ├── suspicious_url.txt
    │   └── whatweb.txt
    ├── enumeration/
    │   ├── results.json
    │   ├── nmap.txt
    │   ├── content_discovery.txt
    │   └── hidden_param.txt
    ├── assessment/
    │   ├── results.json
    │   ├── nuclei.txt
    │   ├── sqli_candidates.txt
    │   ├── xss_candidates.txt
    │   └── llm_candidates.txt
    └── report/
        ├── recon.html
        ├── enumeration.html
        ├── assessment.html
        └── wappalyzer.html
```

## 🎨 Report Features

The HTML reports include:

- **Interactive Navigation** - Switch between modules seamlessly
- **Vulnerability Categorization** - Organized by severity and type
- **Filtering and Search** - Filter suspicious URLs by risk type
- **Copy-to-Clipboard** - Easy copying of URLs and findings
- **Responsive Design** - Works on desktop and mobile
- **Professional Styling** - Clean, modern interface

### Report Sections

#### Reconnaissance Report
- Target overview and WHOIS information
- DNS analysis and subdomain discovery
- Technology stack identification
- URL discovery with suspicious URL highlighting

#### Enumeration Report
- Network port scanning results
- Content discovery findings
- Hidden parameter detection

#### Assessment Report
- Security status overview with scoring
- Vulnerability statistics and categorization
- AI-selected priority targets
- Detailed vulnerability findings by category

## 🤖 AI Integration

HunterNG uses OpenAI's API to:

1. **Intelligent Target Selection** - AI analyzes discovered URLs and selects the top 10 most likely to be vulnerable
2. **Priority Ranking** - Considers parameter names, path structure, and security relevance
3. **LLM Model** - Default model is GPT-4.1-mini

**AI Selection Criteria:**
- Multiple parameters
- Suspicious parameter names (id, user, token, admin, etc.)
- Unusual or deeply nested paths
- Parameters with interesting values


## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper permission before scanning any targets. The authors are not responsible for any misuse or damage caused by this tool.

## 🙏 Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) - For excellent security tools
- [OWASP](https://owasp.org) - For security methodology guidance
- [SecLists](https://github.com/danielmiessler/SecLists) - For comprehensive wordlists

---

**HunterNG** - Making penetration testing more intelligent and efficient! 🚀
