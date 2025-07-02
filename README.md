# 🚀 Universal Email & File Protocol Scanner



Professional-grade multi-threaded network scanner for Email and File protocols with real-time vulnerability detection and comprehensive credential testing.

## ✨ Features

### 🎯 **Multi-Protocol Support**
- 📧 **Email Protocols**: SMTP, POP3, IMAP (including SSL/TLS variants)
- 📁 **File Protocols**: FTP, FTPS, SMB, NetBIOS
- 🌐 **Web Protocols**: HTTP, HTTPS (webmail interface detection)

### 🔍 **Advanced Detection**
- **Service Fingerprinting** - Accurate version detection for 20+ services
- **Anonymous Access Testing** - Automated checks for unauthenticated access
- **Credential Brute Force** - 500+ users, 500+ passwords with smart targeting
- **Vulnerability Scanning** - Detection of misconfigurations and security flaws
- **Data Volume Analysis** - Email count, mailbox size, traffic analysis

### ⚡ **High Performance**
- **Multi-threaded** - Up to 1000 concurrent connections
- **Real-time Results** - Live progress with colored output
- **Smart Rate Limiting** - Adaptive timing to avoid detection
- **Mass Scanning** - Optimized for large target lists (100K+ hosts)

### 📊 **Comprehensive Reporting**
- **Database Storage** - SQLite database with full scan history
- **Multiple Formats** - XML, JSON, and CSV export options
- **Risk Scoring** - Automated risk assessment (0-100 scale)
- **Live Dashboard** - Real-time statistics and progress tracking

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/your-username/universal-protocol-scanner.git
cd universal-protocol-scanner
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan single target (all protocols)
python scanner.py -t 192.168.1.100

# Scan network range
python scanner.py -t 192.168.1.0/24

# Mass scan from file
python scanner.py -f targets.txt --threads 500

# Email protocols only
python scanner.py -f targets.txt --email-only --threads 800

# File protocols only  
python scanner.py -f targets.txt --file-only --threads 600

# Quick scan (no vulnerability checks)
python scanner.py -f targets.txt --quick --threads 1000
```

## 📋 Command Line Options

```
Usage: scanner.py [options]

Target Specification:
  -t, --targets         Target IPs, domains, or CIDR ranges
  -f, --file           File containing targets (one per line)
  -p, --ports          Specific ports to scan

Performance:
  --threads            Number of concurrent threads (default: 100, max: 1000)
  --timeout            Connection timeout in seconds (default: 5)
  --quick              Skip vulnerability and credential checks

Protocol Selection:
  --email-only         Scan only email protocols (SMTP/POP3/IMAP)
  --file-only          Scan only file protocols (FTP/SMB)
  --no-ssl             Skip SSL/TLS ports

Output:
  --verbose, -v        Enable verbose output
  --output-dir         Output directory for reports
  --config             Custom configuration file
```

## 🎯 Target File Format

```
# Single IPs
192.168.1.100
10.0.0.50

# IP ranges
192.168.1.0/24
10.0.0.0/16

# Specific ports
mail.company.com:25,587,993
192.168.1.100:21,445

# Mixed format
fileserver.local:21
192.168.1.0/24
mail.domain.com:25,587,465,110,995,143,993
```

## 🔧 Configuration

The scanner uses `config.yaml` for advanced configuration:

```yaml
# Protocol ports
ports:
  smtp: [25, 465, 587, 2525]
  pop3: [110, 995] 
  imap: [143, 993]
  ftp: [21, 989, 990]
  smb: [445, 139, 135]

# Authentication testing  
authentication:
  test_anonymous: true
  test_weak_creds: true
  max_attempts_per_service: 30
  delay_between_attempts: 0.1

# Performance tuning
performance:
  default_threads: 100
  max_threads: 1000
  connection_timeout: 5
  read_timeout: 8
```

## 📊 Sample Output

```
[15:30:45] 192.168.1.10:21   │ 📁 🔓 ftp          │ vsftpd 3.0.3              │ HIGH:RISK(65)
    ⚠ VULNERABILITIES:
      • Anonymous FTP access enabled
      • Anonymous FTP directory listing enabled
    🔑 WEAK CREDENTIALS:
      • anonymous:<empty>
      • ftp:ftp
    📁 FILE ACCESS:
      • Anonymous FTP access enabled
      • Directory listing available

[15:30:46] 192.168.1.15:25   │ 📧 🔓 smtp         │ Postfix 3.4.13            │ CRITICAL:RISK(85)
    ⚠ VULNERABILITIES:
      • CRITICAL: Open mail relay detected
      • VRFY command enabled - User enumeration possible
    🔑 WEAK CREDENTIALS:
      • postmaster:<empty>
      • admin:password
```

## 🔍 Detected Vulnerabilities

### Email Protocols
- **Open Mail Relay** - SMTP servers accepting external relay
- **User Enumeration** - VRFY/EXPN commands enabled
- **Anonymous Access** - POP3/IMAP without authentication
- **Weak Authentication** - Default/common credentials

### File Protocols  
- **Anonymous FTP** - Unauthenticated file access
- **SMB Null Sessions** - Windows share enumeration
- **Directory Traversal** - Path manipulation vulnerabilities
- **Unrestricted Upload** - File upload capabilities

### Web Protocols
- **Webmail Interfaces** - RoundCube, SquirrelMail, OWA detection
- **Default Credentials** - Admin panel access
- **Information Disclosure** - Version/path leakage

## 📈 Performance Benchmarks

| Target Count | Threads | Avg Rate | Time Estimate |
|-------------|---------|----------|---------------|
| 1,000       | 100     | 45/sec   | ~22 seconds   |
| 10,000      | 300     | 120/sec  | ~1.4 minutes  |
| 50,000      | 500     | 200/sec  | ~4.2 minutes  |
| 100,000     | 800     | 280/sec  | ~6 minutes    |

*Benchmarks may vary based on network conditions and target responsiveness*

## 🛡️ Ethical Usage

This tool is intended for:
- ✅ **Authorized penetration testing**
- ✅ **Security assessments of owned infrastructure**  
- ✅ **Network inventory and asset discovery**
- ✅ **Compliance auditing**
- ✅ **Educational and research purposes**

**⚠️ Important**: Only scan networks and systems you own or have explicit permission to test. Unauthorized scanning may violate laws and regulations.

## 🔧 Requirements

```
Python 3.7+
PyYAML>=6.0
ipaddress (built-in)
threading (built-in)
ssl (built-in)
socket (built-in)
sqlite3 (built-in)
```

## 📁 Project Structure

```
universal-protocol-scanner/
├── scanner.py              # Main scanner script
├── config.yaml            # Configuration file
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── LICENSE                # License file
├── examples/              # Example target files
│   ├── targets_sample.txt
│   └── config_examples/
└── docs/                  # Additional documentation
    ├── USAGE.md
    └── CONFIGURATION.md
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 Known Limitations

- **Windows-specific SSL issues** with very old servers (SSLv2)
- **SMB enumeration** requires additional libraries for deep analysis
- **Large target lists** (1M+) may require memory optimization
- **Rate limiting** by target infrastructure may affect scan speed
- **Some enterprise firewalls** may detect and block scanning activity

## 🐛 Troubleshooting

### Common Issues

**Slow scanning speed:**
```bash
# Reduce threads and increase timeout
python scanner.py -f targets.txt --threads 200 --timeout 8
```

**Connection errors:**
```bash
# Use more conservative settings
python scanner.py -f targets.txt --threads 150 --timeout 10
```

**SSL handshake failures:**
```bash
# Skip SSL ports if problematic
python scanner.py -f targets.txt --no-ssl
```

---

**⚡ Happy Scanning! Remember to scan responsibly.**
