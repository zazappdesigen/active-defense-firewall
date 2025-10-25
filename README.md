# Active Defense Firewall System

**An advanced network security solution with intelligent threat detection and active counter-attack capabilities**

## Overview

The Active Defense Firewall System is a next-generation network security platform that goes beyond traditional firewalls, antivirus software, and VPNs by combining **defensive protection** with **active counter-attack** mechanisms. This system provides comprehensive network security through stateful packet inspection, deep packet inspection, intrusion detection and prevention, behavioral analysis, and automated threat response.

## Key Features

### Core Protection

**Stateful Packet Filtering Engine**
- Real-time packet inspection with connection state tracking
- Deep packet inspection (DPI) for payload analysis
- Protocol validation and anomaly detection
- Intelligent rate limiting and connection management
- Support for custom filtering rules with priority ordering

**Intrusion Detection & Prevention System (IDPS)**
- Signature-based threat detection with 10+ built-in threat patterns
- Anomaly-based detection using behavioral analysis
- Machine learning-ready architecture for adaptive threat recognition
- Real-time blocking of detected threats
- Automatic threat scoring and classification

### Active Defense Capabilities

**Adaptive IP Blocking**
- Dynamic blocklisting with severity-based expiration
- Permanent blocking for critical threats
- Automatic cleanup of expired blocks
- Support for both temporary and permanent bans

**Honeypot Integration**
- Deployable decoy services (SSH, HTTP, FTP)
- Automatic attacker profiling and data collection
- Trap-and-analyze approach for threat intelligence
- Multi-port honeypot support

**Counter-Attack Mechanisms**
- Automated port scanning of attackers
- Traffic redirection to honeypots
- Threat reporting to global databases (AbuseIPDB integration)
- Aggressive rate limiting for malicious sources
- Black-hole routing for severe threats

**Threat Intelligence**
- Real-time threat scoring system
- Historical attack tracking per IP
- Automated threat classification
- Export capabilities for threat data sharing

### Management Dashboard

**Web-Based Interface**
- Real-time threat monitoring with live statistics
- Visual threat distribution by severity and category
- Blocked IP management with unblock functionality
- Firewall rule configuration interface
- Active connection monitoring
- Counter-attack action logs
- Honeypot connection viewer
- System configuration panel

**Authentication & Security**
- Manus OAuth integration for secure access
- Role-based access control (admin/user)
- Session management with JWT tokens
- Secure API endpoints with tRPC

## Architecture

### System Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Packet Engine | Python 3.11 + asyncio | High-performance packet processing |
| Network Interface | iptables/nftables | Kernel-level packet filtering |
| Threat Detection | Pattern matching + ML | Signature and anomaly-based detection |
| Active Defense | Python + subprocess | Counter-attack orchestration |
| Web Dashboard | React 19 + tRPC + Express | Management interface |
| Database | MySQL/TiDB | Threat logs and configuration |
| Authentication | Manus OAuth | Secure user access |

### Security Layers

The system implements defense-in-depth with five security layers:

1. **Network Layer**: Packet filtering, rate limiting, protocol validation
2. **Transport Layer**: Connection tracking, state management, port security
3. **Application Layer**: Deep packet inspection, content filtering
4. **Intelligence Layer**: Threat scoring, behavioral analysis, ML detection
5. **Response Layer**: Automated blocking, counter-attacks, threat reporting

## Installation & Deployment

### Prerequisites

- Linux server (Ubuntu 22.04 recommended)
- Python 3.11+
- Node.js 22+
- MySQL/TiDB database
- Root/sudo privileges for iptables configuration

### Quick Start

**1. Clone the Repository**

```bash
git clone https://github.com/yourusername/active-defense-firewall.git
cd active-defense-firewall
```

**2. Install Python Dependencies**

```bash
pip3 install -r requirements.txt
```

**3. Configure Network Interface**

```bash
# Set up iptables rules (requires root)
sudo python3 core/network_interface.py
```

**4. Deploy Web Dashboard**

The web dashboard is located in the `firewall-dashboard` directory and uses the Manus platform for deployment.

```bash
cd firewall-dashboard
pnpm install
pnpm db:push  # Initialize database
pnpm dev      # Development mode
```

For production deployment, use the Manus platform's publish feature after creating a checkpoint.

### Configuration

**System Configuration**

The firewall can be configured through the web dashboard or by directly modifying configuration files:

- **Firewall Rules**: Define in the web interface or database
- **Threat Signatures**: Customize in `detection/threat_detector.py`
- **Active Defense Settings**: Configure in `defense/active_defense.py`
- **Rate Limits**: Adjust in `core/packet_engine.py`

**Environment Variables**

For the web dashboard, the following environment variables are automatically configured:

- `DATABASE_URL`: Database connection string
- `JWT_SECRET`: Session signing secret
- `VITE_APP_TITLE`: Dashboard title
- OAuth credentials (auto-configured)

## Usage

### Running the Firewall Engine

**Start Packet Filtering**

```bash
sudo python3 -m core.packet_engine
```

**Deploy Honeypots**

```python
from defense.active_defense import ActiveDefenseSystem

defense = ActiveDefenseSystem()
defense.deploy_honeypot(2222, 'ssh')
defense.deploy_honeypot(8080, 'http')
```

**Enable Active Defense**

```python
defense.auto_counter_attack = True
defense.aggressive_mode = True  # Enable counter-scanning
defense.report_threats = True   # Report to threat databases
```

### Using the Web Dashboard

1. **Access the Dashboard**: Navigate to your deployed URL
2. **Login**: Use Manus OAuth to authenticate
3. **Monitor Threats**: View real-time threat detection on the Dashboard page
4. **Manage Blocked IPs**: Review and unblock IPs from the Blocked IPs page
5. **Configure Rules**: Add custom firewall rules in the Firewall Rules section
6. **View Connections**: Monitor active network connections
7. **Review Counter-Attacks**: Check automated response actions
8. **Analyze Honeypots**: Examine captured attacker data

## Advantages Over Traditional Solutions

### vs. Antivirus Software

| Feature | Traditional Antivirus | Active Defense Firewall |
|---------|----------------------|------------------------|
| Protection Scope | Endpoint only | Network-wide |
| Zero-Day Defense | Limited | Behavioral analysis |
| Response Time | After infection | Before reaching endpoint |
| Active Response | None | Automated counter-attacks |
| Threat Intelligence | Vendor-dependent | Self-learning + external feeds |

### vs. VPN

| Feature | VPN | Active Defense Firewall |
|---------|-----|------------------------|
| Protection Direction | Outbound privacy | Bidirectional security |
| Threat Detection | None | Real-time IDS/IPS |
| Attack Prevention | None | Active blocking |
| Visibility | Encrypted tunnel | Full traffic inspection |
| Counter-Measures | None | Honeypots + counter-attacks |

### vs. Traditional Firewalls

| Feature | Traditional Firewall | Active Defense Firewall |
|---------|---------------------|------------------------|
| Inspection Depth | Basic packet filtering | Deep packet inspection |
| Threat Detection | Rule-based only | Signature + anomaly + ML |
| Response | Block only | Block + counter-attack + report |
| Intelligence | Static rules | Dynamic threat scoring |
| Honeypots | None | Integrated |

## Security Considerations

**Ethical Use**

This system includes offensive security capabilities such as port scanning and traffic manipulation. Users must:

- Comply with all applicable laws and regulations
- Only deploy on networks they own or have authorization to protect
- Use counter-attack features responsibly
- Respect privacy and data protection requirements

**Limitations**

- Requires root privileges for iptables manipulation
- Port scanning may trigger security alerts on target networks
- Honeypots may attract additional unwanted attention
- Active defense should be carefully configured to avoid false positives

## Project Structure

```
active-defense-firewall/
├── core/                      # Core firewall engine
│   ├── packet_engine.py       # Packet filtering and inspection
│   └── network_interface.py   # Network interface and iptables
├── detection/                 # Threat detection
│   └── threat_detector.py     # IDS/IPS implementation
├── defense/                   # Active defense
│   └── active_defense.py      # Counter-attack mechanisms
├── web/                       # Web dashboard (legacy)
├── firewall-dashboard/        # Modern web dashboard
│   ├── client/                # React frontend
│   ├── server/                # Express + tRPC backend
│   └── drizzle/               # Database schema
├── config/                    # Configuration files
├── logs/                      # System logs
└── data/                      # Threat intelligence data
```

## Database Schema

The system uses MySQL/TiDB with the following key tables:

- **firewall_rules**: Custom filtering rules
- **blocked_ips**: Blocked IP addresses with expiration
- **threat_events**: Detected security threats
- **active_connections**: Current network connections
- **counter_attack_actions**: Automated response logs
- **honeypot_connections**: Captured attacker data
- **system_config**: System configuration

## API Reference

### tRPC Endpoints

**Firewall Management**
- `firewall.getRules`: List all firewall rules
- `firewall.createRule`: Add new rule
- `firewall.updateRule`: Modify existing rule
- `firewall.deleteRule`: Remove rule

**Blocklist Management**
- `blocklist.getAll`: Get all blocked IPs
- `blocklist.getActive`: Get currently active blocks
- `blocklist.blockIp`: Block an IP address
- `blocklist.unblockIp`: Remove IP from blocklist

**Threat Intelligence**
- `threats.getRecent`: Fetch recent threat events
- `threats.getByIp`: Get threats from specific IP
- `threats.getStatistics`: Threat distribution stats

**System Monitoring**
- `connections.getActive`: List active connections
- `counterAttacks.getRecent`: View counter-attack logs
- `honeypot.getConnections`: Honeypot capture data

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Implement your changes with tests
4. Submit a pull request with detailed description

## License

This project is provided for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations.

## Support

For issues, questions, or feature requests, please open an issue on GitHub or contact the development team.

## Acknowledgments

This system incorporates security research and best practices from:

- OWASP (Open Web Application Security Project)
- MITRE ATT&CK Framework
- Common Vulnerabilities and Exposures (CVE) database
- Security community threat intelligence feeds

---

**Built with ❤️ by Manus AI**

*Protecting networks through intelligent defense and active response*

