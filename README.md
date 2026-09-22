# Active Defense Firewall System

Production-focused Python firewall engine for packet filtering, threat detection, privacy policy enforcement, and controlled defensive response.

## Scope

This repository currently ships **only the Python firewall engine** found in:

- `/home/runner/work/active-defense-firewall/active-defense-firewall/core`
- `/home/runner/work/active-defense-firewall/active-defense-firewall/detection`
- `/home/runner/work/active-defense-firewall/active-defense-firewall/defense`
- `/home/runner/work/active-defense-firewall/active-defense-firewall/firewall_system.py`

It does **not** include a production web dashboard, database-backed control plane, or remote management service.

## Production posture

The runtime defaults are intentionally conservative:

- local blocking is enabled
- aggressive counter-attack is disabled by default
- external threat reporting is disabled by default
- traffic privacy enforcement is enabled by default

Any higher-risk response behavior must be explicitly configured.

## Features

### Packet filtering

- stateful connection tracking
- IP and CIDR based rules
- rate limiting and connection limiting
- packet parsing for TCP, UDP, and generic IP payloads

### Threat detection

- signature-based inspection for common exploit payloads
- anomaly detection for port scans, auth-targeted connection bursts, and traffic floods
- per-source threat scoring with automatic block decisions

### Defensive response

- adaptive temporary and permanent blocklists
- optional honeypot redirection
- optional external reporting
- cooldowns to prevent repeated escalations against the same source

### Privacy enforcement

- blocking of unencrypted DNS by policy
- blocking of unencrypted outbound traffic on known plaintext ports
- scanning-exfiltration pattern detection

## Runtime entrypoints

Primary entrypoint:

```bash
python -m active_defense_firewall
```

Direct script entrypoint:

```bash
python firewall_system.py
```

## Installation

### Requirements

- Linux
- Python 3.10+
- root privileges for live capture and iptables management

### Install dependencies

```bash
pip install -r requirements.txt
pip install pytest
```

## Configuration

The firewall reads JSON configuration from:

- `--config /absolute/path/to/config.json`, or
- `FIREWALL_CONFIG=/absolute/path/to/config.json`

Example:

```json
{
  "interface": "eth0",
  "max_connections_per_ip": 100,
  "max_packets_per_second": 1000,
  "auto_block": true,
  "block_threshold": 50.0,
  "auto_counter_attack": false,
  "aggressive_mode": false,
  "report_threats": false,
  "enable_privacy_shield": true,
  "log_directory": "logs",
  "rules": [
    {
      "name": "Block Telnet",
      "dst_port": 23,
      "protocol": "TCP",
      "action": "BLOCK"
    }
  ],
  "honeypots": [
    {
      "port": 2222,
      "service": "ssh"
    }
  ]
}
```

## Running

```bash
sudo python -m active_defense_firewall --config /absolute/path/to/config.json
```

## Docker

The container uses the same module entrypoint:

```bash
docker build -t active-defense-firewall .
docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW --network host active-defense-firewall
```

Live packet capture and iptables enforcement require appropriate Linux capabilities and host networking.

## Testing

```bash
pytest
python -m compileall .
python -c "import active_defense_firewall"
```

## Repository structure

```text
active-defense-firewall/
├── active_defense_firewall.py
├── config.py
├── firewall_system.py
├── core/
│   ├── packet_engine.py
│   └── network_interface.py
├── detection/
│   └── threat_detector.py
├── defense/
│   ├── active_defense.py
│   └── encrypted_tunnel.py
└── tests/
    └── test_active_defense_firewall.py
```

## Operational notes

- Run only on systems you own or are authorized to defend.
- Review privacy and blocking policy before enabling live enforcement.
- Keep aggressive mode and external reporting disabled until explicitly approved for your environment.
- Validate rules in a controlled environment before deployment.
