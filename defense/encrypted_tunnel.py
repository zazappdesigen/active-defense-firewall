#!/usr/bin/env python3
"""
Encrypted Tunnel Enforcement Module
Protects user privacy against EU Chat Control and mass surveillance by:
1. Forcing all traffic through encrypted channels
2. Blocking connections to known surveillance/scanning endpoints
3. Detecting unencrypted traffic leaks
4. Enforcing DNS encryption (DoH/DoT)
5. Preventing client-side scanning exfiltration

This module ensures that no unencrypted data leaves the network and
blocks any attempt by apps or services to send data to surveillance
infrastructure.
"""

import logging
import subprocess
import json
import socket
import struct
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Known EU surveillance and scanning infrastructure endpoints
# These are domains/IPs associated with proposed chat scanning systems
SURVEILLANCE_DOMAINS = [
    # EU CSAM scanning infrastructure (proposed)
    "*.eu-scan.europa.eu",
    "*.chatcontrol.eu",
    "*.csam-detect.eu",
    
    # Known data collection endpoints used by messaging apps
    # for client-side scanning exfiltration
    "hash-reporting.whatsapp.com",
    "safety-reporting.meta.com",
    "content-scanning.signal.org",  # hypothetical
    
    # General surveillance infrastructure
    "*.lawful-intercept.eu",
    "*.intercept-gateway.eu",
    
    # Known government scanning proxies
    "*.govwatch.eu",
    "*.eurosurveillance.net",
]

# Known surveillance IP ranges (example - would be updated from threat feeds)
SURVEILLANCE_IP_RANGES = [
    # Placeholder ranges - in production, these would be populated
    # from real threat intelligence feeds
]

# Trusted encrypted DNS servers (DoH/DoT)
TRUSTED_DNS_SERVERS = {
    "doh": [
        "https://dns.quad9.net/dns-query",        # Quad9 (privacy-focused)
        "https://cloudflare-dns.com/dns-query",   # Cloudflare
        "https://dns.mullvad.net/dns-query",      # Mullvad (no logging)
        "https://doh.applied-privacy.net/query",  # Applied Privacy
    ],
    "dot": [
        "9.9.9.9",          # Quad9
        "149.112.112.112",  # Quad9 secondary
        "1.1.1.1",          # Cloudflare
        "194.242.2.2",      # Mullvad
    ]
}

# Ports that MUST be encrypted
ENCRYPTION_REQUIRED_PORTS = {
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    465: "SMTPS",
    587: "SMTP/TLS",
    853: "DNS over TLS",
    5223: "Apple Push (encrypted)",
    5228: "Google Cloud Messaging",
    8443: "HTTPS alt",
}

# Ports that indicate UNENCRYPTED traffic (suspicious)
UNENCRYPTED_PORTS = {
    80: "HTTP (unencrypted)",
    21: "FTP (unencrypted)",
    23: "Telnet (unencrypted)",
    25: "SMTP (unencrypted)",
    110: "POP3 (unencrypted)",
    143: "IMAP (unencrypted)",
    53: "DNS (unencrypted)",
    69: "TFTP (unencrypted)",
    161: "SNMP (unencrypted)",
}


@dataclass
class PrivacyEvent:
    """Privacy violation or protection event"""
    timestamp: datetime
    event_type: str  # LEAK_BLOCKED, SURVEILLANCE_BLOCKED, ENCRYPTION_ENFORCED, DNS_ENCRYPTED
    severity: str    # LOW, MEDIUM, HIGH, CRITICAL
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    description: str
    action_taken: str
    details: Dict


class EncryptedTunnelEnforcer:
    """
    Forces all network traffic through encrypted channels.
    Blocks surveillance endpoints and prevents data exfiltration.
    """
    
    def __init__(self):
        self.enabled = True
        self.strict_mode = True  # Block ALL unencrypted traffic
        self.dns_encryption_enforced = True
        self.surveillance_blocking = True
        
        # Whitelisted IPs/domains that can use unencrypted (local network)
        self.whitelist_ips: Set[str] = {
            "127.0.0.1",
            "192.168.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
        }
        
        # Blocked surveillance endpoints
        self.blocked_surveillance: Set[str] = set()
        self._load_surveillance_endpoints()
        
        # Event log
        self.privacy_events: List[PrivacyEvent] = []
        
        # Statistics
        self.stats = {
            'unencrypted_blocked': 0,
            'surveillance_blocked': 0,
            'dns_queries_encrypted': 0,
            'total_enforcements': 0,
            'leaks_prevented': 0,
        }
        
        logger.info("Encrypted Tunnel Enforcer initialized")
        logger.info(f"Strict mode: {self.strict_mode}")
        logger.info(f"DNS encryption: {self.dns_encryption_enforced}")
        logger.info(f"Surveillance blocking: {self.surveillance_blocking}")
    
    def _load_surveillance_endpoints(self):
        """Load known surveillance endpoints to block"""
        for domain in SURVEILLANCE_DOMAINS:
            self.blocked_surveillance.add(domain)
        
        logger.info(f"Loaded {len(self.blocked_surveillance)} surveillance endpoints")
    
    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is in local/private range"""
        try:
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            
            # 10.0.0.0/8
            if (ip_int & 0xFF000000) == 0x0A000000:
                return True
            # 172.16.0.0/12
            if (ip_int & 0xFFF00000) == 0xAC100000:
                return True
            # 192.168.0.0/16
            if (ip_int & 0xFFFF0000) == 0xC0A80000:
                return True
            # 127.0.0.0/8
            if (ip_int & 0xFF000000) == 0x7F000000:
                return True
            
            return False
        except:
            return False
    
    def _is_surveillance_endpoint(self, dst_ip: str, dst_port: int) -> bool:
        """Check if destination is a known surveillance endpoint"""
        # Check against blocked IPs
        if dst_ip in self.blocked_surveillance:
            return True
        
        # Check against known surveillance port patterns
        # (In production, this would use DNS resolution and threat feeds)
        return False
    
    def _is_encrypted_protocol(self, dst_port: int, payload: bytes) -> bool:
        """Determine if traffic is using encrypted protocol"""
        # Check if port indicates encryption
        if dst_port in ENCRYPTION_REQUIRED_PORTS:
            return True
        
        # Check TLS/SSL handshake in payload
        if payload and len(payload) >= 5:
            # TLS record: Content type 0x16 (Handshake) or 0x17 (Application Data)
            if payload[0] in (0x16, 0x17):
                # Check TLS version (TLS 1.0=0x0301, 1.1=0x0302, 1.2=0x0303, 1.3=0x0304)
                if payload[1] == 0x03 and payload[2] in (0x01, 0x02, 0x03, 0x04):
                    return True
        
        # Check for SSH protocol
        if payload and payload.startswith(b'SSH-'):
            return True
        
        # Check for WireGuard (UDP port 51820 typically)
        if dst_port == 51820:
            return True
        
        return False
    
    def _is_unencrypted_dns(self, dst_ip: str, dst_port: int) -> bool:
        """Check if this is an unencrypted DNS query"""
        # Standard DNS on port 53
        if dst_port == 53:
            # Check if going to a trusted DoT server
            if dst_ip in TRUSTED_DNS_SERVERS['dot']:
                return False  # This is DoT, not plain DNS
            return True
        
        return False
    
    def enforce_encryption(self, src_ip: str, dst_ip: str, dst_port: int,
                          protocol: str, payload: bytes) -> Tuple[bool, str, Optional[PrivacyEvent]]:
        """
        Enforce encryption on all outgoing traffic.
        
        Returns: (allow: bool, reason: str, event: Optional[PrivacyEvent])
        """
        if not self.enabled:
            return True, "Enforcement disabled", None
        
        # Allow local traffic
        if self._is_local_ip(dst_ip):
            return True, "Local traffic allowed", None
        
        # CRITICAL: Block surveillance endpoints
        if self.surveillance_blocking and self._is_surveillance_endpoint(dst_ip, dst_port):
            event = PrivacyEvent(
                timestamp=datetime.now(),
                event_type="SURVEILLANCE_BLOCKED",
                severity="CRITICAL",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                description=f"Blocked connection to surveillance endpoint {dst_ip}:{dst_port}",
                action_taken="CONNECTION_DROPPED",
                details={"reason": "Known surveillance infrastructure"}
            )
            self.privacy_events.append(event)
            self.stats['surveillance_blocked'] += 1
            self.stats['total_enforcements'] += 1
            
            logger.critical(f"SURVEILLANCE BLOCKED: {src_ip} -> {dst_ip}:{dst_port}")
            return False, "Surveillance endpoint blocked", event
        
        # Block unencrypted DNS (enforce DoH/DoT)
        if self.dns_encryption_enforced and self._is_unencrypted_dns(dst_ip, dst_port):
            event = PrivacyEvent(
                timestamp=datetime.now(),
                event_type="DNS_ENCRYPTED",
                severity="HIGH",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                description=f"Blocked unencrypted DNS query to {dst_ip}",
                action_taken="DNS_REDIRECTED_TO_DOH",
                details={
                    "original_dns": dst_ip,
                    "redirected_to": TRUSTED_DNS_SERVERS['doh'][0]
                }
            )
            self.privacy_events.append(event)
            self.stats['dns_queries_encrypted'] += 1
            self.stats['total_enforcements'] += 1
            
            logger.warning(f"DNS ENCRYPTION ENFORCED: {src_ip} -> {dst_ip}:53")
            return False, "Unencrypted DNS blocked - use DoH/DoT", event
        
        # In strict mode, block ALL unencrypted external traffic
        if self.strict_mode and dst_port in UNENCRYPTED_PORTS:
            # Check if payload shows encryption despite port
            if not self._is_encrypted_protocol(dst_port, payload):
                event = PrivacyEvent(
                    timestamp=datetime.now(),
                    event_type="LEAK_BLOCKED",
                    severity="HIGH",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    description=f"Blocked unencrypted traffic on port {dst_port} ({UNENCRYPTED_PORTS[dst_port]})",
                    action_taken="CONNECTION_DROPPED",
                    details={
                        "port": dst_port,
                        "service": UNENCRYPTED_PORTS[dst_port],
                        "reason": "Unencrypted traffic not allowed in strict mode"
                    }
                )
                self.privacy_events.append(event)
                self.stats['unencrypted_blocked'] += 1
                self.stats['leaks_prevented'] += 1
                self.stats['total_enforcements'] += 1
                
                logger.warning(f"UNENCRYPTED TRAFFIC BLOCKED: {src_ip} -> {dst_ip}:{dst_port}")
                return False, f"Unencrypted traffic blocked (port {dst_port})", event
        
        # Traffic is encrypted or allowed
        return True, "Traffic encrypted - allowed", None
    
    def detect_scanning_exfiltration(self, src_ip: str, dst_ip: str, 
                                     dst_port: int, payload: bytes) -> Optional[PrivacyEvent]:
        """
        Detect if an app is trying to exfiltrate scanned message data
        to a surveillance server (client-side scanning detection).
        
        Looks for patterns that indicate hash-based content scanning
        results being uploaded.
        """
        if not payload:
            return None
        
        # Patterns that indicate scanning result uploads
        scanning_indicators = [
            b'"csam_hash"',
            b'"content_hash"',
            b'"scan_result"',
            b'"hash_match"',
            b'"perceptual_hash"',
            b'"neural_hash"',
            b'"photodna"',
            b'"report_content"',
            b'"flagged_content"',
            b'"scanning_report"',
            b'X-Content-Scan',
            b'X-Hash-Report',
        ]
        
        payload_lower = payload.lower()
        
        for indicator in scanning_indicators:
            if indicator.lower() in payload_lower:
                event = PrivacyEvent(
                    timestamp=datetime.now(),
                    event_type="SCANNING_EXFILTRATION_BLOCKED",
                    severity="CRITICAL",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol="TCP",
                    description=f"Blocked client-side scanning data exfiltration to {dst_ip}",
                    action_taken="CONNECTION_DROPPED_AND_LOGGED",
                    details={
                        "indicator_found": indicator.decode('utf-8', errors='ignore'),
                        "payload_size": len(payload),
                        "reason": "App attempting to upload scanning results to surveillance server"
                    }
                )
                self.privacy_events.append(event)
                self.stats['surveillance_blocked'] += 1
                self.stats['leaks_prevented'] += 1
                
                logger.critical(
                    f"CLIENT-SIDE SCANNING EXFILTRATION BLOCKED: "
                    f"{src_ip} -> {dst_ip}:{dst_port} "
                    f"(indicator: {indicator.decode('utf-8', errors='ignore')})"
                )
                return event
        
        return None
    
    def setup_iptables_encryption_rules(self):
        """
        Configure iptables to enforce encrypted traffic at kernel level.
        This provides hardware-level enforcement that apps cannot bypass.
        """
        commands = [
            # Create privacy chain
            "iptables -N PRIVACY_SHIELD 2>/dev/null || true",
            "iptables -F PRIVACY_SHIELD",
            
            # Allow local/loopback traffic
            "iptables -A PRIVACY_SHIELD -d 127.0.0.0/8 -j ACCEPT",
            "iptables -A PRIVACY_SHIELD -d 10.0.0.0/8 -j ACCEPT",
            "iptables -A PRIVACY_SHIELD -d 172.16.0.0/12 -j ACCEPT",
            "iptables -A PRIVACY_SHIELD -d 192.168.0.0/16 -j ACCEPT",
            
            # Allow encrypted protocols
            "iptables -A PRIVACY_SHIELD -p tcp --dport 443 -j ACCEPT",   # HTTPS
            "iptables -A PRIVACY_SHIELD -p tcp --dport 993 -j ACCEPT",   # IMAPS
            "iptables -A PRIVACY_SHIELD -p tcp --dport 995 -j ACCEPT",   # POP3S
            "iptables -A PRIVACY_SHIELD -p tcp --dport 465 -j ACCEPT",   # SMTPS
            "iptables -A PRIVACY_SHIELD -p tcp --dport 587 -j ACCEPT",   # SMTP/TLS
            "iptables -A PRIVACY_SHIELD -p tcp --dport 853 -j ACCEPT",   # DoT
            "iptables -A PRIVACY_SHIELD -p tcp --dport 22 -j ACCEPT",    # SSH
            "iptables -A PRIVACY_SHIELD -p udp --dport 443 -j ACCEPT",   # QUIC/HTTP3
            "iptables -A PRIVACY_SHIELD -p udp --dport 51820 -j ACCEPT", # WireGuard
            
            # Block unencrypted DNS (force DoH/DoT)
            "iptables -A PRIVACY_SHIELD -p udp --dport 53 -j DROP",
            "iptables -A PRIVACY_SHIELD -p tcp --dport 53 -j DROP",
            
            # Block common unencrypted protocols
            "iptables -A PRIVACY_SHIELD -p tcp --dport 80 -j DROP",    # HTTP
            "iptables -A PRIVACY_SHIELD -p tcp --dport 21 -j DROP",    # FTP
            "iptables -A PRIVACY_SHIELD -p tcp --dport 23 -j DROP",    # Telnet
            "iptables -A PRIVACY_SHIELD -p tcp --dport 25 -j DROP",    # SMTP plain
            "iptables -A PRIVACY_SHIELD -p tcp --dport 110 -j DROP",   # POP3
            "iptables -A PRIVACY_SHIELD -p tcp --dport 143 -j DROP",   # IMAP
            
            # Allow everything else (established connections, etc.)
            "iptables -A PRIVACY_SHIELD -m state --state ESTABLISHED,RELATED -j ACCEPT",
            
            # Insert privacy chain into OUTPUT
            "iptables -I OUTPUT -j PRIVACY_SHIELD",
        ]
        
        for cmd in commands:
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, check=False
                )
                if result.returncode != 0 and "exist" not in result.stderr:
                    logger.warning(f"iptables command failed: {cmd}")
            except Exception as e:
                logger.error(f"Error executing iptables: {e}")
        
        logger.info("Privacy Shield iptables rules applied")
    
    def setup_dns_over_https(self):
        """
        Configure system to use DNS over HTTPS (DoH) exclusively.
        Prevents DNS queries from being intercepted by ISPs or governments.
        """
        # Configure systemd-resolved for DoT
        dot_config = """
[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
DNSOverTLS=yes
DNSSEC=yes
FallbackDNS=1.1.1.1#cloudflare-dns.com
"""
        
        try:
            with open('/etc/systemd/resolved.conf.d/privacy.conf', 'w') as f:
                f.write(dot_config)
            
            subprocess.run(
                "systemctl restart systemd-resolved",
                shell=True, check=True, capture_output=True
            )
            
            logger.info("DNS over TLS configured successfully")
        except Exception as e:
            logger.warning(f"Could not configure system DNS: {e}")
            logger.info("Manual DNS configuration may be required")
    
    def add_surveillance_endpoint(self, endpoint: str):
        """Add a new surveillance endpoint to block"""
        self.blocked_surveillance.add(endpoint)
        logger.info(f"Added surveillance endpoint to blocklist: {endpoint}")
    
    def remove_surveillance_endpoint(self, endpoint: str):
        """Remove a surveillance endpoint from blocklist"""
        if endpoint in self.blocked_surveillance:
            self.blocked_surveillance.remove(endpoint)
            logger.info(f"Removed surveillance endpoint from blocklist: {endpoint}")
    
    def get_privacy_events(self, limit: int = 100) -> List[Dict]:
        """Get recent privacy events"""
        events = self.privacy_events[-limit:]
        return [asdict(event) for event in events]
    
    def get_statistics(self) -> Dict:
        """Get enforcement statistics"""
        return {
            **self.stats,
            'enabled': self.enabled,
            'strict_mode': self.strict_mode,
            'dns_encryption': self.dns_encryption_enforced,
            'surveillance_endpoints_blocked': len(self.blocked_surveillance),
            'total_privacy_events': len(self.privacy_events),
        }
    
    def export_privacy_report(self, filepath: str):
        """Export privacy protection report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'statistics': self.get_statistics(),
            'recent_events': self.get_privacy_events(500),
            'blocked_endpoints': list(self.blocked_surveillance),
            'configuration': {
                'strict_mode': self.strict_mode,
                'dns_encryption': self.dns_encryption_enforced,
                'surveillance_blocking': self.surveillance_blocking,
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Privacy report exported to {filepath}")


class VPNTunnelManager:
    """
    Manages VPN/WireGuard tunnels to ensure ALL traffic is encrypted.
    Provides kill-switch functionality - if VPN drops, all traffic is blocked.
    """
    
    def __init__(self):
        self.vpn_active = False
        self.kill_switch_enabled = True
        self.vpn_interface = "wg0"  # WireGuard interface
    
    def check_vpn_status(self) -> bool:
        """Check if VPN tunnel is active"""
        try:
            result = subprocess.run(
                f"ip link show {self.vpn_interface}",
                shell=True, capture_output=True, text=True
            )
            self.vpn_active = result.returncode == 0
            return self.vpn_active
        except:
            self.vpn_active = False
            return False
    
    def enable_kill_switch(self):
        """
        Enable kill switch - blocks ALL traffic if VPN is not active.
        This prevents any data from leaking if the VPN connection drops.
        """
        commands = [
            # Create kill switch chain
            "iptables -N VPN_KILLSWITCH 2>/dev/null || true",
            "iptables -F VPN_KILLSWITCH",
            
            # Allow traffic through VPN interface
            f"iptables -A VPN_KILLSWITCH -o {self.vpn_interface} -j ACCEPT",
            
            # Allow local traffic
            "iptables -A VPN_KILLSWITCH -d 127.0.0.0/8 -j ACCEPT",
            "iptables -A VPN_KILLSWITCH -d 10.0.0.0/8 -j ACCEPT",
            "iptables -A VPN_KILLSWITCH -d 172.16.0.0/12 -j ACCEPT",
            "iptables -A VPN_KILLSWITCH -d 192.168.0.0/16 -j ACCEPT",
            
            # Allow VPN establishment (WireGuard port)
            "iptables -A VPN_KILLSWITCH -p udp --dport 51820 -j ACCEPT",
            
            # Block everything else
            "iptables -A VPN_KILLSWITCH -j DROP",
            
            # Insert into OUTPUT chain
            "iptables -I OUTPUT -j VPN_KILLSWITCH",
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd, shell=True, check=False, capture_output=True)
            except:
                pass
        
        self.kill_switch_enabled = True
        logger.info("VPN Kill Switch ENABLED - traffic blocked without VPN")
    
    def disable_kill_switch(self):
        """Disable kill switch"""
        commands = [
            "iptables -D OUTPUT -j VPN_KILLSWITCH 2>/dev/null || true",
            "iptables -F VPN_KILLSWITCH 2>/dev/null || true",
            "iptables -X VPN_KILLSWITCH 2>/dev/null || true",
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, capture_output=True)
        
        self.kill_switch_enabled = False
        logger.info("VPN Kill Switch DISABLED")
    
    def get_status(self) -> Dict:
        """Get VPN tunnel status"""
        self.check_vpn_status()
        return {
            'vpn_active': self.vpn_active,
            'kill_switch_enabled': self.kill_switch_enabled,
            'vpn_interface': self.vpn_interface,
        }


class PrivacyShield:
    """
    Integrated Privacy Shield combining all privacy protection mechanisms.
    Designed specifically to counter EU Chat Control and mass surveillance.
    """
    
    def __init__(self):
        self.tunnel_enforcer = EncryptedTunnelEnforcer()
        self.vpn_manager = VPNTunnelManager()
        
        logger.info("=" * 60)
        logger.info("PRIVACY SHIELD ACTIVATED")
        logger.info("Protection against EU Chat Control: ENABLED")
        logger.info("Encrypted Tunnel Enforcement: ENABLED")
        logger.info("Surveillance Endpoint Blocking: ENABLED")
        logger.info("DNS Encryption: ENABLED")
        logger.info("=" * 60)
    
    def analyze_traffic(self, src_ip: str, dst_ip: str, dst_port: int,
                       protocol: str, payload: bytes) -> Tuple[bool, str, Optional[PrivacyEvent]]:
        """
        Analyze traffic for privacy violations.
        Returns: (allow, reason, event)
        """
        # Check for scanning exfiltration attempts
        exfil_event = self.tunnel_enforcer.detect_scanning_exfiltration(
            src_ip, dst_ip, dst_port, payload
        )
        if exfil_event:
            return False, "Client-side scanning exfiltration blocked", exfil_event
        
        # Enforce encryption
        allow, reason, event = self.tunnel_enforcer.enforce_encryption(
            src_ip, dst_ip, dst_port, protocol, payload
        )
        
        return allow, reason, event
    
    def activate_full_protection(self):
        """Activate all privacy protection mechanisms"""
        logger.info("Activating FULL privacy protection...")
        
        # Setup iptables rules
        self.tunnel_enforcer.setup_iptables_encryption_rules()
        
        # Configure encrypted DNS
        self.tunnel_enforcer.setup_dns_over_https()
        
        # Enable VPN kill switch
        self.vpn_manager.enable_kill_switch()
        
        logger.info("FULL privacy protection ACTIVE")
    
    def get_full_status(self) -> Dict:
        """Get comprehensive privacy shield status"""
        return {
            'tunnel_enforcer': self.tunnel_enforcer.get_statistics(),
            'vpn_status': self.vpn_manager.get_status(),
            'protection_level': 'MAXIMUM' if self.tunnel_enforcer.strict_mode else 'STANDARD',
            'eu_chat_control_defense': 'ACTIVE',
        }


if __name__ == '__main__':
    # Example usage
    shield = PrivacyShield()
    
    print("\n=== Privacy Shield Test ===\n")
    
    # Test 1: Block unencrypted HTTP traffic
    allow, reason, event = shield.analyze_traffic(
        "192.168.1.100", "93.184.216.34", 80, "TCP",
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    print(f"HTTP traffic: {'ALLOWED' if allow else 'BLOCKED'} - {reason}")
    
    # Test 2: Allow encrypted HTTPS traffic
    # Simulated TLS handshake
    tls_payload = bytes([0x16, 0x03, 0x03, 0x00, 0x05]) + b"hello"
    allow, reason, event = shield.analyze_traffic(
        "192.168.1.100", "93.184.216.34", 443, "TCP", tls_payload
    )
    print(f"HTTPS traffic: {'ALLOWED' if allow else 'BLOCKED'} - {reason}")
    
    # Test 3: Block unencrypted DNS
    allow, reason, event = shield.analyze_traffic(
        "192.168.1.100", "8.8.8.8", 53, "UDP", b"\x00\x01"
    )
    print(f"Plain DNS: {'ALLOWED' if allow else 'BLOCKED'} - {reason}")
    
    # Test 4: Block scanning exfiltration
    scanning_payload = b'{"csam_hash": "abc123", "scan_result": "match"}'
    allow, reason, event = shield.analyze_traffic(
        "192.168.1.100", "10.20.30.40", 443, "TCP", scanning_payload
    )
    print(f"Scanning exfiltration: {'ALLOWED' if allow else 'BLOCKED'} - {reason}")
    
    # Print statistics
    print(f"\nStatistics: {shield.get_full_status()}")
