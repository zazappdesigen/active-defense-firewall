#!/usr/bin/env python3
"""
Advanced Packet Filtering Engine
Provides stateful packet inspection, deep packet inspection, and protocol analysis
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
import socket
import struct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PacketInfo:
    """Packet information structure"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload_size: int
    flags: Dict[str, bool]
    payload: bytes


@dataclass
class ConnectionState:
    """Connection state tracking"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    state: str  # NEW, ESTABLISHED, CLOSING, CLOSED
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    first_seen: datetime = None
    last_seen: datetime = None
    flags_seen: Set[str] = None

    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.now()
        if self.last_seen is None:
            self.last_seen = datetime.now()
        if self.flags_seen is None:
            self.flags_seen = set()


class PacketFilterEngine:
    """Core packet filtering engine with stateful inspection"""
    
    def __init__(self):
        self.connections: Dict[str, ConnectionState] = {}
        self.blocked_ips: Set[str] = set()
        self.allowed_ips: Set[str] = set()
        self.rate_limits: Dict[str, List[datetime]] = defaultdict(list)
        self.rules: List[Dict] = []
        
        # Rate limiting configuration
        self.max_connections_per_ip = 100
        self.max_packets_per_second = 1000
        self.connection_timeout = timedelta(minutes=30)
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'packets_blocked': 0,
            'packets_allowed': 0,
            'connections_tracked': 0,
            'rate_limited': 0
        }
        
    def _get_connection_key(self, src_ip: str, dst_ip: str, src_port: int, 
                           dst_port: int, protocol: str) -> str:
        """Generate unique connection identifier"""
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"
    
    def _cleanup_old_connections(self):
        """Remove expired connections"""
        now = datetime.now()
        expired = []
        
        for key, conn in self.connections.items():
            if now - conn.last_seen > self.connection_timeout:
                expired.append(key)
        
        for key in expired:
            del self.connections[key]
            
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired connections")
    
    def _check_rate_limit(self, src_ip: str) -> bool:
        """Check if source IP exceeds rate limits"""
        now = datetime.now()
        
        # Clean old entries
        cutoff = now - timedelta(seconds=1)
        self.rate_limits[src_ip] = [
            ts for ts in self.rate_limits[src_ip] if ts > cutoff
        ]
        
        # Check rate
        if len(self.rate_limits[src_ip]) >= self.max_packets_per_second:
            self.stats['rate_limited'] += 1
            return False
        
        self.rate_limits[src_ip].append(now)
        return True
    
    def _check_connection_limit(self, src_ip: str) -> bool:
        """Check if source IP has too many connections"""
        active_connections = sum(
            1 for conn in self.connections.values()
            if conn.src_ip == src_ip and conn.state == 'ESTABLISHED'
        )
        
        return active_connections < self.max_connections_per_ip
    
    def _update_connection_state(self, packet: PacketInfo):
        """Update connection state tracking"""
        key = self._get_connection_key(
            packet.src_ip, packet.dst_ip, packet.src_port,
            packet.dst_port, packet.protocol
        )
        
        if key not in self.connections:
            # New connection
            self.connections[key] = ConnectionState(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                state='NEW'
            )
            self.stats['connections_tracked'] += 1
        
        conn = self.connections[key]
        conn.last_seen = packet.timestamp
        conn.packets_sent += 1
        conn.bytes_sent += packet.payload_size
        
        # Update state based on TCP flags
        if packet.protocol == 'TCP':
            if packet.flags.get('SYN') and not packet.flags.get('ACK'):
                conn.state = 'NEW'
                conn.flags_seen.add('SYN')
            elif packet.flags.get('SYN') and packet.flags.get('ACK'):
                conn.state = 'ESTABLISHED'
                conn.flags_seen.add('SYN-ACK')
            elif packet.flags.get('FIN'):
                conn.state = 'CLOSING'
                conn.flags_seen.add('FIN')
            elif packet.flags.get('RST'):
                conn.state = 'CLOSED'
                conn.flags_seen.add('RST')
            elif conn.state == 'NEW':
                conn.state = 'ESTABLISHED'
    
    def _apply_rules(self, packet: PacketInfo) -> Tuple[bool, str]:
        """Apply firewall rules to packet"""
        
        # Check blocked IPs
        if packet.src_ip in self.blocked_ips:
            return False, f"Source IP {packet.src_ip} is blocked"
        
        # Check rate limits
        if not self._check_rate_limit(packet.src_ip):
            return False, f"Rate limit exceeded for {packet.src_ip}"
        
        # Check connection limits
        if not self._check_connection_limit(packet.src_ip):
            return False, f"Connection limit exceeded for {packet.src_ip}"
        
        # Apply custom rules
        for rule in self.rules:
            if self._match_rule(packet, rule):
                action = rule.get('action', 'ALLOW')
                if action == 'BLOCK':
                    return False, f"Blocked by rule: {rule.get('name', 'unnamed')}"
                elif action == 'ALLOW':
                    return True, f"Allowed by rule: {rule.get('name', 'unnamed')}"
        
        # Default policy: allow
        return True, "Default policy: ALLOW"
    
    def _match_rule(self, packet: PacketInfo, rule: Dict) -> bool:
        """Check if packet matches a rule"""
        
        # Match source IP
        if 'src_ip' in rule and packet.src_ip != rule['src_ip']:
            if not self._match_cidr(packet.src_ip, rule['src_ip']):
                return False
        
        # Match destination IP
        if 'dst_ip' in rule and packet.dst_ip != rule['dst_ip']:
            if not self._match_cidr(packet.dst_ip, rule['dst_ip']):
                return False
        
        # Match source port
        if 'src_port' in rule and packet.src_port != rule['src_port']:
            return False
        
        # Match destination port
        if 'dst_port' in rule and packet.dst_port != rule['dst_port']:
            return False
        
        # Match protocol
        if 'protocol' in rule and packet.protocol != rule['protocol']:
            return False
        
        return True
    
    def _match_cidr(self, ip: str, cidr: str) -> bool:
        """Check if IP matches CIDR notation"""
        if '/' not in cidr:
            return ip == cidr
        
        try:
            network, bits = cidr.split('/')
            bits = int(bits)
            
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            network_int = struct.unpack('!I', socket.inet_aton(network))[0]
            
            mask = (0xffffffff << (32 - bits)) & 0xffffffff
            
            return (ip_int & mask) == (network_int & mask)
        except:
            return False
    
    def process_packet(self, packet: PacketInfo) -> Tuple[bool, str]:
        """
        Process a packet through the filtering engine
        Returns: (allow: bool, reason: str)
        """
        self.stats['packets_processed'] += 1
        
        # Periodic cleanup
        if self.stats['packets_processed'] % 1000 == 0:
            self._cleanup_old_connections()
        
        # Update connection state
        self._update_connection_state(packet)
        
        # Apply filtering rules
        allow, reason = self._apply_rules(packet)
        
        if allow:
            self.stats['packets_allowed'] += 1
            logger.debug(f"ALLOW: {packet.src_ip}:{packet.src_port} -> "
                        f"{packet.dst_ip}:{packet.dst_port} ({reason})")
        else:
            self.stats['packets_blocked'] += 1
            logger.warning(f"BLOCK: {packet.src_ip}:{packet.src_port} -> "
                          f"{packet.dst_ip}:{packet.dst_port} ({reason})")
        
        return allow, reason
    
    def add_rule(self, rule: Dict):
        """Add a filtering rule"""
        self.rules.append(rule)
        logger.info(f"Added rule: {rule.get('name', 'unnamed')}")
    
    def block_ip(self, ip: str, reason: str = ""):
        """Block an IP address"""
        self.blocked_ips.add(ip)
        logger.warning(f"Blocked IP: {ip} ({reason})")
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            logger.info(f"Unblocked IP: {ip}")
    
    def get_stats(self) -> Dict:
        """Get engine statistics"""
        return {
            **self.stats,
            'active_connections': len(self.connections),
            'blocked_ips': len(self.blocked_ips),
            'rules_loaded': len(self.rules)
        }
    
    def get_active_connections(self) -> List[ConnectionState]:
        """Get list of active connections"""
        return list(self.connections.values())


class DeepPacketInspector:
    """Deep packet inspection for payload analysis"""
    
    def __init__(self):
        self.suspicious_patterns = [
            b'<script>',
            b'../../../',
            b'SELECT * FROM',
            b'DROP TABLE',
            b'exec(',
            b'eval(',
            b'/bin/sh',
            b'/bin/bash',
            b'cmd.exe',
            b'powershell',
        ]
    
    def inspect_payload(self, packet: PacketInfo) -> Tuple[bool, List[str]]:
        """
        Inspect packet payload for suspicious content
        Returns: (is_suspicious: bool, findings: List[str])
        """
        findings = []
        
        if not packet.payload:
            return False, findings
        
        payload_lower = packet.payload.lower()
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern in payload_lower:
                findings.append(f"Suspicious pattern detected: {pattern.decode('utf-8', errors='ignore')}")
        
        # Check for unusual payload size
        if packet.payload_size > 65000:
            findings.append(f"Unusually large payload: {packet.payload_size} bytes")
        
        # Check for null bytes (potential buffer overflow)
        if b'\x00' * 10 in packet.payload:
            findings.append("Multiple null bytes detected (potential exploit)")
        
        # Check for shellcode patterns
        if self._detect_shellcode(packet.payload):
            findings.append("Potential shellcode detected")
        
        return len(findings) > 0, findings
    
    def _detect_shellcode(self, payload: bytes) -> bool:
        """Detect potential shellcode patterns"""
        # Common shellcode indicators
        shellcode_indicators = [
            b'\x90' * 10,  # NOP sled
            b'\xeb\xfe',   # JMP short -2
            b'\x31\xc0',   # XOR EAX, EAX
            b'\x50\x68',   # PUSH/PUSH pattern
        ]
        
        for indicator in shellcode_indicators:
            if indicator in payload:
                return True
        
        return False


if __name__ == '__main__':
    # Example usage
    engine = PacketFilterEngine()
    inspector = DeepPacketInspector()
    
    # Add some rules
    engine.add_rule({
        'name': 'Block SSH from external',
        'dst_port': 22,
        'src_ip': '0.0.0.0/0',
        'action': 'BLOCK'
    })
    
    # Simulate packet processing
    test_packet = PacketInfo(
        timestamp=datetime.now(),
        src_ip='192.168.1.100',
        dst_ip='10.0.0.1',
        src_port=54321,
        dst_port=80,
        protocol='TCP',
        payload_size=512,
        flags={'SYN': True, 'ACK': False},
        payload=b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
    )
    
    allow, reason = engine.process_packet(test_packet)
    print(f"Packet decision: {'ALLOW' if allow else 'BLOCK'} - {reason}")
    
    is_suspicious, findings = inspector.inspect_payload(test_packet)
    if is_suspicious:
        print(f"DPI findings: {findings}")
    
    print(f"\nEngine stats: {engine.get_stats()}")

