#!/usr/bin/env python3
"""
Threat Detection and Intrusion Prevention System
Implements signature-based and anomaly-based threat detection
"""

import logging
import json
import re
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ThreatSignature:
    """Threat signature definition"""
    id: str
    name: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    category: str  # SCAN, EXPLOIT, MALWARE, DOS, BRUTEFORCE
    pattern: str
    protocol: Optional[str] = None
    port: Optional[int] = None
    description: str = ""


@dataclass
class ThreatEvent:
    """Detected threat event"""
    timestamp: datetime
    threat_id: str
    threat_name: str
    severity: str
    category: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    description: str
    confidence: float
    evidence: Dict


class SignatureDetector:
    """Signature-based threat detection"""
    
    def __init__(self):
        self.signatures: Dict[str, ThreatSignature] = {}
        self._load_default_signatures()
    
    def _load_default_signatures(self):
        """Load default threat signatures"""
        
        default_sigs = [
            ThreatSignature(
                id="SIG-001",
                name="SQL Injection Attempt",
                severity="HIGH",
                category="EXPLOIT",
                pattern=r"(union.*select|select.*from|insert.*into|delete.*from|drop.*table|exec.*\()",
                description="Potential SQL injection attack detected"
            ),
            ThreatSignature(
                id="SIG-002",
                name="XSS Attack",
                severity="MEDIUM",
                category="EXPLOIT",
                pattern=r"(<script.*?>|javascript:|onerror=|onload=)",
                description="Cross-site scripting attempt detected"
            ),
            ThreatSignature(
                id="SIG-003",
                name="Path Traversal",
                severity="HIGH",
                category="EXPLOIT",
                pattern=r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\)",
                description="Directory traversal attack detected"
            ),
            ThreatSignature(
                id="SIG-004",
                name="Command Injection",
                severity="CRITICAL",
                category="EXPLOIT",
                pattern=r"(;.*\||&&|`.*`|\$\(.*\)|>\s*/dev/)",
                description="Command injection attempt detected"
            ),
            ThreatSignature(
                id="SIG-005",
                name="Port Scan",
                severity="MEDIUM",
                category="SCAN",
                pattern=r"",  # Detected by behavior analysis
                description="Port scanning activity detected"
            ),
            ThreatSignature(
                id="SIG-006",
                name="Brute Force Attack",
                severity="HIGH",
                category="BRUTEFORCE",
                pattern=r"",  # Detected by behavior analysis
                description="Brute force authentication attempt"
            ),
            ThreatSignature(
                id="SIG-007",
                name="DDoS Attack",
                severity="CRITICAL",
                category="DOS",
                pattern=r"",  # Detected by behavior analysis
                description="Distributed denial of service attack"
            ),
            ThreatSignature(
                id="SIG-008",
                name="Shellcode Execution",
                severity="CRITICAL",
                category="EXPLOIT",
                pattern=r"(\x90{10,}|\\x90{10,})",
                description="Shellcode pattern detected"
            ),
            ThreatSignature(
                id="SIG-009",
                name="Malware Callback",
                severity="CRITICAL",
                category="MALWARE",
                pattern=r"(cmd\.exe|powershell\.exe|/bin/sh|/bin/bash)",
                description="Potential malware command execution"
            ),
            ThreatSignature(
                id="SIG-010",
                name="Suspicious User-Agent",
                severity="LOW",
                category="SCAN",
                pattern=r"(nikto|nmap|masscan|sqlmap|metasploit|burp)",
                description="Security scanning tool detected"
            ),
        ]
        
        for sig in default_sigs:
            self.signatures[sig.id] = sig
    
    def add_signature(self, signature: ThreatSignature):
        """Add a custom threat signature"""
        self.signatures[signature.id] = signature
        logger.info(f"Added signature: {signature.name} ({signature.id})")
    
    def detect(self, payload: bytes, protocol: str, src_port: int, 
               dst_port: int) -> List[ThreatSignature]:
        """
        Detect threats using signature matching
        Returns list of matched signatures
        """
        matches = []
        
        try:
            # Convert payload to string for pattern matching
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            
            for sig in self.signatures.values():
                # Skip if signature has protocol/port requirements
                if sig.protocol and sig.protocol != protocol:
                    continue
                if sig.port and sig.port != dst_port:
                    continue
                
                # Skip empty patterns (behavior-based detection)
                if not sig.pattern:
                    continue
                
                # Check pattern match
                if re.search(sig.pattern, payload_str, re.IGNORECASE):
                    matches.append(sig)
                    logger.warning(f"Signature match: {sig.name} ({sig.id})")
        
        except Exception as e:
            logger.error(f"Error in signature detection: {e}")
        
        return matches


class AnomalyDetector:
    """Anomaly-based threat detection using behavioral analysis"""
    
    def __init__(self):
        # Track connection patterns
        self.connection_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Track failed authentication attempts
        self.auth_attempts: Dict[str, List[datetime]] = defaultdict(list)
        
        # Track port scan attempts
        self.port_scans: Dict[str, Deque[Tuple[datetime, int]]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        self.port_scan_window = timedelta(seconds=60)
        
        # Track traffic volume
        self.traffic_volume: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)
        
        # Thresholds
        self.port_scan_threshold = 10  # ports in 60 seconds
        self.auth_failure_threshold = 5  # failures in 5 minutes
        self.connection_rate_threshold = 100  # connections per second
        self.traffic_spike_multiplier = 10  # 10x normal traffic
    
    def detect_port_scan(self, src_ip: str, dst_port: int) -> Optional[ThreatEvent]:
        """Detect port scanning behavior"""
        now = datetime.now()
        
        self.port_scans[src_ip].append((now, dst_port))
        cutoff = now - self.port_scan_window
        recent_ports = {
            port for ts, port in self.port_scans[src_ip]
            if ts > cutoff
        }

        if len(recent_ports) >= self.port_scan_threshold:
            logger.warning(f"Port scan detected from {src_ip}: "
                          f"{len(recent_ports)} ports")
            
            return ThreatEvent(
                timestamp=now,
                threat_id="SIG-005",
                threat_name="Port Scan",
                severity="MEDIUM",
                category="SCAN",
                src_ip=src_ip,
                dst_ip="*",
                src_port=0,
                dst_port=0,
                protocol="TCP",
                description=f"Scanned {len(recent_ports)} unique ports in 60 seconds",
                confidence=0.9,
                evidence={
                    'ports_scanned': len(recent_ports),
                    'ports': sorted(recent_ports)[:20],
                    'time_window': '60 seconds',
                }
            )
        
        return None
    
    def detect_brute_force(self, src_ip: str, dst_ip: str, 
                          dst_port: int, is_auth_attempt: bool,
                          evidence_reason: str) -> Optional[ThreatEvent]:
        """Detect brute force authentication attempts from repeated auth activity."""
        if not is_auth_attempt:
            return None
        
        now = datetime.now()
        
        self.auth_attempts[src_ip].append(now)
        
        cutoff = now - timedelta(minutes=5)
        self.auth_attempts[src_ip] = [
            ts for ts in self.auth_attempts[src_ip] if ts > cutoff
        ]
        
        if len(self.auth_attempts[src_ip]) >= self.auth_failure_threshold:
            logger.warning(f"Brute force detected from {src_ip}: "
                          f"{len(self.auth_attempts[src_ip])} attempts")
            
            return ThreatEvent(
                timestamp=now,
                threat_id="SIG-006",
                threat_name="Brute Force Attack",
                severity="HIGH",
                category="BRUTEFORCE",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=0,
                dst_port=dst_port,
                protocol="TCP",
                description=f"{len(self.auth_attempts[src_ip])} auth-targeted attempts in 5 minutes",
                confidence=0.8,
                evidence={
                    'attempt_count': len(self.auth_attempts[src_ip]),
                    'time_window': '5 minutes',
                    'reason': evidence_reason,
                }
            )
        
        return None
    
    def detect_ddos(self, src_ip: str, packet_size: int) -> Optional[ThreatEvent]:
        """Detect DDoS attack patterns"""
        now = datetime.now()
        
        # Track traffic volume
        self.traffic_volume[src_ip].append((now, packet_size))
        
        # Clean old entries (older than 10 seconds)
        cutoff = now - timedelta(seconds=10)
        self.traffic_volume[src_ip] = [
            (ts, size) for ts, size in self.traffic_volume[src_ip] if ts > cutoff
        ]
        
        # Calculate current rate
        recent_packets = len(self.traffic_volume[src_ip])
        
        # Check for abnormal connection rate
        if recent_packets > self.connection_rate_threshold:
            logger.warning(f"Potential DDoS from {src_ip}: "
                          f"{recent_packets} packets in 10s")
            
            return ThreatEvent(
                timestamp=now,
                threat_id="SIG-007",
                threat_name="DDoS Attack",
                severity="CRITICAL",
                category="DOS",
                src_ip=src_ip,
                dst_ip="*",
                src_port=0,
                dst_port=0,
                protocol="*",
                description=f"High packet rate: {recent_packets}/10s",
                confidence=0.85,
                evidence={
                    'packet_rate': recent_packets,
                    'time_window': '10 seconds',
                    'threshold': self.connection_rate_threshold
                }
            )
        
        return None
    
    def detect_anomaly(self, src_ip: str, dst_ip: str, src_port: int,
                      dst_port: int, protocol: str, payload_size: int,
                      flags: Dict, payload: bytes) -> List[ThreatEvent]:
        """
        Run all anomaly detection checks
        Returns list of detected threats
        """
        threats = []
        
        # Port scan detection
        if protocol == 'TCP' and flags.get('SYN') and not flags.get('ACK'):
            threat = self.detect_port_scan(src_ip, dst_port)
            if threat:
                threats.append(threat)
        
        # Credential attack detection for plaintext auth protocols
        auth_ports = {21, 23, 110, 143}
        if dst_port in auth_ports:
            payload_lower = payload.lower() if payload else b""
            auth_attempt_indicators = [
                b"user ",
                b"pass ",
                b"login ",
                b"auth ",
                b"authorization: basic ",
            ]
            has_auth_attempt_indicator = any(
                indicator in payload_lower for indicator in auth_attempt_indicators
            )
            threat = self.detect_brute_force(
                src_ip,
                dst_ip,
                dst_port,
                has_auth_attempt_indicator,
                "repeated plaintext authentication commands",
            )
            if threat:
                threats.append(threat)
        
        # DDoS detection
        threat = self.detect_ddos(src_ip, payload_size)
        if threat:
            threats.append(threat)
        
        return threats


class ThreatIntelligence:
    """Threat intelligence and reputation management"""
    
    def __init__(self):
        self.threat_scores: Dict[str, float] = {}
        self.known_malicious: Set[str] = set()
        self.known_good: Set[str] = set()
        self.threat_history: Dict[str, List[ThreatEvent]] = defaultdict(list)
    
    def update_threat_score(self, ip: str, event: ThreatEvent):
        """Update threat score for an IP based on detected event"""
        if ip not in self.threat_scores:
            self.threat_scores[ip] = 0.0
        
        # Add to history
        self.threat_history[ip].append(event)
        
        # Calculate score increment based on severity
        severity_scores = {
            'LOW': 1.0,
            'MEDIUM': 5.0,
            'HIGH': 10.0,
            'CRITICAL': 20.0
        }
        
        increment = severity_scores.get(event.severity, 1.0) * event.confidence
        self.threat_scores[ip] += increment
        
        # Mark as malicious if score is high
        if self.threat_scores[ip] >= 50.0:
            self.known_malicious.add(ip)
            logger.critical(f"IP {ip} marked as malicious (score: {self.threat_scores[ip]})")
    
    def get_threat_score(self, ip: str) -> float:
        """Get current threat score for an IP"""
        return self.threat_scores.get(ip, 0.0)
    
    def is_malicious(self, ip: str) -> bool:
        """Check if IP is known malicious"""
        return ip in self.known_malicious
    
    def get_threat_history(self, ip: str) -> List[ThreatEvent]:
        """Get threat history for an IP"""
        return self.threat_history.get(ip, [])
    
    def export_threat_data(self, filepath: str):
        """Export threat intelligence data"""
        data = {
            'threat_scores': self.threat_scores,
            'known_malicious': list(self.known_malicious),
            'threat_history': {
                ip: [asdict(event) for event in events]
                for ip, events in self.threat_history.items()
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"Exported threat intelligence to {filepath}")


class IntrusionPreventionSystem:
    """Integrated IPS combining all detection methods"""
    
    def __init__(self):
        self.signature_detector = SignatureDetector()
        self.anomaly_detector = AnomalyDetector()
        self.threat_intel = ThreatIntelligence()
        self.auto_block_enabled = True
        self.block_threshold = 50.0
    
    def analyze_packet(self, src_ip: str, dst_ip: str, src_port: int,
                      dst_port: int, protocol: str, payload: bytes,
                      payload_size: int, flags: Dict) -> Tuple[List[ThreatEvent], bool]:
        """
        Analyze packet for threats
        Returns: (detected_threats, should_block)
        """
        threats = []
        
        # Signature-based detection
        sig_matches = self.signature_detector.detect(
            payload, protocol, src_port, dst_port
        )
        
        for sig in sig_matches:
            threat = ThreatEvent(
                timestamp=datetime.now(),
                threat_id=sig.id,
                threat_name=sig.name,
                severity=sig.severity,
                category=sig.category,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                description=sig.description,
                confidence=0.95,
                evidence={'signature': sig.pattern}
            )
            threats.append(threat)
            self.threat_intel.update_threat_score(src_ip, threat)
        
        # Anomaly-based detection
        anomaly_threats = self.anomaly_detector.detect_anomaly(
            src_ip, dst_ip, src_port, dst_port, protocol, payload_size, flags, payload
        )
        
        for threat in anomaly_threats:
            threats.append(threat)
            self.threat_intel.update_threat_score(src_ip, threat)
        
        # Determine if should block
        should_block = False
        
        if self.auto_block_enabled:
            # Block if any critical threat detected
            if any(t.severity == 'CRITICAL' for t in threats):
                should_block = True
            
            # Block if threat score exceeds threshold
            if self.threat_intel.get_threat_score(src_ip) >= self.block_threshold:
                should_block = True
            
            # Block if known malicious
            if self.threat_intel.is_malicious(src_ip):
                should_block = True
        
        return threats, should_block
    
    def get_statistics(self) -> Dict:
        """Get IPS statistics"""
        return {
            'signatures_loaded': len(self.signature_detector.signatures),
            'malicious_ips': len(self.threat_intel.known_malicious),
            'tracked_ips': len(self.threat_intel.threat_scores),
            'auto_block_enabled': self.auto_block_enabled,
            'block_threshold': self.block_threshold
        }


if __name__ == '__main__':
    # Example usage
    ips = IntrusionPreventionSystem()
    
    # Test SQL injection detection
    test_payload = b"GET /login?user=admin' OR '1'='1 HTTP/1.1"
    
    threats, should_block = ips.analyze_packet(
        src_ip='192.168.1.100',
        dst_ip='10.0.0.1',
        src_port=54321,
        dst_port=80,
        protocol='TCP',
        payload=test_payload,
        payload_size=len(test_payload),
        flags={'SYN': False, 'ACK': True}
    )
    
    print(f"Detected {len(threats)} threats")
    for threat in threats:
        print(f"  - {threat.threat_name} ({threat.severity}): {threat.description}")
    
    print(f"Should block: {should_block}")
    print(f"\nIPS Stats: {ips.get_statistics()}")
