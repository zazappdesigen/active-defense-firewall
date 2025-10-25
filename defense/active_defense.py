#!/usr/bin/env python3
"""
Active Defense and Counter-Attack System
Implements offensive security measures to deter and neutralize attackers
"""

import logging
import socket
import subprocess
import json
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict
import threading
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class CounterAttackAction:
    """Counter-attack action record"""
    timestamp: datetime
    action_type: str
    target_ip: str
    description: str
    success: bool
    details: Dict


class AdaptiveBlocklist:
    """Adaptive IP blocking with automatic expiration"""
    
    def __init__(self):
        self.blocked_ips: Dict[str, datetime] = {}
        self.block_durations = {
            'LOW': timedelta(minutes=5),
            'MEDIUM': timedelta(minutes=30),
            'HIGH': timedelta(hours=2),
            'CRITICAL': timedelta(hours=24)
        }
        self.permanent_blocks: Set[str] = set()
    
    def block_ip(self, ip: str, severity: str = 'MEDIUM', 
                 reason: str = "", permanent: bool = False):
        """Block an IP address with automatic expiration"""
        if permanent:
            self.permanent_blocks.add(ip)
            logger.critical(f"PERMANENT BLOCK: {ip} - {reason}")
        else:
            duration = self.block_durations.get(severity, timedelta(minutes=30))
            expiry = datetime.now() + duration
            self.blocked_ips[ip] = expiry
            logger.warning(f"BLOCKED: {ip} for {duration} - {reason}")
    
    def unblock_ip(self, ip: str):
        """Manually unblock an IP"""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            logger.info(f"UNBLOCKED: {ip}")
        
        if ip in self.permanent_blocks:
            self.permanent_blocks.remove(ip)
            logger.info(f"REMOVED FROM PERMANENT BLOCK: {ip}")
    
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked"""
        # Check permanent blocks
        if ip in self.permanent_blocks:
            return True
        
        # Check temporary blocks
        if ip in self.blocked_ips:
            if datetime.now() < self.blocked_ips[ip]:
                return True
            else:
                # Expired, remove
                del self.blocked_ips[ip]
                logger.info(f"Block expired for {ip}")
                return False
        
        return False
    
    def cleanup_expired(self):
        """Remove expired blocks"""
        now = datetime.now()
        expired = [ip for ip, expiry in self.blocked_ips.items() if now >= expiry]
        
        for ip in expired:
            del self.blocked_ips[ip]
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired blocks")
    
    def get_blocked_ips(self) -> List[Dict]:
        """Get list of currently blocked IPs"""
        result = []
        
        for ip in self.permanent_blocks:
            result.append({
                'ip': ip,
                'type': 'permanent',
                'expires': None
            })
        
        for ip, expiry in self.blocked_ips.items():
            result.append({
                'ip': ip,
                'type': 'temporary',
                'expires': expiry.isoformat()
            })
        
        return result


class Honeypot:
    """Honeypot service to trap and analyze attackers"""
    
    def __init__(self, port: int, service_type: str = 'ssh'):
        self.port = port
        self.service_type = service_type
        self.running = False
        self.connections: List[Dict] = []
        self.server_socket: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start honeypot service"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)
            
            self.running = True
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()
            
            logger.info(f"Honeypot started: {self.service_type} on port {self.port}")
        except Exception as e:
            logger.error(f"Failed to start honeypot: {e}")
    
    def stop(self):
        """Stop honeypot service"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.thread:
            self.thread.join(timeout=2)
        logger.info(f"Honeypot stopped: {self.service_type} on port {self.port}")
    
    def _run(self):
        """Main honeypot loop"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                self._handle_connection(client_socket, address)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Honeypot error: {e}")
    
    def _handle_connection(self, client_socket: socket.socket, address: tuple):
        """Handle honeypot connection"""
        ip, port = address
        logger.warning(f"Honeypot connection from {ip}:{port}")
        
        connection_data = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'port': port,
            'service': self.service_type,
            'data': []
        }
        
        try:
            # Send fake banner
            if self.service_type == 'ssh':
                client_socket.send(b"SSH-2.0-OpenSSH_7.4\r\n")
            elif self.service_type == 'http':
                client_socket.send(b"HTTP/1.1 200 OK\r\n\r\n")
            elif self.service_type == 'ftp':
                client_socket.send(b"220 FTP Server Ready\r\n")
            
            # Receive data
            client_socket.settimeout(5.0)
            data = client_socket.recv(4096)
            
            if data:
                connection_data['data'].append(data.hex())
                logger.info(f"Honeypot received {len(data)} bytes from {ip}")
            
        except socket.timeout:
            pass
        except Exception as e:
            logger.error(f"Honeypot connection error: {e}")
        finally:
            client_socket.close()
            self.connections.append(connection_data)
    
    def get_connections(self) -> List[Dict]:
        """Get recorded honeypot connections"""
        return self.connections


class ThreatReporter:
    """Report threats to external threat intelligence platforms"""
    
    def __init__(self):
        self.report_history: List[Dict] = []
        self.enabled = True
    
    def report_to_abuseipdb(self, ip: str, categories: List[int], 
                           comment: str) -> bool:
        """
        Report malicious IP to AbuseIPDB
        Note: Requires API key in production
        """
        if not self.enabled:
            return False
        
        try:
            # This is a placeholder - in production, use actual API
            logger.info(f"Would report to AbuseIPDB: {ip}")
            logger.info(f"  Categories: {categories}")
            logger.info(f"  Comment: {comment}")
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'platform': 'AbuseIPDB',
                'ip': ip,
                'categories': categories,
                'comment': comment,
                'success': True
            }
            
            self.report_history.append(report)
            return True
            
        except Exception as e:
            logger.error(f"Failed to report to AbuseIPDB: {e}")
            return False
    
    def report_to_blocklist(self, ip: str, reason: str) -> bool:
        """Report to custom blocklist service"""
        try:
            logger.info(f"Would report to blocklist: {ip} - {reason}")
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'platform': 'Blocklist',
                'ip': ip,
                'reason': reason,
                'success': True
            }
            
            self.report_history.append(report)
            return True
            
        except Exception as e:
            logger.error(f"Failed to report to blocklist: {e}")
            return False
    
    def get_report_history(self) -> List[Dict]:
        """Get reporting history"""
        return self.report_history


class PortScanner:
    """Scan attacker's network for reconnaissance"""
    
    def __init__(self):
        self.scan_results: Dict[str, Dict] = {}
    
    def scan_ports(self, target_ip: str, ports: List[int], 
                   timeout: float = 1.0) -> Dict[int, bool]:
        """
        Scan specific ports on target IP
        Returns dict of port: is_open
        """
        results = {}
        
        logger.info(f"Scanning {target_ip} ports: {ports}")
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                
                is_open = (result == 0)
                results[port] = is_open
                
                if is_open:
                    logger.info(f"  Port {port}: OPEN")
                
            except Exception as e:
                logger.error(f"Error scanning port {port}: {e}")
                results[port] = False
        
        self.scan_results[target_ip] = {
            'timestamp': datetime.now().isoformat(),
            'ports': results
        }
        
        return results
    
    def quick_scan(self, target_ip: str) -> Dict[int, bool]:
        """Quick scan of common ports"""
        common_ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080]
        return self.scan_ports(target_ip, common_ports, timeout=0.5)


class TrafficRedirector:
    """Redirect malicious traffic to honeypots or black holes"""
    
    def __init__(self):
        self.redirections: Dict[str, str] = {}
    
    def redirect_to_honeypot(self, src_ip: str, honeypot_ip: str, 
                            honeypot_port: int) -> bool:
        """
        Redirect traffic from source IP to honeypot
        Uses iptables DNAT
        """
        try:
            cmd = (
                f"iptables -t nat -A PREROUTING -s {src_ip} "
                f"-j DNAT --to-destination {honeypot_ip}:{honeypot_port}"
            )
            
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, check=True
            )
            
            self.redirections[src_ip] = f"{honeypot_ip}:{honeypot_port}"
            logger.info(f"Redirected {src_ip} to honeypot {honeypot_ip}:{honeypot_port}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to redirect traffic: {e}")
            return False
    
    def blackhole_traffic(self, src_ip: str) -> bool:
        """
        Drop all traffic from source IP (black hole)
        """
        try:
            cmd = f"iptables -A INPUT -s {src_ip} -j DROP"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            
            logger.info(f"Black-holed traffic from {src_ip}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to black-hole traffic: {e}")
            return False


class ActiveDefenseSystem:
    """Integrated active defense and counter-attack system"""
    
    def __init__(self):
        self.blocklist = AdaptiveBlocklist()
        self.honeypots: Dict[int, Honeypot] = {}
        self.threat_reporter = ThreatReporter()
        self.port_scanner = PortScanner()
        self.traffic_redirector = TrafficRedirector()
        self.counter_attack_log: List[CounterAttackAction] = []
        
        # Configuration
        self.auto_counter_attack = True
        self.aggressive_mode = False
        self.report_threats = True
    
    def respond_to_threat(self, threat_event, src_ip: str, severity: str):
        """
        Execute appropriate response to detected threat
        """
        logger.warning(f"Responding to threat from {src_ip}: {threat_event}")
        
        actions_taken = []
        
        # 1. Block the IP
        permanent = (severity == 'CRITICAL' and self.aggressive_mode)
        self.blocklist.block_ip(src_ip, severity, threat_event, permanent)
        actions_taken.append('BLOCKED')
        
        # 2. Report to threat intelligence
        if self.report_threats:
            self.threat_reporter.report_to_abuseipdb(
                src_ip,
                categories=[18, 21],  # Brute force, Port scan
                comment=f"Detected: {threat_event}"
            )
            actions_taken.append('REPORTED')
        
        # 3. Counter-scan in aggressive mode
        if self.aggressive_mode and self.auto_counter_attack:
            try:
                scan_results = self.port_scanner.quick_scan(src_ip)
                open_ports = [p for p, is_open in scan_results.items() if is_open]
                
                if open_ports:
                    logger.info(f"Counter-scan found open ports on {src_ip}: {open_ports}")
                    actions_taken.append(f'SCANNED:{len(open_ports)}')
                
            except Exception as e:
                logger.error(f"Counter-scan failed: {e}")
        
        # 4. Redirect to honeypot for analysis
        if severity in ['HIGH', 'CRITICAL'] and 2222 in self.honeypots:
            self.traffic_redirector.redirect_to_honeypot(
                src_ip, '127.0.0.1', 2222
            )
            actions_taken.append('REDIRECTED')
        
        # Log action
        action = CounterAttackAction(
            timestamp=datetime.now(),
            action_type='THREAT_RESPONSE',
            target_ip=src_ip,
            description=f"Response to: {threat_event}",
            success=True,
            details={
                'severity': severity,
                'actions': actions_taken
            }
        )
        self.counter_attack_log.append(action)
        
        logger.info(f"Actions taken against {src_ip}: {', '.join(actions_taken)}")
    
    def deploy_honeypot(self, port: int, service_type: str = 'ssh'):
        """Deploy a honeypot on specified port"""
        if port in self.honeypots:
            logger.warning(f"Honeypot already running on port {port}")
            return
        
        honeypot = Honeypot(port, service_type)
        honeypot.start()
        self.honeypots[port] = honeypot
        
        logger.info(f"Deployed {service_type} honeypot on port {port}")
    
    def shutdown_honeypot(self, port: int):
        """Shutdown honeypot on specified port"""
        if port in self.honeypots:
            self.honeypots[port].stop()
            del self.honeypots[port]
            logger.info(f"Shutdown honeypot on port {port}")
    
    def get_statistics(self) -> Dict:
        """Get active defense statistics"""
        return {
            'blocked_ips': len(self.blocklist.blocked_ips),
            'permanent_blocks': len(self.blocklist.permanent_blocks),
            'active_honeypots': len(self.honeypots),
            'honeypot_connections': sum(
                len(hp.connections) for hp in self.honeypots.values()
            ),
            'threats_reported': len(self.threat_reporter.report_history),
            'counter_attacks': len(self.counter_attack_log),
            'auto_counter_attack': self.auto_counter_attack,
            'aggressive_mode': self.aggressive_mode
        }
    
    def export_logs(self, filepath: str):
        """Export defense logs"""
        data = {
            'blocked_ips': self.blocklist.get_blocked_ips(),
            'counter_attacks': [asdict(action) for action in self.counter_attack_log],
            'threat_reports': self.threat_reporter.get_report_history(),
            'honeypot_data': {
                port: hp.get_connections()
                for port, hp in self.honeypots.items()
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"Exported defense logs to {filepath}")


if __name__ == '__main__':
    # Example usage
    defense = ActiveDefenseSystem()
    
    print("Active Defense System initialized")
    print(f"Stats: {defense.get_statistics()}")
    
    # Deploy honeypots
    print("\nDeploying honeypots...")
    defense.deploy_honeypot(2222, 'ssh')
    defense.deploy_honeypot(8080, 'http')
    
    # Simulate threat response
    print("\nSimulating threat response...")
    defense.respond_to_threat(
        threat_event="Port scan detected",
        src_ip="192.168.1.100",
        severity="HIGH"
    )
    
    print(f"\nFinal stats: {defense.get_statistics()}")
    
    # Cleanup
    time.sleep(2)
    for port in list(defense.honeypots.keys()):
        defense.shutdown_honeypot(port)

