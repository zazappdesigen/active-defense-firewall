#!/usr/bin/env python3
"""
Network Interface and Packet Capture
Handles raw packet capture and injection using iptables integration
"""

import subprocess
import logging
import socket
import struct
from datetime import datetime
from typing import Optional, Callable
from core.packet_engine import PacketInfo

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkInterface:
    """Network interface management and packet capture"""
    
    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
        self.running = False
        self.packet_callback: Optional[Callable] = None
        
    def setup_iptables(self):
        """Configure iptables for packet forwarding"""
        commands = [
            # Enable IP forwarding
            "sysctl -w net.ipv4.ip_forward=1",
            
            # Create custom chain for firewall
            "iptables -N ACTIVE_DEFENSE 2>/dev/null || true",
            
            # Flush existing rules in custom chain
            "iptables -F ACTIVE_DEFENSE",
            
            # Send all traffic through custom chain
            "iptables -I FORWARD -j ACTIVE_DEFENSE",
            "iptables -I INPUT -j ACTIVE_DEFENSE",
            "iptables -I OUTPUT -j ACTIVE_DEFENSE",
            
            # Default policy
            "iptables -P FORWARD ACCEPT",
        ]
        
        for cmd in commands:
            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    check=False
                )
                if result.returncode != 0 and "exist" not in result.stderr:
                    logger.warning(f"Command failed: {cmd}\n{result.stderr}")
            except Exception as e:
                logger.error(f"Error executing: {cmd}\n{e}")
    
    def add_block_rule(self, ip: str):
        """Add iptables rule to block an IP"""
        commands = [
            f"iptables -I ACTIVE_DEFENSE -s {ip} -j DROP",
            f"iptables -I ACTIVE_DEFENSE -d {ip} -j DROP",
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                logger.info(f"Blocked IP in iptables: {ip}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to block IP {ip}: {e}")
    
    def remove_block_rule(self, ip: str):
        """Remove iptables block rule for an IP"""
        commands = [
            f"iptables -D ACTIVE_DEFENSE -s {ip} -j DROP",
            f"iptables -D ACTIVE_DEFENSE -d {ip} -j DROP",
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                logger.info(f"Unblocked IP in iptables: {ip}")
            except subprocess.CalledProcessError:
                pass  # Rule might not exist
    
    def add_rate_limit_rule(self, ip: str, limit: str = "10/sec"):
        """Add rate limiting rule for an IP"""
        cmd = (
            f"iptables -I ACTIVE_DEFENSE -s {ip} "
            f"-m limit --limit {limit} -j ACCEPT"
        )
        
        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            logger.info(f"Added rate limit for {ip}: {limit}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add rate limit: {e}")
    
    def cleanup_iptables(self):
        """Remove firewall iptables rules"""
        commands = [
            "iptables -D FORWARD -j ACTIVE_DEFENSE 2>/dev/null || true",
            "iptables -D INPUT -j ACTIVE_DEFENSE 2>/dev/null || true",
            "iptables -D OUTPUT -j ACTIVE_DEFENSE 2>/dev/null || true",
            "iptables -F ACTIVE_DEFENSE 2>/dev/null || true",
            "iptables -X ACTIVE_DEFENSE 2>/dev/null || true",
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, capture_output=True)
        
        logger.info("Cleaned up iptables rules")
    
    def parse_tcp_packet(self, data: bytes, src_ip: str, dst_ip: str) -> Optional[PacketInfo]:
        """Parse TCP packet data"""
        try:
            if len(data) < 20:
                return None
            
            # Parse TCP header
            tcp_header = struct.unpack('!HHIIBBHHH', data[:20])
            src_port = tcp_header[0]
            dst_port = tcp_header[1]
            seq_num = tcp_header[2]
            ack_num = tcp_header[3]
            flags_byte = tcp_header[5]
            
            # Parse flags
            flags = {
                'FIN': bool(flags_byte & 0x01),
                'SYN': bool(flags_byte & 0x02),
                'RST': bool(flags_byte & 0x04),
                'PSH': bool(flags_byte & 0x08),
                'ACK': bool(flags_byte & 0x10),
                'URG': bool(flags_byte & 0x20),
            }
            
            # Get payload
            header_length = (tcp_header[4] >> 4) * 4
            payload = data[header_length:]
            
            return PacketInfo(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol='TCP',
                payload_size=len(payload),
                flags=flags,
                payload=payload
            )
        except Exception as e:
            logger.error(f"Error parsing TCP packet: {e}")
            return None
    
    def parse_udp_packet(self, data: bytes, src_ip: str, dst_ip: str) -> Optional[PacketInfo]:
        """Parse UDP packet data"""
        try:
            if len(data) < 8:
                return None
            
            # Parse UDP header
            udp_header = struct.unpack('!HHHH', data[:8])
            src_port = udp_header[0]
            dst_port = udp_header[1]
            length = udp_header[2]
            
            # Get payload
            payload = data[8:]
            
            return PacketInfo(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol='UDP',
                payload_size=len(payload),
                flags={},
                payload=payload
            )
        except Exception as e:
            logger.error(f"Error parsing UDP packet: {e}")
            return None
    
    def parse_ip_packet(self, data: bytes) -> Optional[PacketInfo]:
        """Parse IP packet and extract transport layer data"""
        try:
            if len(data) < 20:
                return None
            
            # Parse IP header
            ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
            version_ihl = ip_header[0]
            ihl = (version_ihl & 0x0F) * 4
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dst_ip = socket.inet_ntoa(ip_header[9])
            
            # Get transport layer data
            transport_data = data[ihl:]
            
            # Parse based on protocol
            if protocol == 6:  # TCP
                return self.parse_tcp_packet(transport_data, src_ip, dst_ip)
            elif protocol == 17:  # UDP
                return self.parse_udp_packet(transport_data, src_ip, dst_ip)
            else:
                # Other protocols
                return PacketInfo(
                    timestamp=datetime.now(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=0,
                    dst_port=0,
                    protocol=f'IP-{protocol}',
                    payload_size=len(transport_data),
                    flags={},
                    payload=transport_data
                )
        except Exception as e:
            logger.error(f"Error parsing IP packet: {e}")
            return None
    
    def start_capture(self, callback: Callable[[PacketInfo], None]):
        """
        Start capturing packets (requires root privileges)
        Note: This is a simplified implementation for demonstration
        """
        self.packet_callback = callback
        self.running = True
        
        logger.info(f"Starting packet capture on {self.interface}")
        logger.warning("Note: Actual packet capture requires root privileges and scapy")
        logger.warning("This is a demonstration implementation")
        
        # In production, you would use:
        # from scapy.all import sniff
        # sniff(iface=self.interface, prn=self._handle_packet, store=False)
    
    def _handle_packet(self, packet):
        """Handle captured packet (scapy callback)"""
        if not self.running or not self.packet_callback:
            return
        
        # This would be implemented with scapy in production
        # For now, it's a placeholder
        pass
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        logger.info("Stopped packet capture")
    
    def inject_packet(self, packet_data: bytes):
        """Inject a raw packet into the network"""
        try:
            # Create raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Send packet
            s.sendto(packet_data, (self.interface, 0))
            s.close()
            
            logger.debug("Injected packet into network")
        except Exception as e:
            logger.error(f"Failed to inject packet: {e}")


class TrafficMonitor:
    """Monitor network traffic statistics"""
    
    def __init__(self):
        self.stats = {
            'total_bytes_in': 0,
            'total_bytes_out': 0,
            'total_packets_in': 0,
            'total_packets_out': 0,
            'protocols': {},
            'top_talkers': {},
        }
    
    def update_stats(self, packet: PacketInfo, direction: str):
        """Update traffic statistics"""
        if direction == 'in':
            self.stats['total_packets_in'] += 1
            self.stats['total_bytes_in'] += packet.payload_size
        else:
            self.stats['total_packets_out'] += 1
            self.stats['total_bytes_out'] += packet.payload_size
        
        # Track protocols
        proto = packet.protocol
        if proto not in self.stats['protocols']:
            self.stats['protocols'][proto] = 0
        self.stats['protocols'][proto] += 1
        
        # Track top talkers
        talker = packet.src_ip
        if talker not in self.stats['top_talkers']:
            self.stats['top_talkers'][talker] = {'packets': 0, 'bytes': 0}
        self.stats['top_talkers'][talker]['packets'] += 1
        self.stats['top_talkers'][talker]['bytes'] += packet.payload_size
    
    def get_stats(self) -> dict:
        """Get current statistics"""
        return self.stats
    
    def get_top_talkers(self, n: int = 10) -> list:
        """Get top N talkers by traffic volume"""
        sorted_talkers = sorted(
            self.stats['top_talkers'].items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )
        return sorted_talkers[:n]


if __name__ == '__main__':
    # Example usage
    interface = NetworkInterface()
    
    print("Setting up iptables rules...")
    interface.setup_iptables()
    
    print("Adding test block rule...")
    interface.add_block_rule('192.168.1.100')
    
    print("Adding rate limit...")
    interface.add_rate_limit_rule('10.0.0.1', '100/sec')
    
    print("\nNote: Run with sudo for actual packet capture")
    print("Cleanup with: interface.cleanup_iptables()")

