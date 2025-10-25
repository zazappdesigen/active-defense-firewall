#!/usr/bin/env python3
"""
Active Defense Firewall System - Main Integration
Combines all components into a unified firewall system
"""

import sys
import signal
import logging
import time
from datetime import datetime
from typing import Optional

# Import firewall components
from core.packet_engine import PacketFilterEngine, DeepPacketInspector, PacketInfo
from core.network_interface import NetworkInterface, TrafficMonitor
from detection.threat_detector import IntrusionPreventionSystem
from defense.active_defense import ActiveDefenseSystem

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ActiveDefenseFirewall:
    """
    Integrated Active Defense Firewall System
    Combines packet filtering, threat detection, and active defense
    """
    
    def __init__(self, interface: str = 'eth0'):
        logger.info("Initializing Active Defense Firewall System...")
        
        # Core components
        self.packet_engine = PacketFilterEngine()
        self.dpi = DeepPacketInspector()
        self.network_interface = NetworkInterface(interface)
        self.traffic_monitor = TrafficMonitor()
        self.ips = IntrusionPreventionSystem()
        self.active_defense = ActiveDefenseSystem()
        
        # State
        self.running = False
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'ips_blocked': 0,
            'counter_attacks': 0,
            'start_time': None
        }
        
        logger.info("Firewall system initialized successfully")
    
    def configure(self, config: dict):
        """Apply system configuration"""
        logger.info("Applying configuration...")
        
        # Packet engine config
        if 'max_connections_per_ip' in config:
            self.packet_engine.max_connections_per_ip = config['max_connections_per_ip']
        
        if 'max_packets_per_second' in config:
            self.packet_engine.max_packets_per_second = config['max_packets_per_second']
        
        # IPS config
        if 'auto_block' in config:
            self.ips.auto_block_enabled = config['auto_block']
        
        if 'block_threshold' in config:
            self.ips.block_threshold = config['block_threshold']
        
        # Active defense config
        if 'auto_counter_attack' in config:
            self.active_defense.auto_counter_attack = config['auto_counter_attack']
        
        if 'aggressive_mode' in config:
            self.active_defense.aggressive_mode = config['aggressive_mode']
        
        if 'report_threats' in config:
            self.active_defense.report_threats = config['report_threats']
        
        # Load firewall rules
        if 'rules' in config:
            for rule in config['rules']:
                self.packet_engine.add_rule(rule)
        
        # Deploy honeypots
        if 'honeypots' in config:
            for hp in config['honeypots']:
                self.active_defense.deploy_honeypot(hp['port'], hp['service'])
        
        logger.info("Configuration applied successfully")
    
    def process_packet(self, packet: PacketInfo):
        """
        Process a single packet through the firewall pipeline
        """
        self.stats['packets_processed'] += 1
        
        # Step 1: Packet filtering
        allow, reason = self.packet_engine.process_packet(packet)
        
        if not allow:
            logger.debug(f"Packet blocked by filter: {reason}")
            return False
        
        # Step 2: Deep packet inspection
        is_suspicious, findings = self.dpi.inspect_payload(packet)
        
        if is_suspicious:
            logger.warning(f"DPI findings for {packet.src_ip}: {findings}")
        
        # Step 3: Intrusion detection
        threats, should_block = self.ips.analyze_packet(
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol,
            packet.payload,
            packet.payload_size,
            packet.flags
        )
        
        # Step 4: Handle detected threats
        if threats:
            self.stats['threats_detected'] += len(threats)
            
            for threat in threats:
                logger.warning(
                    f"THREAT DETECTED: {threat.threat_name} from {packet.src_ip} "
                    f"(Severity: {threat.severity})"
                )
                
                # Active defense response
                if should_block:
                    self.handle_threat(packet.src_ip, threat.severity, threat.threat_name)
        
        # Step 5: Update traffic monitoring
        self.traffic_monitor.update_stats(packet, 'in')
        
        return not should_block
    
    def handle_threat(self, src_ip: str, severity: str, threat_name: str):
        """
        Handle detected threat with active defense measures
        """
        logger.critical(f"Handling threat from {src_ip}: {threat_name} ({severity})")
        
        # Block the IP in packet engine
        self.packet_engine.block_ip(src_ip, f"Threat: {threat_name}")
        
        # Block in iptables
        self.network_interface.add_block_rule(src_ip)
        
        # Add to active defense blocklist
        self.active_defense.blocklist.block_ip(
            src_ip, 
            severity, 
            f"Threat: {threat_name}",
            permanent=(severity == 'CRITICAL')
        )
        
        self.stats['ips_blocked'] += 1
        
        # Execute active defense response
        self.active_defense.respond_to_threat(threat_name, src_ip, severity)
        self.stats['counter_attacks'] += 1
        
        logger.info(f"Threat response completed for {src_ip}")
    
    def start(self):
        """Start the firewall system"""
        if self.running:
            logger.warning("Firewall is already running")
            return
        
        logger.info("=" * 60)
        logger.info("STARTING ACTIVE DEFENSE FIREWALL SYSTEM")
        logger.info("=" * 60)
        
        self.stats['start_time'] = datetime.now()
        self.running = True
        
        # Setup iptables
        logger.info("Configuring iptables...")
        self.network_interface.setup_iptables()
        
        # Start packet capture
        logger.info("Starting packet capture...")
        self.network_interface.start_capture(self.process_packet)
        
        logger.info("Firewall system is now ACTIVE and protecting your network")
        logger.info("Press Ctrl+C to stop")
        
        # Main loop
        try:
            while self.running:
                time.sleep(1)
                
                # Periodic cleanup
                if self.stats['packets_processed'] % 10000 == 0:
                    self.active_defense.blocklist.cleanup_expired()
        
        except KeyboardInterrupt:
            logger.info("\nReceived shutdown signal...")
            self.stop()
    
    def stop(self):
        """Stop the firewall system"""
        if not self.running:
            return
        
        logger.info("Stopping Active Defense Firewall System...")
        
        self.running = False
        
        # Stop packet capture
        self.network_interface.stop_capture()
        
        # Shutdown honeypots
        for port in list(self.active_defense.honeypots.keys()):
            self.active_defense.shutdown_honeypot(port)
        
        # Export logs
        logger.info("Exporting logs...")
        self.export_logs()
        
        # Cleanup iptables (optional - comment out to keep rules)
        # self.network_interface.cleanup_iptables()
        
        # Print final statistics
        self.print_statistics()
        
        logger.info("Firewall system stopped successfully")
    
    def print_statistics(self):
        """Print system statistics"""
        uptime = datetime.now() - self.stats['start_time'] if self.stats['start_time'] else None
        
        print("\n" + "=" * 60)
        print("FIREWALL STATISTICS")
        print("=" * 60)
        
        if uptime:
            print(f"Uptime: {uptime}")
        
        print(f"Packets Processed: {self.stats['packets_processed']}")
        print(f"Threats Detected: {self.stats['threats_detected']}")
        print(f"IPs Blocked: {self.stats['ips_blocked']}")
        print(f"Counter-Attacks: {self.stats['counter_attacks']}")
        
        print("\nPacket Engine Stats:")
        for key, value in self.packet_engine.get_stats().items():
            print(f"  {key}: {value}")
        
        print("\nIPS Stats:")
        for key, value in self.ips.get_statistics().items():
            print(f"  {key}: {value}")
        
        print("\nActive Defense Stats:")
        for key, value in self.active_defense.get_statistics().items():
            print(f"  {key}: {value}")
        
        print("=" * 60 + "\n")
    
    def export_logs(self):
        """Export system logs and threat intelligence"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export threat intelligence
        threat_file = f"logs/threat_intelligence_{timestamp}.json"
        self.ips.threat_intel.export_threat_data(threat_file)
        logger.info(f"Threat intelligence exported to {threat_file}")
        
        # Export active defense logs
        defense_file = f"logs/active_defense_{timestamp}.json"
        self.active_defense.export_logs(defense_file)
        logger.info(f"Active defense logs exported to {defense_file}")


def main():
    """Main entry point"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║        ACTIVE DEFENSE FIREWALL SYSTEM v1.0               ║
    ║                                                           ║
    ║        Advanced Network Security with Active Defense     ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Check for root privileges
    import os
    if os.geteuid() != 0:
        print("ERROR: This program requires root privileges")
        print("Please run with: sudo python3 firewall_system.py")
        sys.exit(1)
    
    # Initialize firewall
    firewall = ActiveDefenseFirewall(interface='eth0')
    
    # Example configuration
    config = {
        'max_connections_per_ip': 100,
        'max_packets_per_second': 1000,
        'auto_block': True,
        'block_threshold': 50.0,
        'auto_counter_attack': True,
        'aggressive_mode': False,  # Set to True for counter-scanning
        'report_threats': True,
        'rules': [
            {
                'name': 'Block SSH from external',
                'dst_port': 22,
                'src_ip': '0.0.0.0/0',
                'action': 'BLOCK'
            }
        ],
        'honeypots': [
            {'port': 2222, 'service': 'ssh'},
            {'port': 8080, 'service': 'http'}
        ]
    }
    
    firewall.configure(config)
    
    # Setup signal handlers
    def signal_handler(sig, frame):
        firewall.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start firewall
    firewall.start()


if __name__ == '__main__':
    main()

