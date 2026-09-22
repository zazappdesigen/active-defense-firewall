from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from active_defense_firewall import ActiveDefenseFirewall
from config import FirewallConfig, RuleConfig, load_config
from core.network_interface import NetworkInterface
from core.packet_engine import DeepPacketInspector, PacketFilterEngine, PacketInfo
from defense.active_defense import ActiveDefenseSystem
from defense.encrypted_tunnel import PrivacyShield
from detection.threat_detector import IntrusionPreventionSystem


def build_packet(**overrides):
    base = {
        "timestamp": datetime.now(),
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
        "src_port": 12345,
        "dst_port": 443,
        "protocol": "TCP",
        "payload_size": 5,
        "flags": {"SYN": True, "ACK": False},
        "payload": b"hello",
    }
    base.update(overrides)
    return PacketInfo(**base)


def test_module_import_and_configuration():
    firewall = ActiveDefenseFirewall(interface="eth0")
    config = FirewallConfig.from_dict(
        {
            "interface": "eth0",
            "rules": [{"name": "Allow HTTPS", "dst_port": 443, "protocol": "TCP", "action": "ALLOW"}],
            "honeypots": [{"port": 2222, "service": "ssh"}],
        }
    )

    with patch.object(firewall.active_defense, "deploy_honeypot") as deploy_honeypot:
        firewall.configure(config)

    assert firewall.packet_engine.rules[0]["name"] == "Allow HTTPS"
    deploy_honeypot.assert_called_once_with(2222, "ssh")


def test_configuration_replaces_rules_and_honeypots():
    firewall = ActiveDefenseFirewall(interface="eth0")
    firewall.packet_engine.rules.append({"name": "stale"})
    firewall.active_defense.honeypots[2222] = Mock()

    config = FirewallConfig.from_dict(
        {
            "interface": "eth0",
            "rules": [{"name": "Allow DNS", "dst_port": 53, "protocol": "UDP", "action": "ALLOW"}],
            "honeypots": [{"port": 8080, "service": "http"}],
        }
    )

    with patch.object(firewall.active_defense, "shutdown_honeypot") as shutdown_honeypot, \
         patch.object(firewall.active_defense, "deploy_honeypot") as deploy_honeypot:
        firewall.configure(config)

    assert firewall.packet_engine.rules == [
        {"name": "Allow DNS", "action": "ALLOW", "dst_port": 53, "protocol": "UDP"}
    ]
    shutdown_honeypot.assert_called_once_with(2222)
    deploy_honeypot.assert_called_once_with(8080, "http")


def test_rule_config_rejects_invalid_values():
    with pytest.raises(ValueError):
        RuleConfig(name="bad", src_ip="not-an-ip")

    with pytest.raises(ValueError):
        RuleConfig(name="bad", dst_port=70000)


def test_load_config_from_json(tmp_path):
    config_path = tmp_path / "firewall.json"
    config_path.write_text(
        """
        {
          "interface": "eth1",
          "auto_counter_attack": false,
          "rules": [{"name": "Block Telnet", "dst_port": 23, "protocol": "TCP", "action": "BLOCK"}]
        }
        """
    )

    config = load_config(str(config_path))

    assert config.interface == "eth1"
    assert config.rules[0].dst_port == 23


def test_packet_engine_matches_cidr_and_blocks_rule():
    engine = PacketFilterEngine()
    engine.add_rule({"name": "Block SSH", "src_ip": "10.0.0.0/8", "dst_port": 22, "action": "BLOCK"})

    packet = build_packet(src_ip="10.1.2.3", dst_port=22)

    allow, reason = engine.process_packet(packet)

    assert not allow
    assert "Blocked by rule" in reason


def test_deep_packet_inspector_flags_shellcode():
    inspector = DeepPacketInspector()
    packet = build_packet(payload=b"\x90" * 12, payload_size=12)

    suspicious, findings = inspector.inspect_payload(packet)

    assert suspicious is True
    assert any("shellcode" in finding.lower() for finding in findings)


def test_intrusion_prevention_blocks_sql_injection():
    ips = IntrusionPreventionSystem()
    payload = b"GET /?q=1 UNION SELECT password FROM users HTTP/1.1"

    threats, should_block = ips.analyze_packet(
        src_ip="203.0.113.5",
        dst_ip="10.0.0.5",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        payload=payload,
        payload_size=len(payload),
        flags={"SYN": False, "ACK": True},
    )

    assert any(threat.threat_name == "SQL Injection Attempt" for threat in threats)
    assert should_block is False


def test_privacy_shield_blocks_unencrypted_http():
    shield = PrivacyShield()

    allowed, reason, event = shield.analyze_traffic(
        "192.168.1.20",
        "93.184.216.34",
        80,
        "TCP",
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )

    assert allowed is False
    assert "Unencrypted traffic blocked" in reason
    assert event is not None


def test_intrusion_prevention_detects_repeated_plaintext_auth_attempts():
    ips = IntrusionPreventionSystem()
    payload = b"USER admin\r\nPASS guessme\r\n"

    threats = []
    for _ in range(5):
        threats, _ = ips.analyze_packet(
            src_ip="203.0.113.9",
            dst_ip="10.0.0.20",
            src_port=40000,
            dst_port=21,
            protocol="TCP",
            payload=payload,
            payload_size=len(payload),
            flags={"SYN": False, "ACK": True},
        )

    assert any(threat.threat_name == "Brute Force Attack" for threat in threats)


def test_intrusion_prevention_tracks_auth_attempts_per_target():
    ips = IntrusionPreventionSystem()
    payload = b"USER admin\r\nPASS guessme\r\n"

    for _ in range(4):
        ips.analyze_packet(
            src_ip="203.0.113.9",
            dst_ip="10.0.0.20",
            src_port=40000,
            dst_port=21,
            protocol="TCP",
            payload=payload,
            payload_size=len(payload),
            flags={"SYN": False, "ACK": True},
        )

    threats, _ = ips.analyze_packet(
        src_ip="203.0.113.9",
        dst_ip="10.0.0.21",
        src_port=40001,
        dst_port=21,
        protocol="TCP",
        payload=payload,
        payload_size=len(payload),
        flags={"SYN": False, "ACK": True},
    )

    assert not any(threat.threat_name == "Brute Force Attack" for threat in threats)


def test_network_interface_rejects_invalid_block_rule():
    interface = NetworkInterface()

    with pytest.raises(ValueError):
        interface.add_block_rule("invalid-ip")


def test_network_interface_uses_safe_subprocess_arguments():
    interface = NetworkInterface()

    with patch.object(interface, "_run_command", return_value=Mock(returncode=1, stderr="", stdout="")) as run_command:
        interface.add_block_rule("203.0.113.8")

    first_call = run_command.call_args_list[0].args[0]
    assert first_call[:4] == ["iptables", "-C", "ACTIVE_DEFENSE", "-s"]


def test_active_defense_uses_cooldown_for_repeat_responses():
    defense = ActiveDefenseSystem()
    defense.report_threats = False

    with patch.object(defense.traffic_redirector, "redirect_to_honeypot") as redirect, \
         patch.object(defense.port_scanner, "quick_scan", return_value={22: True}) as quick_scan:
        defense.auto_counter_attack = True
        defense.aggressive_mode = True
        defense.honeypots[2222] = Mock()

        defense.respond_to_threat("Port scan detected", "203.0.113.10", "HIGH")
        defense.respond_to_threat("Port scan detected", "203.0.113.10", "HIGH")

    quick_scan.assert_called_once_with("203.0.113.10")
    redirect.assert_called_once()
    assert defense.counter_attack_log[-1].details["countermeasures_suppressed"] is True


def test_export_logs_creates_log_directory(tmp_path):
    firewall = ActiveDefenseFirewall(interface="eth0")
    firewall.configure(FirewallConfig(log_directory=str(tmp_path), enable_privacy_shield=False))
    firewall.stats["start_time"] = datetime.now() - timedelta(seconds=1)

    with patch.object(firewall.ips.threat_intel, "export_threat_data") as export_threats, \
         patch.object(firewall.active_defense, "export_logs") as export_defense:
        firewall.export_logs()

    export_threats.assert_called_once()
    export_defense.assert_called_once()
    assert tmp_path.exists()
