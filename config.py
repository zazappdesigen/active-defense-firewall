#!/usr/bin/env python3
"""
Runtime configuration for the active defense firewall.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}
VALID_RULE_ACTIONS = {"ALLOW", "BLOCK"}
VALID_HONEYPOT_SERVICES = {"ssh", "http", "ftp"}


def _validate_port(port: int, field_name: str) -> int:
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"{field_name} must be an integer between 1 and 65535")
    return port


def _validate_ip_or_cidr(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")

    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name}: {value}") from exc

    return value


@dataclass(frozen=True)
class RuleConfig:
    name: str
    action: str = "ALLOW"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    def __post_init__(self):
        if not self.name:
            raise ValueError("Rule name is required")

        action = self.action.upper()
        if action not in VALID_RULE_ACTIONS:
            raise ValueError(f"Invalid rule action: {self.action}")
        object.__setattr__(self, "action", action)

        if self.src_ip is not None:
            _validate_ip_or_cidr(self.src_ip, "src_ip")
        if self.dst_ip is not None:
            _validate_ip_or_cidr(self.dst_ip, "dst_ip")
        if self.src_port is not None:
            _validate_port(self.src_port, "src_port")
        if self.dst_port is not None:
            _validate_port(self.dst_port, "dst_port")

        if self.protocol is not None:
            protocol = self.protocol.upper()
            if protocol not in VALID_PROTOCOLS:
                raise ValueError(f"Invalid rule protocol: {self.protocol}")
            object.__setattr__(self, "protocol", protocol)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "RuleConfig":
        return cls(
            name=raw["name"],
            action=raw.get("action", "ALLOW"),
            src_ip=raw.get("src_ip"),
            dst_ip=raw.get("dst_ip"),
            src_port=raw.get("src_port"),
            dst_port=raw.get("dst_port"),
            protocol=raw.get("protocol"),
        )

    def to_runtime_dict(self) -> Dict[str, Any]:
        data = {"name": self.name, "action": self.action}
        for field_name in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol"):
            value = getattr(self, field_name)
            if value is not None:
                data[field_name] = value
        return data


@dataclass(frozen=True)
class HoneypotConfig:
    port: int
    service: str = "ssh"

    def __post_init__(self):
        _validate_port(self.port, "honeypot port")
        service = self.service.lower()
        if service not in VALID_HONEYPOT_SERVICES:
            raise ValueError(f"Unsupported honeypot service: {self.service}")
        object.__setattr__(self, "service", service)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "HoneypotConfig":
        return cls(port=raw["port"], service=raw.get("service", "ssh"))


@dataclass(frozen=True)
class FirewallConfig:
    interface: str = "eth0"
    max_connections_per_ip: int = 100
    max_packets_per_second: int = 1000
    auto_block: bool = True
    block_threshold: float = 50.0
    auto_counter_attack: bool = False
    aggressive_mode: bool = False
    report_threats: bool = False
    enable_privacy_shield: bool = True
    log_directory: str = "logs"
    rules: List[RuleConfig] = field(default_factory=list)
    honeypots: List[HoneypotConfig] = field(default_factory=list)

    def __post_init__(self):
        if not isinstance(self.interface, str) or not self.interface.strip():
            raise ValueError("interface must be a non-empty string")
        if not isinstance(self.max_connections_per_ip, int) or self.max_connections_per_ip < 1:
            raise ValueError("max_connections_per_ip must be a positive integer")
        if not isinstance(self.max_packets_per_second, int) or self.max_packets_per_second < 1:
            raise ValueError("max_packets_per_second must be a positive integer")
        if self.block_threshold <= 0:
            raise ValueError("block_threshold must be greater than 0")
        if self.aggressive_mode and not self.auto_counter_attack:
            raise ValueError("aggressive_mode requires auto_counter_attack to be enabled")

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "FirewallConfig":
        rules = [RuleConfig.from_dict(item) for item in raw.get("rules", [])]
        honeypots = [HoneypotConfig.from_dict(item) for item in raw.get("honeypots", [])]

        return cls(
            interface=raw.get("interface", "eth0"),
            max_connections_per_ip=raw.get("max_connections_per_ip", 100),
            max_packets_per_second=raw.get("max_packets_per_second", 1000),
            auto_block=raw.get("auto_block", True),
            block_threshold=raw.get("block_threshold", 50.0),
            auto_counter_attack=raw.get("auto_counter_attack", False),
            aggressive_mode=raw.get("aggressive_mode", False),
            report_threats=raw.get("report_threats", False),
            enable_privacy_shield=raw.get("enable_privacy_shield", True),
            log_directory=raw.get("log_directory", "logs"),
            rules=rules,
            honeypots=honeypots,
        )


def load_config(config_path: Optional[str] = None) -> FirewallConfig:
    path = config_path or os.getenv("FIREWALL_CONFIG")
    if not path:
        return FirewallConfig()

    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, dict):
        raise ValueError("Configuration file must contain a JSON object")
    return FirewallConfig.from_dict(payload)
