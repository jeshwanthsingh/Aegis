from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

RuntimeBackend = Literal["firecracker", "gvisor"]


@dataclass(slots=True)
class ResourceScope:
    workspace_root: str
    read_paths: list[str] = field(default_factory=list)
    write_paths: list[str] = field(default_factory=list)
    deny_paths: list[str] = field(default_factory=list)
    max_distinct_files: int = 1

    def to_wire(self) -> dict[str, Any]:
        return {
            "workspace_root": self.workspace_root,
            "read_paths": list(self.read_paths),
            "write_paths": list(self.write_paths),
            "deny_paths": list(self.deny_paths),
            "max_distinct_files": self.max_distinct_files,
        }


@dataclass(slots=True)
class NetworkScope:
    allow_network: bool
    allowed_domains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)
    max_dns_queries: int = 0
    max_outbound_conns: int = 0

    def to_wire(self) -> dict[str, Any]:
        return {
            "allow_network": self.allow_network,
            "allowed_domains": list(self.allowed_domains),
            "allowed_ips": list(self.allowed_ips),
            "max_dns_queries": self.max_dns_queries,
            "max_outbound_conns": self.max_outbound_conns,
        }


@dataclass(slots=True)
class ProcessScope:
    allowed_binaries: list[str] = field(default_factory=list)
    allow_shell: bool = False
    allow_package_install: bool = False
    max_child_processes: int = 0

    def to_wire(self) -> dict[str, Any]:
        return {
            "allowed_binaries": list(self.allowed_binaries),
            "allow_shell": self.allow_shell,
            "allow_package_install": self.allow_package_install,
            "max_child_processes": self.max_child_processes,
        }


@dataclass(slots=True)
class BrokerScope:
    allowed_delegations: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    allowed_action_types: list[str] = field(default_factory=list)
    require_host_consent: bool = False

    def to_wire(self) -> dict[str, Any]:
        wire = {
            "allowed_delegations": list(self.allowed_delegations),
            "require_host_consent": self.require_host_consent,
        }
        if self.allowed_domains:
            wire["allowed_domains"] = list(self.allowed_domains)
        if self.allowed_action_types:
            wire["allowed_action_types"] = list(self.allowed_action_types)
        return wire


@dataclass(slots=True)
class Budgets:
    timeout_sec: int
    memory_mb: int
    cpu_quota: int
    stdout_bytes: int

    def to_wire(self) -> dict[str, Any]:
        return {
            "timeout_sec": self.timeout_sec,
            "memory_mb": self.memory_mb,
            "cpu_quota": self.cpu_quota,
            "stdout_bytes": self.stdout_bytes,
        }


@dataclass(slots=True)
class IntentContract:
    version: str
    execution_id: str
    workflow_id: str
    task_class: str
    declared_purpose: str
    language: str
    resource_scope: ResourceScope
    network_scope: NetworkScope
    process_scope: ProcessScope
    broker_scope: BrokerScope
    budgets: Budgets
    backend_hint: RuntimeBackend | None = None
    attributes: dict[str, str] = field(default_factory=dict)

    def to_wire(self) -> dict[str, Any]:
        wire = {
            "version": self.version,
            "execution_id": self.execution_id,
            "workflow_id": self.workflow_id,
            "task_class": self.task_class,
            "declared_purpose": self.declared_purpose,
            "language": self.language,
            "resource_scope": self.resource_scope.to_wire(),
            "network_scope": self.network_scope.to_wire(),
            "process_scope": self.process_scope.to_wire(),
            "broker_scope": self.broker_scope.to_wire(),
            "budgets": self.budgets.to_wire(),
        }
        if self.backend_hint:
            wire["backend_hint"] = self.backend_hint
        if self.attributes:
            wire["attributes"] = dict(self.attributes)
        return wire


def coerce_intent_payload(intent: IntentContract | Mapping[str, Any] | None) -> dict[str, Any] | None:
    if intent is None:
        return None
    if isinstance(intent, IntentContract):
        return intent.to_wire()
    return dict(intent)
