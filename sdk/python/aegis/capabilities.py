from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class BrokerDelegation:
    name: str
    resource: str | None = None
    method: str | None = None

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {"name": self.name}
        if self.resource:
            wire["resource"] = self.resource
        if self.method:
            wire["method"] = self.method
        return wire


@dataclass(slots=True)
class BrokerCapabilities:
    delegations: list[BrokerDelegation] = field(default_factory=list)
    http_requests: bool = False
    dependency_fetch: bool = False

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {}
        if self.delegations:
            wire["delegations"] = [delegation.to_wire() for delegation in self.delegations]
        if self.http_requests:
            wire["http_requests"] = True
        if self.dependency_fetch:
            wire["dependency_fetch"] = True
        return wire


@dataclass(slots=True)
class CapabilitiesRequest:
    network_domains: list[str] = field(default_factory=list)
    write_paths: list[str] = field(default_factory=list)
    broker: BrokerCapabilities | None = None

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {}
        if self.network_domains:
            wire["network_domains"] = list(self.network_domains)
        if self.write_paths:
            wire["write_paths"] = list(self.write_paths)
        if self.broker is not None:
            broker_wire = self.broker.to_wire()
            if broker_wire:
                wire["broker"] = broker_wire
        return wire


def coerce_capabilities_payload(capabilities: CapabilitiesRequest | Mapping[str, Any] | None) -> dict[str, Any] | None:
    if capabilities is None:
        return None
    if isinstance(capabilities, CapabilitiesRequest):
        return capabilities.to_wire()
    return dict(capabilities)
