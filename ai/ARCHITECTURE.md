# Aegis Architecture

## What it is
Firecracker/KVM microVM execution runtime for sandboxing AI-generated code.

## Core components
- virtio-vsock IPC between host and guest
- cgroups v2 isolation
- TAP/iptables network isolation  
- DNS interceptor
- YAML policy engine
- Real-time SSE streaming
- Prometheus metrics
- Postgres audit logging

## Hard rules
- Never use glibc in guest — Alpine/musl only (WSL2 netlink bug)
- All goroutines that close over loop variables must capture by value
- net.DefaultResolver unavailable in WSL2 — force external resolver
- Sub-150ms cold start target
- All containment decisions must be logged to Postgres

## Stack
Go, Firecracker, Linux KVM, virtio-vsock, cgroups v2
