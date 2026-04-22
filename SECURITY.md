# Security Policy

This file is the repository's reporting policy. Product security behavior and trust boundaries live in:

- [docs/security-faq.md](docs/security-faq.md)
- [docs/trust-model.md](docs/trust-model.md)

## Report A Vulnerability

If you believe you found a security issue in Aegis:

1. Use GitHub Security Advisories or the repository's private reporting path if one is available.
2. If no private reporting path is visible, open a minimal public issue asking for a secure contact channel and do not include exploit details.
3. Include the affected component, exact reproduction steps, impact, and whether the issue touches runtime isolation, broker behavior, approvals, receipts, or verification.

## Scope Reminder

Aegis today is:

- a single-host Firecracker/KVM runtime
- host-signed receipt generation plus offline verification

It is not currently:

- attested
- trustless
- a hosted multi-tenant control plane

Use the linked docs above for the full current boundary.
