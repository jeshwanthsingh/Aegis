# Target Profile

This document defines the exact people and company profile for the first 15-20 Aegis validation conversations.

## Exact champion

Primary champion:

- Staff Security Engineer or Principal Platform Engineer who is already being asked to approve or enable internal coding-agent execution on real repositories

Strong secondary champion:

- Director of Engineering Productivity who owns internal developer tooling and has a live agent rollout under review

## Exact budget owner

Most likely budget owner:

- Director of Platform Engineering
- Director of Engineering Productivity

In some organizations, the security champion will create the urgency, but the platform or productivity owner will own the pilot budget and operator time.

## Exact company profile

Target companies for the first pass should look like this:

- 300-5,000+ engineers
- strong internal platform or developer productivity function
- active internal use of coding agents, code assistants, or agentic software-development workflows
- meaningful source-code, credentials, or customer-data sensitivity
- enough infrastructure maturity to run a self-hosted pilot
- willingness to keep the first rollout narrow instead of demanding a full control plane on day one

## Companies to target first

Start with organizations that publicly show both engineering maturity and active interest in agentic software workflows.

- Stripe
- Datadog
- Shopify
- GitLab
- Vercel

These are good first conversations because they already talk publicly about AI agents, developer workflows, or governed software delivery. The point is not logo hunting. The point is to talk to teams already close to the problem.

## Companies to avoid first

Avoid these first:

- startups with fewer than roughly 100 engineers
- companies without a clear platform or security owner for internal developer tooling
- teams that only want a hosted vendor and will not consider self-hosted execution control
- teams looking for broad AI governance programs instead of a narrow coding-agent execution problem
- buyers who require host attestation, external signing custody, or multi-tenant controls as day-one requirements

## Validation signals

The wedge is getting stronger when a conversation reveals all or most of these:

- they already have an internal coding-agent workflow running or in pilot
- security or platform has explicitly blocked broader rollout because of execution and exfiltration risk
- they care about self-hosted execution control rather than only hosted convenience
- they say logs are not enough and want a signed run record or reviewable receipt
- they can name one workflow that could be piloted in 6-8 weeks
- they can identify both a technical champion and an owner with authority to run the pilot

## Wedge-killing signals

The wedge is likely wrong or too broad when you hear these repeatedly:

- "We only need better code suggestions, not agent execution"
- "A hosted sandbox is fine; we do not need self-hosted control"
- "Receipts do not matter; logs are enough"
- "The real problem is broad policy governance across the whole company"
- "We would only evaluate this after you have hosted control plane, dashboarding, and enterprise policy management"
- "We cannot run a narrow pilot without host attestation or HSM/KMS custody on day one"

## Practical sourcing note

Bias toward teams already operating close to engineering infrastructure, security review, or internal AI rollout pressure. A design partner conversation is useful only if the person can describe a real workflow, a real blocker, and a real owner.
