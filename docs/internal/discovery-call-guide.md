# Discovery Call Guide

Use this guide for 25-30 minute conversations only. The goal is to determine whether the current wedge is real, not to collect broad interest.

## Exact questions

1. What internal coding-agent workflow is already live or actively under review right now?
2. What tasks do you currently let that agent perform against a real repository or build environment?
3. What is the main reason broader rollout is blocked today?
4. When an agent executes code today, what execution boundary does it actually get: developer machine, CI runner, remote sandbox, or something else?
5. What is the specific exfiltration or host-exposure concern your security or platform team worries about?
6. If an agent tries a denied action today, what evidence do you have afterward besides ordinary logs?
7. Does self-hosted execution control matter to you, or would a hosted sandbox be acceptable?
8. If a run ends with a signed receipt and proof bundle, who inside your organization would care about that and why?
9. Could you name one workflow that would be acceptable for a 6-8 week pilot with one or two policy paths only?
10. What would make this non-starter for you in the next quarter?
11. Who would need to approve a self-hosted pilot: security, platform, engineering productivity, or someone else?
12. If this problem were solved for one workflow, what would change operationally for your team?

## Answers that validate the wedge

- they can name a real internal coding-agent workflow without hand-waving
- they describe direct egress, secret exposure, or host access as a concrete blocker
- they say self-hosted control matters for trust, policy, or deployment reasons
- they say ordinary logs are not enough for review or signoff
- they can identify one pilot workflow and one accountable owner
- they want a narrow control point, not a broad governance platform

## Answers that kill the wedge

- they are only experimenting with code suggestions, not agent execution
- they have no real workflow under review
- they are happy with a hosted sandbox and do not care about self-hosting
- they do not care about receipts or signed run evidence
- they need a full enterprise platform before any pilot would be considered
- they require trust properties Aegis does not have today, such as host attestation on day one

## How to identify the real owner of the problem

The real owner is not the person most excited about AI. The real owner is the person who has to say yes or no to letting agent-written code run against real repos and infrastructure.

Signals you have the right owner:

- they can describe the current execution path in detail
- they know what security review is blocking
- they control platform implementation time, policy decisions, or pilot approval
- they can commit a real workflow to a 6-8 week evaluation

Signals you do not have the right owner:

- they can only talk about general AI strategy
- they cannot identify the blocked workflow
- they cannot name the approving team
- they want to forward you to someone in platform, productivity, or security
