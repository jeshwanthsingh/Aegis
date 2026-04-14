# Outreach Messages

Use these only for the narrow Aegis wedge:

- internal coding agents
- self-hosted execution control
- signed receipts for what the host observed and enforced

## Warm intro ask

Subject:

`Intro to the team looking at internal coding-agent execution controls?`

Message:

`I’m working on Aegis, a self-hosted way to let internal coding agents run code without giving them a normal machine, with signed receipts for what they tried to do. I’m trying to speak with the person who is currently approving or blocking internal coding-agent execution in engineering. If someone on your platform, productivity, or security team owns that problem, would you be willing to introduce us? I’m not looking for a broad AI conversation, just one narrow workflow and the controls around it.`

## Direct email or LinkedIn message

Subject:

`Question on internal coding-agent execution`

Message:

`I’m speaking with platform and security teams that are trying to let internal coding agents run real build/test/repo tasks without handing those agents a normal host or CI runner. Aegis is a self-hosted runtime that blocks direct egress by default and emits signed receipts for what the host observed and enforced.`

`The question I’m trying to answer is simple: is this a real blocker for teams already rolling out coding agents, or is a generic sandbox good enough?`

`If you own or are close to that decision at <company>, would you be open to a 25-minute call? I’m looking for honest signal, not a generic product pitch.`

## Follow-up message

`Following up on the note below. I’m specifically looking for teams that already have an internal coding-agent workflow in flight and are running into execution-control or reviewability problems. If that is not you, no worries. If it is, I’d value a short conversation to see whether the current wedge is real or not.`

## Short reply to "How is this different from a sandbox?"

`The narrow difference is that Aegis is not just "code ran somewhere else." It is aimed at self-hosted internal coding-agent execution where the team wants direct egress denied by default and a signed receipt showing what the host observed and enforced for that run. If a generic sandbox already solves that in a way your platform and security teams accept, then Aegis is probably not the right wedge for you.`
