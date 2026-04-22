# Validation Decision Rule

This document defines how to judge the wedge after 15-20 conversations.

## What counts as real validation

Count the wedge as validated only if at least 6 of the 15-20 conversations meet all of these conditions:

- the person is in one of the target roles or directly reports to one
- they already have a real internal coding-agent workflow live or in active pilot
- they name execution control or exfiltration risk as a real blocker, not a hypothetical concern
- self-hosted execution control is acceptable or preferred
- receipts or signed run evidence matter to the internal review process
- they can describe a narrow 6-8 week pilot with one workflow and one or two policy paths

Validation is strongest if at least 3 of those 6 are willing to move into an actual pilot design conversation in the current or next quarter.

## What counts as weak interest

Treat the signal as weak interest if the conversation sounds positive but one or more of these are true:

- they do not have a live or active coding-agent workflow
- they are curious but cannot name a concrete blocker
- they like the idea of receipts but do not actually need them for review
- they want a hosted product, not self-hosted execution control
- they agree to "stay in touch" but cannot define a next step tied to a workflow

Weak interest should not be counted as wedge validation.

## What forces wedge narrowing

Narrow the wedge further if, across the 15-20 conversations, you repeatedly hear one clear sub-problem but not the full current pitch. Examples:

- receipts matter, but only for one regulated engineering workflow
- self-hosted matters, but only for source-code-sensitive repos
- the buyer is always platform, never security
- the second policy path adds confusion and the only consistently valued control is direct egress denial

If one narrow pattern appears in at least 5 conversations, rewrite the wedge around that narrower problem before expanding anything else.

## What forces wedge rejection

Reject the current wedge if any of these are true after 15-20 conversations:

- fewer than 4 conversations reveal a real internal coding-agent workflow plus a real execution-control blocker
- fewer than 3 target buyers say self-hosted execution control is acceptable or preferred
- fewer than 3 say receipts or signed evidence materially matter
- the dominant answer is "a generic hosted sandbox is enough"
- the dominant requirement is a product surface Aegis explicitly does not have and should not build for this wedge

The purpose of these conversations is not to collect general enthusiasm. It is to learn whether a narrow self-hosted execution-control wedge for internal coding agents is urgent enough to deserve continued focus.
