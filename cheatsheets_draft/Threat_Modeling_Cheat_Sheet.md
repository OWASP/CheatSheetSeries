# Threat Modeling Cheat Sheet

## Introduction

TODO: Add an introduction that could summarize the CS in a couple of lines.

## The 4 Questions

### What Are We Building

#### Things to Do

- DO Scope to what is under your control.
- DO Understand the context your system will live in. This includes but is not limited to the environment, security controls, etc
- DO If you get stuck, either look at the entry and exit points OR let the Subject Matter Expert (SME) tell a story to get back on track.

#### Things to Avoid

- DON’T Go beyond/deeper than design level.
- DON’T Use Threat Modeling like a kitchen sink, don’t try to put everything in.

### What Can Go Wrong

#### Things to Do

- DO Use the whole team: including security operations, product owner, marketing and design usability (don’t limit yourself or shut down the brainstorm too early)
- DO Use existing libraries, practices and structures such as STRIDE, CAPEC, Kill Chain, Story Mapping (don’t reinvent the wheel)
- DO Capture good notes, use open questions, and own the follow-up process
- DO Engage constructively and blamelessly - create a safe space

#### Things to Avoid

- DON’T Get stuck in a framework, or discredit ideas because they don’t fit the framework (do admit when you are stuck and be wary of diminishing returns)

### What Are We Going to Do About It

#### Things to Do

- DO Collaborate, validate and prioritise (findings, threats and first assumptions)
- DO Draw on, extend and customise existing countermeasures
    - Organisational standards - SSO and WAF
    - Common standards - USE ACL and Hash PW
- DO Write tests and test cases
- DO Integrate with partner or team tools and processes

#### Things to Avoid

- DON’T Confuse can and should

### Did We Do a Good Enough Job

#### Things to Do

- DO Follow Up and Actionable Outputs
- DO Follow up with Survey and Lessons Learned
- DO Keep what works and lose what fails
- DO Actioned Items
- DO Continuous Validation
- DO Compare Q1 (what we are building) with Q3 (what we built)
- DO Validate Assumptions
- DO Compare outputs with Bug Bounty, Pen Test and Audit Findings
- DO Share outputs with whole team

#### Things to Avoid

- DON’T Skip this step!
