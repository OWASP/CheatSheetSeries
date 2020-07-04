# Threat Modeling Cheat Sheet

## Introduction

Threat modelling works to identify, communicate, and understand threats and mitigations within the context of protecting something of value. Threat modeling can be performed on a wide range of processes and systems.

This cheat sheet provides guidence on how to...

## The 4 Questions

### What Are We Building

The first step is to define the scope of the Threat Model. It can be helpful to draw a [Data-flow diagram](https://en.wikipedia.org/wiki/Data-flow_diagram) at this stage to help visualise and understand the context of the system and the scope of the Threat Model.

#### Things to Do

- Scope to what is under your control.
- Understand the context your system will live in. This includes, but is not limited to, the environment, security controls, etc
- If you get stuck either:
    - Look at the entry and exit points of the system.
    - Ask the Subject Matter Expert (SME) to explain a user story or scenario.

#### Things to Avoid

- Avoid going beyond or deeper than design level.
- Avoid using the Threat Modeling process like a kitchen sink; don’t try to put everything in a single Threat Model.

### What Can Go Wrong

Once the scope of the Threat Model is defined you may begin identifying potential threats. Structures such as [STRIDE](https://en.wikipedia.org/wiki/STRIDE_%28security%29) and [Kill Chain](https://en.wikipedia.org/wiki/Kill_chain) can help with prompts and discussion points.

#### Things to Do

- Include the whole team: security operations, product owners, marketing, and design (don’t limit yourself or shut down the brainstorming too early).
- Use existing libraries, practices, and structures such as: STRIDE, CAPEC, Kill Chain, and Story Mapping (don't reinvent the wheel).
- Capture good notes, use open questions, and own the follow-up process.
- Engage constructively and blamelessly; create a safe space.

#### Things to Avoid

- Avoid getting stuck in a framework or discredit ideas because they don’t fit the framework (do admit when you are stuck and be wary of diminishing returns)

### What Are We Going to Do About It

#### Things to Do

- DO Collaborate, validate and prioritise (findings, threats and first assumptions)
- DO Draw on, extend, and customise existing countermeasures
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
