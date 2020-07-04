# Threat Modeling Cheat Sheet

## Introduction

Threat modelling works to identify, communicate, and understand threats and mitigations within the context of protecting something of value. Threat Modeling is a team activity that can be performed on a wide range of procedures and systems.

This cheat sheet provides guidance on how to identify threats, validate threats, and prioritize threats using the Threat Modeling process.

## The 4 Questions

### What are we building

The first step is to define the scope of the Threat Model. It can be helpful to draw a [Data-flow diagram](https://en.wikipedia.org/wiki/Data-flow_diagram) with the team to help conceptualize the context of the system which may help to inform the scope of the Threat Model. Ensure that the scope of the Threat Model does not contain systems or procedures that you do not control.

#### Things to do

- Scope to what is under your control.
- Understand the context your system will live in. This includes, but is not limited to, the environment, security controls, etc
- If you get stuck either:
    - Look at the entry and exit points of the system.
    - Ask the Subject Matter Expert (SME) to explain a user story or scenario.

#### Things to avoid

- Avoid going beyond or deeper than the design level.
- Avoid using the Threat Modeling process like a kitchen sink; don’t try to put everything in at once.

### What can go wrong

Once the scope of the Threat Model is defined and the context is understood you may begin identifying potential threats. Structures such as [STRIDE](https://en.wikipedia.org/wiki/STRIDE_%28security%29) and [Kill Chain](https://en.wikipedia.org/wiki/Kill_chain) can help with prompts and discussion points.

#### Things to do

- Include the whole team: security operations, product owners, marketing, and design (don’t limit yourself or shut down the brainstorming too early).
- Use existing libraries, practices, and structures such as STRIDE, CAPEC, Kill Chain, and Story Mapping (don't reinvent the wheel).
- Capture good notes, use open questions, and own the follow-up process.
- Engage constructively and blamelessly; create a safe space.

#### Things to avoid

- Avoid getting stuck in a framework or discrediting ideas because they don’t fit the framework (do admit when you are stuck and be wary of diminishing returns).

### What are we going to do about it

This section of the Threat Modeling process is concerned with the validation, prioritization and mitigation of the threats identified in the previous section: "What can go wrong".

The [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) provides an approach to calculating the risk for a given threat.

#### Things to do

- Collaborate, validate, and prioritize (findings, threats, and first assumptions)
- Draw on, extend, and customise existing countermeasures:
    - Organisational standards, e.g. Single sign-on (SSO) and web application firewalls (WAF)
    - Common standards, e.g. access control lists (ACL) and password hashing
- Write tests and test cases
- Integrate with partner or team tools and processes

#### Things to avoid

- Avoid confusing "can" and "should"

### Did we do a good enough job

It is important to continuously review the priority and risk associated with the identified threats and to review the Threat Modeling process as a whole. Organize retrospectives with the team to help inform the Threat Modeling process so that it meets your team's needs. Ensure that outputs from the previous section ("What are we going to do about it") are shared and actioned by the team.

#### Things to do

- Follow up and document actionable outputs
- Follow up with a survey and a Lessons Learned retrospective
- Keep what works and lose what fails
- Action the outputs
- Continuously validate the process
- Compare Q1 (what are we building) with Q3 (what are we going to do about it)
- Validate assumptions
- Compare outputs with bug bounty submissions, penetration test findings and audit findings
- Share outputs with the whole team

#### Things to avoid

- Do not skip this step!
