# Threat Modeling Cheat Sheet

## Introduction

Threat Modeling is a team activity, facilitated by one or two people, whereby sections of a system or process are laid out infront of the team and are reviewed for potential security vulnerabilities.

TODO, why should I care, what is the output etc.

## Getting started

Threat modeling can be done at any time, however the most fitting time to threat model a system or process is just after the design phase. Threat modeling after the design phase will both help to highlight potential vulnerabilities and inform the necessary countermeasures, all before a line of code is written. 

Threat modeling can also be performed retrospectively on existing systems or processes to help identify current vulnerabilites.

### Agree on the scope

TODO, agree what is in scope and out of scope, only threat model the bits you have control over. Explain TM-ing an entire system may take a long time, better to focus on parts of the domain (vertically sliced)? e.g. authorisation flow, user management, account management etc.

### Visualize the system

TODO, draw out the system, using C4 or a simple DFD (boxes and lines even), on whiteboard, pen/paper, online diagram tools, important to keep these diagrams up to date going forward

### Identify threats

TODO, step through the diagram with team using STRIDE or LINDUNN, important to stick with a particular risk framework the first few times and then make changes/improvements as you become more comfortable with the TM process.

### Share the results

TODO, document and share findings with team, score each identified risk high, medium, low (OWASP risk rating?), priotise with team and fix.
