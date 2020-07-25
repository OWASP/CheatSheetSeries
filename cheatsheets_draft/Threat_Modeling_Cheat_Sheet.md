# Threat Modeling Cheat Sheet

## Introduction

Threat Modeling is a team activity, facilitated by one or two people, whereby sections of a system or process are laid out in front of the team and are reviewed for potential security vulnerabilities.

TODO, why should I care, what is the output etc.

## Getting started

Threat modeling can be done at any time, however, the most fitting time to threat model a system or process is just after the design phase. Threat modeling after the design phase will both help to highlight potential vulnerabilities and inform the necessary countermeasures, all before a line of code is written.

Threat modeling can also be performed retrospectively on existing systems or processes to help identify current vulnerabilities.

It can be useful at this point to split your entire system or entire process into key domain areas, for example: authorization flow, user management, account management, and order management. These domain areas should be vertical slices through the system. Threat modeling each of these domain areas individually will help you and the team focus your attention on the data flowing through a given area and at which key points in the system data is validated, updated, stored, returned, and deleted.

TODO image showing different parts of an example domain split up?
TODO who is needed

### Agree on the scope

Before anything else, you must agree with the team on what should be threat modeled and what shouldn't be threat modeled. Although potentially interesting it may not be beneficial to spend time threat modeling parts of a system you have little control over. The scope of a threat model impacts how long the threat modeling session runs for: the larger the scope, the longer the session.

### Visualize the system

TODO, draw out the system, using C4 or a simple DFD (boxes and lines even), on whiteboard, pen/paper, online diagram tools, important to keep these diagrams up to date going forward

### Identify threats

TODO, step through the diagram with team using STRIDE or LINDUNN, important to stick with a particular risk framework the first few times and then make changes/improvements as you become more comfortable with the TM process.

### Share the results

TODO, document and share findings with team, score each identified risk high, medium, low (OWASP risk rating?), priotise with team and fix.
