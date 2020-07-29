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

Once you have a good idea about which part of the wider system or wider process you're going to threat model, and what is in scope and out of scope, you're ready to diagram it.

Spending the time to diagram what you're going to threat model will provide you with a piece of documentation which can be used as a tangible discussion point by the team. Diagraming as a team will help team members understand which types of data are in present in the system, and how data flows through the system. Having a clear diagram to guide and inform discussions can help keep the conversations and questions relevant.

System diagrams (for the purposes of threat modeling) don't have to be elegant. Diagrams drawn using a whiteboard and dry marker, or pen and paper, are more than enough to facilitate a threat modeling session. Making a digital copy of these diagrams after the session is beneficial as digital copies are easier to keep up to date. If team members are separated and are working from different locations, online whiteboarding or diagramming tools may be used.

System diagrams drawn as part of a threat model should be kept fairly high level, concerned more with components and context and less concerned with exact implementations. It is very easy to become bogged down in the smaller details. You may also have less experienced members of the team present, so drawing high level diagrams will make it easier for them to contribute.

[C4](https://c4model.com/) is a model that defines a set of patterns for documenting system architectures in a clear and consistent way. The different levels of C4 diagrams [can be seen here](https://c4model.com/#CoreDiagrams). Generally, Level 2 diagrams provide enough detail for threat modelling.

TODO example C4
TODO include DFD's, or is there enough with C4 alone?

### Identify threats

TODO, step through the diagram with team using STRIDE or LINDUNN, important to stick with a particular risk framework the first few times and then make changes/improvements as you become more comfortable with the TM process.

### Share the results

TODO, document and share findings with team, score each identified risk high, medium, low (OWASP risk rating?), priotise with team and fix.
