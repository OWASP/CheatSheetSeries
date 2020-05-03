---
title: Secure SDLC Cheat Sheet
permalink: /Secure_SDLC_Cheat_Sheet/
---

DRAFT CHEAT SHEET - WORK IN PROGRESS
====================================

Background
==========

This cheat sheet provides a quick reference on the most important initiatives to build security into multiple parts of software development processes. This cheat sheet is based on the OWASP Software Assurance Maturity Model ([SAMM](/OWASP_SAMM_Project\ "wikilink")) which can be integrated into any existing SDLC.

SAMM is based around a set of 12 security practices, which are grouped into 4 business functions. Every security practice contains a set of activities, structured into 3 maturity levels. The activities on a lower maturity level are typically easier to execute and require less formalization than the ones on a higher maturity level.

The structure and setup of the **SAMM maturity model** are made to support:

1.  The **assessment** of the current software assurance posture
2.  The definition of the **strategy** (i.e. the target) that the organization should take
3.  The formulation of an implementation **roadmap** of how to get there and
4.  Prescriptive advice on how to **implement** particular activities.

In that sense, the value of SAMM lies in providing a means to know where your organization is on its journey towards software assurance, and to understand what is recommended to move to a next level of maturity. Note that SAMM does not insist that all organizations achieve maturity level 3 in every category. Indeed, you determine the target maturity level for each Security Practice that is the best fit for your organization and its needs. SAMM provides a number of templates for typical organizations to this end, but you can adapt these as you see fit.

How to Apply
============

A typical approach of using SAMM in an organization is as follows:

{\\| class="wikitable" ! scope="col" \\| Step ! scope="col" \\| Purpose ! scope="col" \\| Activities ! scope="col" \\| Resources ! scope="col" \\| Best Practices \\|- \\| Step 1 - **Assess** \\| Ensure a proper start of the project \\| **Define the scope** Set the target of the effort (The entire enterprise, a particular application or project or team etc.)

**Identify Stakeholders**

Ensure that important stakeholders supposed to support and execute the project are identified and well aligned

**Spread the word**

Inform people about the initiative and provide them with information to understand what you will be doing \\| **Consider involving at least:**

-   Executive Sponsor
-   Security Team
-   Developers
-   Architects
-   Business Owners
-   QA Testers
-   Managers

The OpenSAMM main site: <http://www.opensamm.org/>

The model in .pdf: <http://www.opensamm.org/> \\| Pre-screen software development maturity to have realistic expectations The smaller the scope, the easier the exercise \\|- \\| Step 2 - **Assess** \\| Identify and understand the maturity of your chosen scope in each of the 12 software security practices \\| **Evaluate current practices** Organize interviews with relevant stakeholders to understand the current state of practice within your organization. You could evaluate this yourself if you understand the organization sufficiently well. SAMM provides lightweight and detailed assessments (where the latter is an evidence-based evaluation) – use the detailed one only if you want to have absolute certainty about the scores.

**Determine maturity level**

Based on the outcome of the previous activity, determine for each security practice the maturity level according to the SAMM maturity scoring system. In a nutshell, when all activities below and within a maturity level have been implemented, this level can be used for the overall score. When extra higher-level activities have been implemented without reaching a full next level, add a "+" to the rating. \\| The OpenSAMM toolbox <http://LINK>

Online Self Assessment Tool

<https://github.com/AsteriskLabs/ssa>

Both of these resources provide you with:

-   Assessment questions
-   Maturity level calculation

\\| Ensure consistent assessment for different stakeholders and teams by using the same questions and interviewer Consider using different formats to gather data (e.g., workshops vs. interviews. Ensure interviewees understand the particularities of activities. Understand which activities are not applicable to the organization and take this into account in the overall scoring. Anticipate/document whether you plan to award partial credit, or just document various judgement calls. Repeat questions to several people to improve the assessment quality Consider making interviews anonymous to ensure honesty Don't take questions too literally) \\|- \\| Step 3 - **Set the target** \\| Develop a target score that you can use as a measuring stick to guide you to act on the "most important" activities for your situation \\| **Define the target**

Set or update the target by identifying which activities your organization should implement ideally. Typically this will include more lower-level than higher-level activities. Predefined roadmap templates can be used as a source for inspiration. Ensure that the total set of selected activities makes sense and take into account dependencies between activities.

**Estimate overall impact**

Estimate the impact of the chosen target on the organization. Try to express in budgetary arguments. \\| See the How-To-Guide for predefined templates Software Assurance Maturity Model (SAMM) Roadmap Chart Worksheet (part of the OpenSAMM Benchmarking as a comparative source) \\| Take into account the organisation's risk profile Respect dependencies between activities As a rough measure, the overall impact of a software assurance effort is estimated at 5 to 10% of the total development cost. \\|- \\| Step 4 - **Define the plan** \\| Develop or update your plan to take your organization to the next level \\| **Determine change schedule** Choose a realistic change strategy in terms of number and duration of phases. A typical roadmap consists of 4-6 phases of 3 to 12 months.

**Develop / Update the roadmap plan**

Distribute the implementation of additional activities over the different roadmap phases, taking into account the effort required to implement them.. Try to balance the implementation effort over the different periods, and take dependencies between activities into account \\| Software Assurance Maturity Model : A guide to building security into software development page 33: <http://www.opensamm.org/>

Project Plan <http://www.opensamm.org/downloads/> \\| Identify quick wins and plan them early on Start with awareness/training Adapt to coming release cycles / key projects \\|- \\| Step 5 - **Implement** \\| Work the plan \\| **Implement activities** Implement all activities that are part of this period. Consider their impact on processes, people, knowledge and tools. The SAMM model contains prescriptive advice on how to do this. OWASP projects may help to facilitate this. \\| Useful OWASP resources per activity are described at <https://owasp.org> \\| Treat legacy software separately. Do not mandate migration unless really important. Avoid operational bottle-necks (in particular for the security team) \\|- \\| Step 6 - **Roll out** \\| Ensure that improvements are available and effectively used within the organization \\| **Evangelize Improvements** Make the steps and improvements visible for everyone involved by organizing training and communicating.

**Measure effectiveness**

Measure the adoption and effectiveness of implemented improvements by analyzing usage and impact. \\| \\| Categorize applications according to their impact on the organization. Focus on high-impact applications. Use team champions to spread new activities throughout the organization \\|}

As part of a quick start effort, the first four phases (preparation, assess, setting the target and defining the plan) can be executed by a single person in a limited amount of time (1 to 2 days). Making sure that this is supported in the organization, as well as the implementation and roll-out phases typically require much more time to execute.

Final Notes
===========

The best way to grasp SAMM is to start using it. This document has presented a number of concrete steps and supportive material to execute these. Now it's your turn. We warmly invite you to spend a day or two on following the first steps, and you will quickly understand and appreciate the added value of the model. Enjoy! Suggestions for improvements are very welcome. And if you're interested, consider to join the mailinglist or become part of the OpenSAMM community

------------------------------------------------------------------------

[Category:Cheatsheets](/Category:Cheatsheets "wikilink") [Category:OWASP_Builders](/Category:OWASP_Builders "wikilink")
