# Cloud Architecture Security Cheat Sheet

## Introduction

This cheat sheet will discuss common and necessary security patterns to follow when creating and reviewing **cloud architectures.** Each section will cover a specific security guideline or cloud design decision to consider. This sheet is written from a medium to large scale enterprise system, so additional overhead elements will be discussed, which may be unecessary for smaller organizations.


### Table of Contents
- Risk Analysis, Threat Modeling, and Attack Surface Modeling
- Public and Private Resources
- Trust Boundaries
- Security Tooling
- Tooling Limitations
- Managed vs Un-Managed Tooling


## General Guidelines

### Risk Analysis, Threat Modeling, and Attack Surface Assessments

With any application or architecture, understanding the risk and threats is extremely important for properly security. No one can spend their entire budget or bandwidth focus on security, and a product must be delivered at some point, so properly allocating security resources is necessary.
With this in mind, enterprises must perform risk assessments, threat modeling activites, and attack surface assessments to identify the following:
- What threats the application might face
- The likelihood of those threats actualizing as attacks
- The attack surface with which those attacks could be targeted
