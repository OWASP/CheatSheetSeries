# Software Supply Chain Security

## Introduction

No piece of software is developed in a vacuum; regardless of the technologies used to develop it, software is embedded in a Software Supply Chain (SSC). According to [NIST](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204D.pdf), an entity's SSC can be defined as "a collection of steps that create, transform, and assess the quality and  policy conformance of software artifacts". From a developer's perspective, these steps span the entire SDLC and are accomplished using a wide range of components and tools. Common examples (by no means exhaustive) of components that are especially relevant from a developer's perspective include:

- IDEs and code editors
- Internally developed source code
- Third-party software libraries
- Version control systems (VCS)
- Build tools (Maven, Rake, make, Grunt, etc.)
- CI/CD software (Jenkins, CircleCI, TeamCity, etc.)
- Configuration management tools (Ansible, Puppet, Chef, etc.)
- Package management software and ecosystems (pip, npm, Composer, etc.)

Each of these components must be secured; a flaw in a single component, such as a vulnerable third-party dependency or misconfigured VCS, can put an entire SSC in jeopardy. Thus, in order to strengthen Software Supply Chain Security (SCSS), developers should possess a general understanding of what the SSC is, common threats against it, and practices and techniques that can be applied to reduce SSC risk.

## Overview of Threat Landscape

Given the breadth and complexity of the SSC, it is unsurprising that the threat landscape for SSC is similarly expansive. Threats include [dependency confusion](https://fossa.com/blog/dependency-confusion-understanding-preventing-attacks/), compromise of an upstream providers infrastructure, theft of code signing certificates, and CI/CD system exploits. More broadly, threats may be grouped into four categories based upon what component of the supply chain they seek to compromise [[4,5](#references)]:

- Source code threats. These type of threats focus on violating the integrity of a source code which is then built and and deployed or potentially consumed by other software projects. Threats in this category include VCS exploits, the introduction of malicious or vulnerable code into a code base, or building code from an unauthorized branch.
- Build environment threats. These threats modify a software artifact but without altering the underlying source code or exploiting the build process itself. Examples include build cache poisoning, compromising a privileged account used by the build system, or publishing software built from an untrusted source.
- Dependency related threats. Threats that result from the consumption of both direct and transitive software dependencies. The most common threat is using a vulnerable or compromised dependency.
- Deployment and runtime threats. These threats exploit either the deployment process or runtime environment. Common examples include compromising a privilege CI/CD account, software misconfigurations, and deployment of compromised binaries.

The characteristics of threat actors seeking exploit the SSC are similarly diverse. Although SSC compromise is often associated with highly sophisticated threat actors, such sophistication is not inherently necessary for attacking the SSC, especially if the attack focuses on compromising the SSC of entities with poor security practices. Threat actor motive also varies widely, A SSC exploit can result in loss of confidentiality, integrity, and/or availability of any organization's assets and thus fulfill a wide range of attacker goals such as espionage or financial gain.

Finally, it must be recognized that many SSC threats have the capability to propagate across many entities. This is due to consumer-supplier relationship that is integral to an SSC. For example, uf a large-scale software supplier, whether proprietary or open-source, is compromised, many downstream, consuming entities could also be impacted as a result. The 2020 Solarwind and 2021 Codecov incidents are excellent real-world examples of this.

## Mitigations and Security Best Practices

Mitigating SSC related risk can seem daunting, yet it need not be. Even for sophisticated attacks that may focus on compromising upstream suppliers, individual organization can take reasonable steps to defend its own assets and mitigate risk even if its supplier is compromised. Although some parts of SSCS may remain outside direct control of development teams, those teams must still do their part to improve SSCS in their organization; the guidance below is intended as starting point for developers to do just that.

### General

The practices described below are general techniques that can be used to mitigate risk related to a wide variety of threat types.

#### Implement Strong Access Control

  Compromised accounts, particularly privileged ones, represents a significant threats to SSCs. Account takeover can allow an attacker can perform a variety of malicious acts including injecting code into legitimate dependencies, manipulating CI/CD pipeline execution, and replacing a benign artifact with a malicious one. Strong access control for build, development, version control, and similar environments is thus critical. Best practices include adhering to  the basic security principles of least privileges and separation of duties, enforcing MFA, rotating credentials, and ensuring credentials are never stored or transmitted in clear text or committed to source control.

#### Logging and Monitoring

  When considering SSCS, the importance of detective controls should not be overlooked; these controls are essential for detecting attacks and enabling prompt respond. In the context of SSCS, logging is critical. All systems involved in the SSC, including VCS, build tools, delivery mechanisms, artifact repositories, and the systems responsible for running applications should be configured to log authentication attempts, configuration changes, and other events that could assist in identifying anomalous behavior or that could prove crucial for incident response efforts. Logs throughout the SSC must be sufficient in both depth and breadth to support detection and response

  However, logging events is not sufficient. These logs must be monitored, and, if necessary, acted upon. A centralized SIEM, log aggregator, or similar tool is preferred, especially given the complexity of SSCs. Regardless of the technology used, the basic objective remains the same: log data should be actionable.

#### Leverage Security Automation

For complex SSCs, automation of security tasks, such as scanning, monitoring, and testing is critical. Such automation, while not a replacement for manual reviews and other actions performed by skilled professionals, is capable of detecting, and in some cases responding to, vulnerabilities and potential attacks with a scale and consistency that is hard to achieve through manual human intervention. Types of tools that support automation include SAST, DAST, SCA, container image scanners and more. The exact tools most capable of delivering value to an organization will vary significantly based on the characteristics of the organization. However, regardless of the type of tools and vendors used, it is important to acknowledge that these tools themselves must be mainlined, secured, and configured correctly. Failure to do so could actually increase SSC risk for an organization, or at the very least, fail to bring meaningful benefit to the organization. Finally, it must be clearly understood that these tools are but one component of an overall SSCS program; they cannot be considered a comprehensive solution or be relied on to identify all vulnerabilities.

### Mitigating Source Code Threats

The practices described below can help reduce SSC risk associated with source code and development.

#### Peer Reviews

Manual code reviews are an important, relatively low cost technique for reducing SSC risk; these reviews can act as both detective controls and deterrents. Reviews should be performed by peers possessing both experience in the technology being used and secure coding processes and should occur before code is merged within a source control systems [[3](#references)]. The reviews should look for both unintentional security flaws as well as intentional code that could serve malicious purposes. The results of the review should be documented for later review if needed.

#### Secure Config of Version Control Systems

Compromise or abuse of the source control system is consistently recognized as a significant SSC risk [[4,5](#references)]. The general security best practices of strong access control and logging and monitoring are two methods to help secure VCS. Security features specific to the VCS system, such as protected branches and merge policies in git, should also be leveraged. You can find a wide variety of recommended policies in this [documentation](https://policies.legitify.dev/). There are tools available to help manage configuration of SCM systems, such as [Legitify](https://github.com/Legit-Labs/legitify), an open-source tool by [Legit security](https://www.legitsecurity.com/). Legitify is designed to detect misconfigurations in GitHub and GitLab and assist with the implementation of best practices. Regardless of any security controls added a VCS, it must be remember that secrets should never be committed to these systems.

#### Secure Development Platform

IDEs, development plugins, and similar tools can help assist the development process. However, like all pieces of software, these components can have vulnerabilities and become an attack vector. Thus, it is important to take steps not only to ensure these tools are used securely, but also to secure the underlying system. The development system should have endpoint security software installed and should have threat assessments performed against it [[2](#references)]. Only trusted, well-vetted software should be used in the development process; this includes not only "core" development tools such as IDEs, but also any plugins or extensions.  Additionally, these tools should be included as part of an organization's system inventory.

### Mitigating Dependency Threats

Best practices and techniques related to secure use of dependencies are described below.

#### Assess Suppliers

Before incorporating a third-party service, product, or software component into the SSC, the vendor and specific offering should both be thoroughly assessed for security. This applies to both open-source and proprietary offerings. The form and extent of the analysis will vary substantially in accordance with both the criticality and nature of the component being considered. Component maturity, security history, and the vendor's response to past vulnerabilities are useful information in nearly any case. For larger vendors or service offerings, determining whether or not a solution has been evaluated against third-party assessments and certifications, such as those performed against [FedRAMP](https://marketplace.fedramp.gov/products), [CSA](https://cloudsecurityalliance.org/star/registry), or various ISO standards (ISO/IEC 27001, ISO/IEC 15408,
ISO/IEC 27034), can be a useful data point, but must not be relied on exclusively.

Due to its transparent nature, open-source projects offer additional assessment opportunities. Questions to consider include [[6](#references)]:

- Is the project actively maintained?
- Is the project sufficiently popular and well-known in the applicable community?
- Is the project sufficiently mature?
- Is the product or version being evaluated a "release" version, e.g. not an alpha, beta, or comparable versions?
- Given the complexity of the project, does the project have a sufficient number of maintainers and contributors?
- Does the project keep its dependencies updated?
- Does the project have sufficient test coverage and do the tests include security relevant rules?
- Is the project well-documented and does the document include guidance on how to use the component securely?
- Does the project have an established and documented process for reporting vulnerabilities and are these vulnerabilities addressed in a timely manner?
- Is the intended usage of the project consistent with the project's license?

#### Understand and Monitor Software Dependencies

While third-party software dependencies can greatly accelerate the development process, they are also one of the leading risks associated with modern applications. Dependencies must not only be carefully selected before they are incorporated into an application, but also carefully monitored and maintained throughout the SDLC. In order achieve this, having insight into the various dependencies consumed by software is a crucial first step. To facilitate this, SBOMs may be used. Both production and consumption of these SBOMs should be automated, preferably as part of the  organization's CI/CD process.

Once the organization has inventoried depdencies, it must also monitor them for known vulnerabilities. This should also be automated as much as possible; tools such as [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/) or [retire.js](https://retirejs.github.io/retire.js/) can assist in this process. Additionally, sources such as the [NVD](https://nvd.nist.gov/), [OSVDB](https://osv.dev/list), or [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) may also be monitored for known vulnerabilities related to dependencies used in the organization's SSC.

#### SAST

Although using SAST to detect potential security in custom developed code is a widely used security technique, it can also be used on OSS components within the SSC [[2](#references)]. As when using SAST on internally developed code, one must recognize that these tools can produce both false positives and false negatives. Thus, SAST results must not be accepted without manual verification and should not be interpreted as providing a comprehensive view of the project's security. However, as long as their limitations are understood, SAST scans can prove useful when analyzing both internally developed or OSS code.

#### Lockfile/Version Pinning

To reduce the likelihood that a compromised or vulnerable version is unwittingly pulled into an application, one should limit the applications dependencies to a specific version that has been previously verified as legitimate and secure. This is commonly accomplished using lockfiles such as the package-lock.json file used by npm.

### Build Threats

The section below describes techniques that are especially relevant for securing build related threats.

#### Inventory Build Tools

Knowing the components used in the SSC is essential to the security of that SSC. This concept extends to build tools. An inventory of all build tools, including versions and any plugins, should be automatically collected and mainlined, One must also monitor vulnerability databases, vendor security advisories and other sources for any vulnerabilities related to the identified build tools.

#### Harden Build Tools

Compromised build tools can enable a wide range of exploits and thus represent an appealing target for attackers. As such, all infrastructure and tools used in build process must be hardened to mitigate risk. Techniques for hardening build environments include [[2](#references)]:

- Ensure build tools are located in an appropriately segregated networks.
- Use DLP and other tools and techniques to detect and prevent exfiltration.
- Disable/remove any unused services.
- Use version control systems to manage and store pipeline configurations.

#### Enforce Code Signing

From a the perspective of software consumers, only accepting components which have been digitally signed and validating the signature before utilizing the software is an important task step in ensuring the component is authentic and has not been tampered with. For those performing code signing, it is imperative that the code signing infrastructure is thoroughly hardened. Failure to do so can result in compromise of the code signing system and lead further exploits, including those targeting consumers of the software.

#### Use Private Artifact Repository

Using a private artifact repository increases the control an organization has over the various artifacts that are used within the SSC. Artifacts should be reviewed before being allowed in the private repository and organizations must ensure that usage of these repositories cannot be bypassed. Although usage of private repositories can introduce extra maintenance or reduce agility, they can also be an important component of SSCS, especially for sensitive or critical applications.

#### Use Source Control for Build Scripts and Config

The benefits of VCSs can be realized for items beyond source control; this is especially true for config and scripts related to CI/CD pipelines. Enforcing version control for these files allows one to incorporate reviews, merge rules, and like controls into the config update process. Using VCS also increase visibility, allowing one easy visibility into any changes introduced, whether malicious or benign [[2](#references)].

#### Verify Provenance/Ensure Sufficient Metadata is Generated

Having assurance that an SSC component comes from a trusted source and has not been tampered with is a important part of SSCS. Generation and consumption of provenance, defined in [SLSA 1.0](https://slsa.dev/spec/v1.0/provenance) as "the verifiable information about software artifacts describing where, when and how something was produced" is an important part of this. The provenance should be generated by the build platform (as opposed to a local development system), be very difficult for attackers to forge, and contain all details necessary to accurately link the result back to the builder [[7](#references)]. SLSA 1.0 compliant provenance can be generated using builders such as [FRSCA](https://github.com/buildsec/frsca) or [Github Actions](https://github.com/slsa-framework/slsa-github-generator) and verified [using SLSA Verifier](https://github.com/slsa-framework/slsa-verifier?tab=readme-ov-file)

#### Ephemeral, Isolated Builds

Reuse and sharing of build environments may allow attackers to perform cache poising or otherwise more readily inject malicious code.  Builds should be performed in isolated, temporary ("ephemeral") environments. This can be achieved using technologies such as VMs or containers for builds and ensuring the environment is immediately destroyed afterward.

#### Limit use of Parameters

Although passing user controllable parameters to a build process can increase flexibility, it also increases risk. If parameters can be modified by users in order to alter how a build is performed, an attacker with sufficient permission will also be able to modify the parameters and potentially compromise the build process [[8](#references)]. One should thus make an effort to minimize or eliminate any user controllable build parameters.

### Deployment and Runtime Threats

The section below outlines a couple of techniques that can be used to protect software during the deployment and runtime phases.

#### Scan Final Build Binary

Once the build process has finished, one should not simply assume that the final result is secure. Binary composition analysis can help detect exposed secrets, detect unauthorized components or content, and verify integrity [[2](#references)]. This task should be performed by both suppliers and consumers.

#### Monitor Deployed Software for Vulnerabilities

SSCS does not end with the deployment of the software; the deployed software must be monitored and maintained to reduce risk. New vulnerabilities, whether introduced due to an update or simply newly discovered (or made public), are a continual concern in software systems [[4](#references)]. When performing this monitoring, a wholistic approached must be used; code dependencies, container images, web servers, and operating system components are just a sampling of items that must be consider. To support this monitoring, an accurate and up-to-date inventory of system components is critical. Additionally, insecure configuration changes must be monitored and acted upon.

## References

1. [NIST SP 800-204D: Strategies for the Integration of Software Supply Chain Security in DevSecOps CI/CD Pipelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204D.pdf)
2. [Securing the Software Supply Chain: Recommended Practices Guide for Developers](https://media.defense.gov/2022/Sep/01/2003068942/-1/-1/0/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN_DEVELOPERS.PDF)
3. [Google Cloud Software Supply Chain Security: Safeguard Source](https://cloud.google.com/software-supply-chain-security/docs/safeguard-source)
4. [Google Cloud Software Supply Chain Security: Attack Vectors](https://cloud.google.com/software-supply-chain-security/docs/attack-vectors)
5. [SLSA 1.0: Threats](https://slsa.dev/spec/v1.0/threats)
6. [OpenSSF: Concise Guide for Evaluating Open Source Software](https://best.openssf.org/Concise-Guide-for-Evaluating-Open-Source-Software)
7. [SLSA 1.0: Requirements](https://slsa.dev/spec/v1.0/requirements#provenance-generation)
8. [Google Cloud Security Supply Chain Security: Safeguard Builds](https://cloud.google.com/software-supply-chain-security/docs/safeguard-builds)
