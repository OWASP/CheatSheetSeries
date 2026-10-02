# Automotive Security Cheat Sheet

## Introduction

This cheat sheet helps developers secure vehicle electronic control units (ECUs), connected services, and companion apps. Start with a [threat model](Threat_Modeling_Cheat_Sheet.md): map external connections, diagnostic access, sensitive data, and paths to safety-critical functions. Agree on safe behavior during security failures with the vehicle's safety engineers; automatically shutting down a moving vehicle can introduce danger. [National Highway Traffic Safety Administration (NHTSA) guidance](https://www.nhtsa.gov/sites/nhtsa.gov/files/2022-09/cybersecurity-best-practices-safety-modern-vehicles-2022-tag.pdf) provides the broader development framework.

## Protect Communications and Inputs

- **Separate trust zones.** Isolate infotainment, wireless connectivity, and diagnostic interfaces from safety-critical controls. Allow only required message flows through gateways. Segmentation limits a compromise's reach; it does not authenticate messages within a segment.
- **Authenticate vehicle messages.** Conventional Controller Area Network (CAN) does not authenticate senders. Use platform-supported protection such as [AUTOSAR Secure Onboard Communication (SecOC)](https://www.autosar.org/fileadmin/standards/R25-11/CP/AUTOSAR_CP_SWS_SecureOnboardCommunication.pdf), with freshness checks to reject replay. SecOC authenticates configured message data; it does not encrypt traffic or prevent bus flooding. A compromised sender can still produce authenticated messages.
- **Protect external connections.** Use [Transport Layer Security (TLS)](Transport_Layer_Security_Cheat_Sheet.md) with certificate validation for vehicle-to-backend and app connections. Authenticate vehicles individually; an encrypted connection alone does not authorize commands.
- **Validate before acting.** Check message lengths, types, ranges, and whether an action is permitted in the current vehicle state, even for authenticated inputs. See [Input Validation](Input_Validation_Cheat_Sheet.md). Authentication does not establish that a sensor reading is physically correct.

## Verify Software and Updates

- **Verify before execution.** Use secure boot with a protected trust root to authenticate the boot chain. Include recovery firmware. [National Institute of Standards and Technology (NIST) guidance, sections 4.3–4.4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf) covers verification and recovery. Secure boot does not prevent runtime exploitation of trusted but vulnerable software.
- **Authenticate updates on the ECU.** For over-the-air (OTA) and workshop updates, verify signed metadata, image hashes, target hardware, freshness, and rollback policy. Follow [Uptane's update verification requirements](https://uptane.org/docs/2.1.0/standard/uptane-standard#543-installing-images-on-primary-or-secondary-ecus); transport encryption alone cannot establish update authenticity.
- **Plan safe recovery.** Activate updates only under agreed safe vehicle conditions. Recover from interrupted installation using authenticated software, without bypassing rollback protections. Signatures do not establish that software is free of vulnerabilities; protect the [software supply chain](Software_Supply_Chain_Security_Cheat_Sheet.md) too.

## Restrict Access and Protect Data

- **Authorize each operation.** Enforce [authorization](Authorization_Cheat_Sheet.md) for the specific vehicle and action in backend services and vehicle command handlers. Separate owner, fleet, and service privileges. Revoke previous users' access when ownership or rental access ends.
- **Protect service interfaces.** Disable unnecessary production debug access; authenticate and restrict necessary diagnostic functions while preserving authorized repair. Physical access is not authorization. See [NHTSA sections 7–8.4](https://www.nhtsa.gov/sites/nhtsa.gov/files/2022-09/cybersecurity-best-practices-safety-modern-vehicles-2022-tag.pdf#page=16).
- **Protect keys and stored data.** Avoid shared fleet-wide access secrets. Use hardware-backed key protection where available, with renewal and revocation procedures. Minimize retained location and personal data; [encrypt sensitive storage](Cryptographic_Storage_Cheat_Sheet.md) with keys protected separately from the data. Encryption limits offline extraction, but software authorized to decrypt data can still expose it.

## Test and Maintain Security

Follow [NHTSA's lifecycle practices, section 4.2](https://www.nhtsa.gov/sites/nhtsa.gov/files/2022-09/cybersecurity-best-practices-safety-modern-vehicles-2022-tag.pdf#page=8):

- Track component versions against deployed vehicles so vulnerabilities lead to targeted fixes. Agree with suppliers on patch ownership and support duration.
- Test rejected commands, malformed inputs, replay handling, and interrupted updates on isolated benches or simulators. Verify both security enforcement and safe failure behavior before vehicle deployment.
- Log authentication failures, privileged operations, and update results without secrets. Assign responsibility for reviewing events and responding to reports.
- For components that cannot be patched, restrict reachable interfaces and plan replacement. Gateway filtering reduces exposure but does not repair vulnerable firmware.

## References

- [NHTSA: Cybersecurity Best Practices for the Safety of Modern Vehicles](https://www.nhtsa.gov/sites/nhtsa.gov/files/2022-09/cybersecurity-best-practices-safety-modern-vehicles-2022-tag.pdf)
- [AUTOSAR R25-11: Specification of Secure Onboard Communication](https://www.autosar.org/fileadmin/standards/R25-11/CP/AUTOSAR_CP_SWS_SecureOnboardCommunication.pdf)
- [Uptane Standard 2.1.0: Update Verification and Installation](https://uptane.org/docs/2.1.0/standard/uptane-standard#543-installing-images-on-primary-or-secondary-ecus)
