# Drone Security Cheat Sheet

## Introduction

Drone security is crucial due to their widespread adoption in industries such as military, construction, and community services. With the increasing use of drone swarms, even minor security lapses can lead to significant risks.

This cheat sheet provides an overview of vulnerable endpoints in drone systems and strategies to mitigate security threats.

---

## Drone System Components

A typical drone architecture consists of three main components:

1. **Unmanned Aircraft (UmA)** – The physical drone itself, including its sensors and onboard systems.
2. **Ground Control Station (GCS)** – The interface used to control and monitor drone operations.
3. **Communication Data-Link (CDL)** – The network connection between the drone and the GCS.

![Drone](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Drone_Security_Cheat_Sheet.png)

The communication between the drone and the GCS is vulnerable to interception and attacks. This will be made evident in the future sections as well. It is important to understand that peripherals attached to drone may be vulnerable too! To explain this, we have made a list of **vulnerable endpoints** below.

---

## Vulnerable Endpoints & Security Risks

### 1. Communication Security

- **Insecure Communication Links** – Data transmitted between the drone and GCS can be intercepted if not properly encrypted. Use standard protocols for encryption of any data being sent over.

- **Command Spoofing and Replay Attacks** – Authenticate command messages and reject replayed messages using the protocol's freshness checks. For MAVLink, use [message signing and timestamp validation](https://mavlink.io/en/guide/message_signing.html#accept_signed_packets); encryption alone does not provide these controls.

- **Wi-Fi Weaknesses** – Weak authentication or unprotected channels can allow unauthorized access. This is even possible through simple [microcontrollers like ESP8266](https://github.com/SpacehuhnTech/esp8266_deauther)!

    - Use **802.11w MFP (Management Frame Protection)** to prevent Wi-Fi deauthentication attacks. Don't worry, if your Wi-Fi systems are up-to-date, then this is a default protocol now.

### 2. Authentication & Access Control

Most drone controllers use 2 sets of computers,

1. The main chip that performs the PID control and handles motors

2. An additional SoC (called the **companion computer**) to manage peripherals (like the cameras, LiDARs etc.) and send telemetry data.

Thus, it becomes very important to maintain their security as well. The possible risks in this case are:

- **Companion Computers** – Open ports (e.g., SSH, FTP) can be exploited if not securely configured.

- **User Error and Misconfiguration** – Misconfigured security settings can expose the drone to risks.

### 3. Data Protection

Drones often handle sensitive information (e.g., mission details, sensor logs, or edge AI models) and face a high risk of being lost or captured. Therefore, it's important to protect the onboard data:

- **Storage Encryption** - Ensures data is secure at rest, even if someone gains physical access to the drone while it's powered off. Examples: [LUKS](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/encrypting-block-devices-using-luks_security-hardening) for block-level encryption, [gocryptfs](https://nuetzlich.net/gocryptfs/) for filesystem in userspace, [age](https://github.com/FiloSottile/age) for file encryption.
- **Sensitive Data in RAM** - Store highly sensitive information (e.g, encryption keys, credentials, intellectual property) in RAM and clear after use. Provide this data before mission start using secure channels.

### 4. Physical Security

If your drone is ever captured or lost, you should ensure that it's not physically possible to steal data from it. This may happen under the following conditions:

- **Insufficient Physical Security** – Unsecured USB ports or exposed hardware can lead to data theft or tampering.

- **Insecure Supply Chain** – Compromised components from suppliers can introduce hidden vulnerabilities.

- **End-of-Life Decommissioning Risks** – Improperly decommissioned drones may retain sensitive data or be repurposed maliciously.

### 5. System Integrity

A drone shares many properties with a classical IoT device when it comes to protecting integrity against unauthorized modifications of firmware, software, or configuration. Without these protections, attackers could inject malicious firmware or modify the control stack, gaining persistent and often invisible access - especially if the device is physically accessible to them (e.g., while it is in storage).

Fortunately, IoT also has a number of security controls for such cases:

- **Secure Boot** – Secure Boot ensures that the drone starts only with trusted software:
    - Every piece of firmware is signed with a cryptographic key. Only signed software is allowed to run.
    - A first-stage bootloader is immutable (in ROM or eFuse-locked code). It verifies signature on the second bootloader.
    - Each component verifies the next component (e.g., second stage bootloader -> kernel -> application).

- **Measured Boot** – Measured Boot takes Secure Boot further by recording what software was loaded at each stage. This allows remote systems (like a fleet manager or ground station) to verify that the drone is running only trusted code. It also allows to authorize actions locally, such as releasing decryption keys only when the device boots properly.

- **Firmware Signing** – Ensures that firmware and configuration updates are signed with cryptographic signatures. Implement rollback protection to prevent attackers from loading older, vulnerable firmware versions. It's also a good idea to encrypt firmware packages, especially if they contain sensitive IP.

### 6. Sensor Security

With drones implementing control logic depending on how close they are to other drones or aerial vehicles, manipulating sensor data can be disastrous!

Attackers can manipulate drone sensors (GPS, cameras, altimeters) to feed incorrect data. Think of this more like how [stuxnet](https://en.wikipedia.org/wiki/Stuxnet) changed the speed of the Uranium centrifuges in Iran while still reporting the speed as normal.

To prevent this, there is new research being developed involving **watermarked signals** whose **entropy** can be used to determine if the sensor values are correct of not. Read more about this method [here](https://ieeexplore.ieee.org/abstract/document/9994719).

### 7. Logging & Monitoring

- **Inadequate Logging and Monitoring** – Without sufficient monitoring, security breaches or operational anomalies may go undetected.

- **Integration Issues** – Some cameras require webserver configurations, and if poorly integrated, these web servers on cameras or telemetry systems may expose vulnerabilities that can be used to gather sensitive information.

To prevent this, ensure that your credentials are strong!

---

## Secure Communication Protocols

Below are some protocols used by drone systems to communicate. This can be either between each other (if in a horde) or with the ground stations. We have mentioned what can go wrong with each protocol and also provided recommendations.

1. **MAVLink 2.0** – A widely used protocol for communication between drones and ground control stations (GCS).

   - Require valid [MAVLink 2 message signatures](https://mavlink.io/en/guide/message_signing.html#accepting_unsigned_packets) for commands received over untrusted links. Reject unsigned or incorrectly signed commands. Protect the shared signing key and [persist signing timestamps across restarts](https://mavlink.io/en/mavgen_c/message_signing_c.html#handling-timestamps) so replay checks remain effective.

   - [Heartbeat messages](https://mavlink.io/en/services/heartbeat.html) advertise a component's presence, type, and state. Treat heartbeat receipt as a liveness signal, not authorization to execute commands.

   - Tools like **ArduPilot** and **PX4** support MAVLink 2.0 security enhancements. They have been thoroughly tested and are therefore recommended.

   - Utilize **end-to-end encryption**! Either through TLS or DTLS is fine and good.

Recent CVEs underscore the risk of unauthenticated MAVLink. The absence of default authentication is not theoretical — it has produced critical, remotely-reachable vulnerabilities across both dominant open-source autopilots:

- [CVE-2026-1579](https://www.cisa.gov/news-events/ics-advisories/icsa-26-090-02) (PX4, CVSS 9.8, CISA ICSA-26-090-02, CWE-306): with MAVLink 2 message signing disabled, an unauthenticated party can send SERIAL_CONTROL to obtain interactive shell access.

- [CVE-2026-38971](https://www.cve.org/CVERecord?id=CVE-2026-38971) (ArduPilot ArduPlane ≤ 4.6.3, CVSS 9.1, CWE-125): an out-of-bounds read in the SERIAL_CONTROL handler (GCS_serial_control.cpp), reachable over MAVLink by an unauthenticated attacker — flight-controller memory disclosure and denial of service.

- CVE-2026-32743 and related PX4 issues (CWE-121): MAVLink-reachable stack buffer overflows in the log handler cause denial of service.

- [CVE-2020-10283](https://www.cve.org/CVERecord?id=CVE-2020-10283) (MAVLink): an earlier authentication downgrade issue — the weakness is long-standing, not new.

Defense-in-depth beyond message signing. Because signing is frequently disabled in the field and any software mitigation runs in the same trust domain an attacker may have compromised, consider enforcing protocol integrity out-of-band:

- Header validation — use system-ID allowlists and [packet sequence numbers](https://mavlink.io/en/guide/serialization.html#mavlink2_packet_format) to detect unexpected senders and packet loss. These fields do not authenticate unsigned messages; they cannot replace signature and timestamp validation.

- Typed-payload validation — reject non-finite parameter values (PARAM_SET) and bound FTP path lengths to defeat malformed-value and buffer-overflow classes.

- Hardware-enforced enforcement point — where the autopilot firmware cannot be modified or trusted, a bump-in-the-wire validation device placed between the companion computer and the flight controller can apply the above checks in a separate hardware domain, independent of a potentially compromised software stack.

2. **CAN (Controller Area Network) Bus** – A communication protocol used between internal drone system components (e.g., flight controllers, ESCs, GPS modules).

   - Most attacks require **physical access** to exploit CAN. It works on a differential signal and hardware hacking may be possible by tapping into them.

   - Do not rely on DroneCAN alone to authenticate CAN senders. Its [multi-frame cyclic redundancy check (CRC)](https://dronecan.github.io/Specification/4.1_CAN_bus_transport_layer/#transfer-crc) is an unkeyed checksum, not a message authentication code. Protect physical bus access and isolate the bus from untrusted components.

3. **ZigBee** – A low-power wireless protocol often used for telemetry and sensor communication in backup systems.

   - This has a way to enable **AES-128 encryption** to secure transmissions. Make sure you do that.

   - Deploy **network keys with frequent rotation** to prevent key compromise. Read more about [key rotations here](https://cloud.google.com/kms/docs/key-rotation#:~:text=A%20rotation%20schedule%20defines%20the,require%20periodic%2C%20automatic%20key%20rotation.).

   - Monitor for **ZigBee packet sniffing attacks** using SDR-based tools like **HackRF** or **YARD Stick One**.

4. **Bluetooth** – Used for device connections, such as drone controllers or mobile applications.

   - You must enforce **Strict Pairing Modes** that is LE (Low Energy) Secure Connections over Bluetooth 4.2+. This uses the Elliptic curve Diffie-Hellman cryptosystem to generate keys. Essentially, its state of the art.

   - Pairing methods such as [_Just works_](https://devzone.nordicsemi.com/f/nordic-q-a/17165/ble-just-works-pairing) are vulnerable to MITM attacks! Do not use them if you're setting up your own Bluetooth adapters.

5. **Wi-Fi (802.11a/b/g/n/ac/ax)** – A common method for FPV (First Person View) video transmission and drone control.

   - Make sure that you are using **WPA3 encryption** for the highest level of security. Note that protocols like **WEP** are vulnerable!

   - Use **802.11w Management Frame Protection (MFP)** to mitigate deauthentication attacks (these are crafted packets that emulate a server and cause deauthentication).

   - Do not rely on hiding the Wi-Fi network name or filtering media access control (MAC) addresses to prevent unauthorized access: [hidden networks remain discoverable and MAC addresses can be spoofed](https://support.apple.com/en-ca/102766#hiddennetwork). Use Wi-Fi authentication and encryption as described above.

By implementing these security measures, drone operators can significantly reduce the risks of cyberattacks and unauthorized access to UAV communication systems.

## Summary

The table maps common attacks to relevant controls. Choose controls for the interfaces actually present on the drone and GCS; the impact depends on the implementation. Radio interference, forged messages, and software vulnerabilities require different defenses.

| Attack or exposure | Security measures and limitations |
| --- | --- |
| Malware | Install firmware and GCS software from trusted sources and keep them updated; restrict scripts and plugins. Follow the [GCS hardening guidance](https://ardupilot.org/dev/docs/security-landing-page.html#ground-control-stations). |
| Backdoor access | Restrict administrative interfaces and use [verified firmware](https://ardupilot.org/dev/docs/secure-firmware.html). Login authentication alone cannot prevent access through a backdoor that bypasses it. |
| Social engineering | Train operators to [verify suspicious requests through a trusted contact channel](https://www.ncsc.gov.uk/collection/phishing-scams/spot-scams), especially requests for credentials or software installation. |
| Baiting | Restrict untrusted removable media and peripherals on the GCS and companion computer; combine operator training with [device access controls](https://www.ncsc.gov.uk/collection/device-security-guidance/policies-and-settings/using-peripherals-securely). |
| Message injection or modification | Authenticate messages and validate their contents before acting on them; apply the [MAVLink controls above](#secure-communication-protocols). A valid signature does not make an unsafe command safe. |
| Fabricated commands | Require authenticated commands from trusted controllers. For MAVLink, [reject unsigned commands on untrusted links and protect the shared signing key](https://mavlink.io/en/guide/message_signing.html#accepting_unsigned_packets); any holder of that key can sign messages. |
| Reconnaissance | Reduce exposed interfaces and protect sensitive telemetry. [Encryption does not conceal all traffic metadata](https://datatracker.ietf.org/doc/html/rfc8446#appendix-E.3). |
| Network scanning | [Disable unused interfaces and restrict network access](https://ardupilot.org/dev/docs/security-landing-page.html#security-attack-surface). Encrypting traffic does not close reachable ports. |
| TCP SYN flooding | For exposed TCP services, use the platform's [SYN-flood protections](https://datatracker.ietf.org/doc/html/rfc4987#section-3), such as SYN cookies. A normal three-way handshake is not an attack. |
| Eavesdropping | Encrypt sensitive telemetry and control traffic using the [secure communication protocols above](#secure-communication-protocols). Message signing alone does not provide confidentiality. |
| Traffic analysis | Evaluate [protocol-supported padding](https://datatracker.ietf.org/doc/html/rfc8446#appendix-E.3) when packet lengths expose sensitive information. Ordinary encryption does not hide traffic timing or volume; padding has bandwidth and latency costs. |
| Man-in-the-middle | Authenticate the communicating peers and encrypt the connection; validate certificates or provisioned keys. See the [TLS Cheat Sheet](Transport_Layer_Security_Cheat_Sheet.md). |
| Password guessing or cracking | Use strong, unique passwords, login rate limits, and multifactor authentication where supported; see the [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md). Do not rely on periodic password changes. |
| Wi-Fi credential attacks | Use [WPA3 and a strong network password](https://support.apple.com/en-ca/102766#security) where supported. Avoid WEP and other deprecated security modes; an intrusion detection system does not repair weak authentication. |
| Wi-Fi radio jamming | Configure and test [link-loss failsafes](https://docs.px4.io/main/en/config/safety#data-link-loss-failsafe) for the vehicle and mission. These reduce the consequences of a lost link; they do not prevent radio interference. |
| Forged Wi-Fi deauthentication | Require [802.11w Management Frame Protection](https://www.cisco.com/c/en/us/support/docs/wireless-mobility/wireless-lan-wlan/212576-configure-802-11w-management-frame-prote.pdf) on compatible endpoints. It protects against forged management frames, not radio jamming. |
| Replay | Authenticate messages and validate freshness; maintain replay state, including across restarts. See the [MAVLink signing guidance above](#secure-communication-protocols). |
| Buffer overflow | Use memory-safe components or enforce [buffer bounds checks](https://cwe.mitre.org/data/definitions/120.html), and patch vulnerable parsers. Changing radio frequencies does not fix memory corruption. |
| Denial of service through resource exhaustion | Bound message sizes and processing resources, apply rate limits, and isolate critical control functions. See the [Denial of Service Cheat Sheet](Denial_of_Service_Cheat_Sheet.md); radio changes do not resolve application resource exhaustion. |
| Address Resolution Protocol (ARP) cache poisoning | On IP networks, isolate untrusted participants and use [dynamic ARP inspection with trusted address bindings](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/software/release/16-8/configuration_guide/sec/b_168_sec_9500_cg/configuring_dynamic_arp_inspection.html) where supported. This is a local network attack, not radio jamming. |
| Ping-of-Death / malformed IP packets | Keep the network stack patched and use supported [malformed-packet filtering](https://www.cisco.com/c/en/us/td/docs/switches/lan/csbss/CBS220/CLI-Guide/b_220CLI/security_dos_commands.pdf). Changing radio frequencies does not correct packet-processing vulnerabilities. |
| GPS spoofing | Use navigation consistency checks and evaluate [non-GPS navigation as a backup](https://ardupilot.org/dev/docs/security-landing-page.html#security-attack-surface). Do not assume return-to-home is safe when its position estimate is untrusted; test the vehicle's navigation failsafes. |

There are multiple GitHub repos that help with drone attack [simulations](https://github.com/nicholasaleks/Damn-Vulnerable-Drone) and [actual exploits](https://github.com/dhondta/dronesploit). Be sure to check them out too for a deeper understanding of drone security.

## References

- [NIST SP 800-193: Platform Firmware Resiliency Guidelines](https://csrc.nist.gov/pubs/sp/800/193/final)
- [MAVLink: Message Signing (Authentication)](https://mavlink.io/en/guide/message_signing.html)
