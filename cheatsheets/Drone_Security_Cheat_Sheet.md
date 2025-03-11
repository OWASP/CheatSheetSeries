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

The communication between the drone and the GCS is vulnerable to interception and attacks. This will be made evident in the future sections as well. It is important to understand that peripherals attached to drone may be vulnerable too! To explain this, we have made a list of **vulnerable endpoints** below.

---

## Vulnerable Endpoints & Security Risks

### 1. Communication Security

- **Insecure Communication Links** – Data transmitted between the drone and GCS can be intercepted if not properly encrypted. Use standard protocols for encryption of any data being sent over.

- **Spoofing and Replay Attacks** – If the drone uses a GPS module then data spoofing and command replay attacks can also become a reality. Again encrpyted data transfer is the best way to go forward. There are many more methods, which have been discussed [here](https://www.okta.com/identity-101/gps-spoofing/)

- **Wi-Fi Weaknesses** – Weak authentication or unprotected channels can allow unauthorized access. This is even possible through simple [microcontrollers like ESP8266](https://github.com/SpacehuhnTech/esp8266_deauther)!

    - Use **802.11w MFP (Management Frame Protection)** to prevent Wi-Fi deauthentication attacks. Don't worry, if your Wi-Fi systems are up to date, then this is a default protocol now.

### 2. Authentication & Access Control

Most drone controllers use 2 sets of computers,

1. The main chip that performs the PID control and handles motors

2. An additional SoC (called the **companion computer**) to manage peripherals (like the cameras, LiDARs etc.) and send telemetry data.

Thus, it becomes very important to maintain their security as well. The possible risks in this case are:

- **Companion Computers** – Open ports (e.g., SSH, FTP) can be exploited if not securely configured.

- **User Error and Misconfiguration** – Misconfigured security settings can expose the drone to risks.

### 3. Physical Security

If your drone is ever captured or lost, you should ensure that its not physically possible to steal data from it. This may happen under the following conditions:

- **Insufficient Physical Security** – Unsecured USB ports or exposed hardware can lead to data theft or tampering.

- **Insecure Supply Chain** – Compromised components from suppliers can introduce hidden vulnerabilities.

- **End-of-Life Decommissioning Risks** – Improperly decommissioned drones may retain sensitive data or be repurposed maliciously.

### 4. Sensor Security

With drones implementing control logic depending on how close they are to other drones or aerial vehicles, manipulating sensor data can be disastrous!

Attackers can manipulate drone sensors (GPS, cameras, altimeters) to feed incorrect data. Think of this more like how [stuxnet](https://en.wikipedia.org/wiki/Stuxnet) changed the speed of the Uranium centrifuges in Iran while still reporting the speed as normal.

To prevent this, there is new research being developed involving **watermarked signals** whose **entropy** can be used to determine if the sensor values are correct of not. Read more about this method [here](https://ieeexplore.ieee.org/abstract/document/9994719).

### 5. Logging & Monitoring

- **Inadequate Logging and Monitoring** – Without sufficient monitoring, security breaches or operational anomalies may go undetected.

- **Integration Issues** – Some cameras require webserver configurations, and if poorly integrated, these web servers on cameras or telemetry systems may expose vulnerabilities that can be used to gather sensitive information.

To prevent this, ensure that your credentials are strong!

---

## Secure Communication Protocols

Below are some protocols used by drone systems to communicate. This can be either between each other (if in a horde) or with the ground stations. We have mentioned what can go wrong with each protocol and also provided recommendations.

1. **MAVLink 2.0** – A widely used protocol for communication between drones and ground control stations (GCS).

   - Implement **message signing** to prevent spoofing and replay attacks.

   - You must secure **heartbeat messages** to avoid [command injection vulnerabilities](https://owasp.org/www-community/attacks/Command_Injection). A heartbeat message is usually a single byte that is sent at a certain frequency to all other nodes, informing of the device's existence. The frequency is important here!

   - Tools like **ArduPilot** and **PX4** support MAVLink 2.0 security enhancements. There are thoroughly tested softwares and hence recommended.

   - Utilize **end-to-end encryption**! Either through TLS or DTLS is fine and good.

2. **CAN (Controller Area Network) Bus** – A communication protocol used between internal drone system components (e.g., flight controllers, ESCs, GPS modules).

   - Most attacks require **physical access** to exploit CAN. It works on a differential signal and hardware hacking may be possible by tapping into them.

   - There exist tools like **DroneCAN** which make using secure CAN communications easy.

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

   - Disable **SSID broadcasting** and use **MAC filtering** where feasible. This is advisable because it essentially hides your drone's Wi-Fi adapters from simple scans.

By implementing these security measures, drone operators can significantly reduce the risks of cyberattacks and unauthorized access to UAV communication systems.

## Summary

The following table summaries the different attack vectors for a drone system.

| Attack |  | Targets | | | | | Security Measures | |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Type | Nature | Privacy| Data Confidentiality | Integrity | Accessibility | Authentication|Non-Cryptographic | Cryptographic |
| Malware | Infection | x | x |x |x |x | Control access, system integrity solutions and multi-factor authentication | Hybrid lightweight Intrusion Detection System |
| BackDoor Access | Infection |x|x|x| x|x | Multi-factor robust authentication scheme | Hybrid lightweight Intrusion Detection System, vulnerability assessment |
| Social Engineering | Exploitation | x|x |- |- |x | N/A | Raising awareness, training operators |
| Baiting | Exploitation |x| x| x|- |x | N/A | Raising awareness, training operators |
| Injection/Modification | Exploitation |x |- |x |- |- | Message authentication or digital signature | Machine-Learning hybrid Intrusion Detection System, timestamps |
| Fabrication | Exploitation |x |- |x |- |x | Multi-factor authentication, message authentication or digital signature | Assigning privilege |
| Reconnaissance | Information gathering | x| x| -|- |- | Encrypted traffic/stream | Hybrid lightweight Intrusion Detection System |
| Scanning | Information gathering | x|x |x |- |- | Encrypted traffic/stream | Hybrid lightweight Intrusion Detection System or Honeypot |
| Three-Way Handshake | Interception | -|- |- |x |x | - | Traffic filtering, close unused TCP/FTP ports |
| Eavesdropping | Interception | x| x| -| -| -| Securing communication/traffic, secure connection | N/A |
| Traffic Analysis | Interception | x|- |- |- |- | Securing communication/traffic, secure connection | N/A |
| Man-in-the-Middle | Authentication |x |x |x |- |- | Multi-factor authentication & lightweight strong cryptographic authentication protocol | Lightweight hybrid Intrusion Detection System |
| Password Breaking | Cracking | x|x |x |x |- | Strong periodic passwords, strong encryption | Lightweight Intrusion Detection System |
| Wi-Fi Aircrack | Cracking | x|x |x |x |- | Strong & periodic passwords, strong encryption algorithm | Lightweight Intrusion Detection System at the physical layer |
| Wi-Fi Jamming | Jamming | x| x| x| x|- | N/A | Frequency hopping, frequency range variation |
| De-Authentication | Jamming | x| x| x| x| -| N/A | Frequency hopping, frequency range variation |
| Replay | Jamming | x| x| x| x| -| N/A | Frequency hopping, timestamps |
| Buffer Overflow | Jamming |x |x | x| x|- | N/A | Frequency hopping, frequency range variation |
| Denial of Service | Jamming |x |x |x |x |- | N/A | Frequency hopping, frequency range variation |
| ARP Cache Poison | Jamming |x |x | x| x|- | N/A | Frequency hopping, frequency range variation |
| Ping-of-Death | Jamming | x| x| x| x| -| N/A | Frequency range variation |
| GPS Spoofing | Jamming | x| x| x| x| -| N/A | Return-to-base, frequency range variation |

There are multiple GitHub repos that help with drone attack [simulations](https://github.com/nicholasaleks/Damn-Vulnerable-Drone) and [actual exploits](https://github.com/dhondta/dronesploit). Be sure to check them out too for a deeper understanding of drone security.

## References

- [ESP8266 Wi-Fi deauther](https://github.com/SpacehuhnTech/esp8266_deauther)

- [Command Injection explanation](https://owasp.org/www-community/attacks/Command_Injection)

- [key rotations at certain frequencies](https://cloud.google.com/kms/docs/key-rotation#:~:text=A%20rotation%20schedule%20defines%20the,require%20periodic%2C%20automatic%20key%20rotation.)

- [Vulnerable Just works bluetooth protocol](https://devzone.nordicsemi.com/f/nordic-q-a/17165/ble-just-works-pairing)

- [Drone Exploit Module](https://github.com/dhondta/dronesploit)

- [Vulnerable Drone System Simulation](https://github.com/nicholasaleks/Damn-Vulnerable-Drone)

- [Drones from a Cybersecurity Perspective](https://dronewolf.darkwolf.io/intro)

- [Dynamic Watermarking in UAVs](https://ieeexplore.ieee.org/abstract/document/9994719)

- [GPS spoofing and prevention](https://www.okta.com/identity-101/gps-spoofing/)
