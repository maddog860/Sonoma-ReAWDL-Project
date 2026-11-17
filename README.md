
# Sonoma ReAWDL Project

### Experimental Intel Wi-Fi Support for Apple Wireless Direct Link (AWDL) on macOS Sonoma

ReAWDL is an experimental modification of the [OpenIntelWireless AirportItlwm](https://github.com/OpenIntelWireless/itlwm) driver, primarily developed for the **Intel AX210 Wi-Fi 6E** chipset under macOS Sonoma.

The original goal was to enable native Apple Wireless Direct Link (AWDL) functionality on Intel Wi-Fi hardware, allowing direct communication with Apple devices without requiring a conventional shared Wi-Fi network.

The ultimate objectives included **AirDrop, peer-to-peer AirPlay, native device discovery, and reliable bidirectional wireless communication**, without compromising ordinary Wi-Fi connectivity.

Although complete compatibility was not achieved, the project made substantial progress in driver functionality, packet handling, firmware integration, and stability.

**Latest release:** [ReAWDL v3.5.1 — Releases](https://github.com/maddog860/Sonoma-ReAWDL-Project/releases)

**Project Status:** Development concluded. Source code preserved for reference, research, and possible future community contributions.

---

## Project Overview

Apple Wireless Direct Link is the peer-to-peer wireless technology used by Apple features such as AirDrop and certain AirPlay workflows.

Establishing a native `awdl0` interface is only one part of supporting AWDL. Complete interoperability also requires appropriate management frames, radio scheduling, channel coordination, peer discovery, and reliable bidirectional data transfer.

ReAWDL investigated these requirements using Intel firmware capabilities alongside Apple's **IO80211** and **Skywalk** networking frameworks.

### Original Project Objectives

- Establish a native `awdl0` interface on Intel Wi-Fi hardware.
- Enable discovery and direct communication with Apple devices without a shared wireless network.
- Support peer-to-peer AirPlay and ultimately complete AirDrop file transfers.
- Provide reliable bidirectional communication.
- Preserve ordinary infrastructure Wi-Fi functionality.

---

## What the Project Achieved

### Native AWDL Integration

The project successfully established a native `awdl0` interface through Apple's IO80211 and Skywalk networking frameworks.

Implemented functionality included interface registration, state management, IPv6 link-local networking, and native packet transmission and reception pathways.

This represented meaningful integration with Apple's networking architecture rather than simply displaying a virtual interface.

### AWDL Discovery and Synchronization

Experimental support was developed for AWDL management frames, radio scheduling, channel alignment, and secondary Intel MAC/PHY operation.

A historical diagnostic capture demonstrated:

| Diagnostic | Recorded Result |
|---|---|
| AWDL presence/synchronization frame submissions | 5,259 |
| Reported submission errors | 0 |
| P2P session-rearm events | 5,083 |
| AWDL management and multicast reception | Demonstrated |
| Apple-device peer discovery | Observed during testing |

These results established meaningful AWDL activity, although they did not prove successful bidirectional communication or complete AirDrop functionality.

### MAC Address Synchronization

The driver gained the ability to synchronize Intel firmware **MAC1** with Apple's live `awdl0` hardware address.

Runtime diagnostics confirmed matching addresses, resolving an important identity-consistency issue in the tested configuration.

This work helped establish a more consistent relationship between Apple's virtual AWDL interface and the Intel firmware radio context.

### Functional AWDL Multicast Reception

The project achieved native AWDL multicast packet delivery through Apple's Skywalk networking stack.

A receive-path correction also addressed unsafe packet handling associated with earlier system instability.

This demonstrated meaningful progress beyond management-frame transmission alone.

### Partial Peer-to-Peer AirPlay

An iPhone successfully initiated media playback through the experimental Intel setup without requiring a shared infrastructure Wi-Fi network.

However, playback controls such as pause, seek, and track skipping did not reliably synchronize.

This demonstrated **partial AirPlay functionality**, not complete compatibility.

### Driver Reliability and Diagnostics

Additional development addressed several important areas of driver reliability:

- DMA buffer mapping and resource management.
- Packet ownership and cleanup.
- Firmware command tracking and completion handling.
- Deferred transmission processing.
- Queue ownership and lifecycle safeguards.
- Reset recovery and prevention of stale operations.
- Peer-to-peer radio scheduling and firmware diagnostics.
- Input validation and memory-safety improvements.

The project also introduced expanded diagnostics capable of displaying:

- Intel Wi-Fi hardware model and capabilities.
- Actual loaded Intel firmware image and version.
- Firmware command capabilities.
- AWDL radio scheduling and session activity.
- Transmission and reception statistics.
- Packet completion and firmware error information.

Detailed instrumentation can be enabled using the optional boot argument:

`-itlwm-diag`

Obsolete experimental firmware snapshot instrumentation was removed from the final source.

---

## Performance and Functionality Improvements

The project's primary gains involved **new functionality, improved packet-handling correctness, and specific reliability improvements**, rather than increased raw wireless speed.

| Area | Result |
|---|---|
| Native AWDL interface | Operational |
| AWDL management-frame activity | Demonstrated |
| P2P firmware session scheduling | Operational in recorded tests |
| AWDL multicast reception | Functional |
| Firmware MAC synchronization | Confirmed |
| Apple-device discovery | Demonstrated |
| Sleep/wake discovery recovery | Observed in final testing |
| Peer-to-peer AirPlay | Partially functional |
| Packet handling and recovery | Improved |
| Hardware and firmware diagnostics | Significantly expanded |
| Ordinary infrastructure Wi-Fi | Functional during successful tests |

### Wireless Performance

Ordinary infrastructure Wi-Fi remained functional throughout successful development testing.

No controlled improvement in Wi-Fi throughput, latency, or battery efficiency was established.

Performance gains should therefore be understood primarily as improvements in **driver functionality, reliability, and experimental AWDL capabilities**.

---

## Remaining Limitations

Despite considerable development, several important challenges remained unresolved.

### Bidirectional Unicast Communication

The driver could transmit AWDL management frames and receive multicast traffic, but reliable peer-directed unicast communication was not achieved.

One experiment recorded 505 unicast transmission attempts reaching the Intel firmware retry limit.

The most significant unresolved challenge was establishing a dependable bidirectional AWDL unicast data path integrated with Apple's native networking services.

### Complete AirDrop Compatibility

Native AWDL discovery and synchronization were demonstrated, but no complete Intel-to-Apple or Apple-to-Intel AirDrop file transfer was successfully demonstrated.

Receiving AWDL advertisements or discovering another device does not necessarily establish a working AirDrop connection.

### AirPlay Compatibility

Initial peer-to-peer playback worked in certain experiments, but media controls and session synchronization remained unreliable.

### Independent Firmware Transmit Queue

Station-3 queue ownership safeguards were developed, but independent private firmware transmission remained gated and was not enabled as a completed feature.

### Additional Compatibility Testing

Broad compatibility across different Intel wireless devices, arbitrary-channel coexistence, and all possible operating conditions was not fully validated.

| Feature | Final Status |
|---|---|
| Infrastructure Wi-Fi | Demonstrated |
| Native `awdl0` interface | Operational |
| AWDL management-frame activity | Demonstrated |
| AWDL multicast reception | Demonstrated |
| P2P session management | Demonstrated |
| Apple-device discovery | Demonstrated in testing |
| Sleep/wake discovery recovery | Observed |
| Reliable AWDL unicast data delivery | Not demonstrated |
| Complete AirDrop file transfer | Not demonstrated |
| Fully synchronized peer-to-peer AirPlay | Not achieved |
| Independent station-3 firmware TX queue | Not enabled |

---

## Final Project Outcome

Sonoma ReAWDL did not achieve complete AirDrop compatibility, but it progressed substantially beyond simply exposing an AWDL interface.

The project demonstrated:

- Native Apple-compatible AWDL interface integration.
- AWDL management-frame activity and synchronization.
- Multicast packet reception and delivery.
- Experimental peer-to-peer firmware scheduling.
- Firmware MAC address synchronization.
- Apple-device discovery.
- Partial peer-to-peer AirPlay functionality.
- Meaningful packet-handling and reliability improvements.
- Expanded Intel hardware and firmware diagnostics.

The resulting source code remains a valuable experimental foundation for understanding and extending Apple-compatible peer-to-peer wireless networking on Intel hardware.

**Project Status:** Development concluded. The final source is available for reference, research, and potential community contributions.

---

# Credits & Acknowledgments

This project builds upon the work of the OpenIntelWireless community and several independent efforts to understand and implement Apple Wireless Direct Link.

Special thanks go to the developers and researchers whose work helped make these Intel Wi-Fi experiments possible.

## Project Development

### NorthKoreanNoodles (Maddog860)

Project direction, extensive hardware testing, experimental design, troubleshooting, and validation of driver changes.

Contributions included investigating native AWDL interface creation, identifying functional limitations, interpreting real-world results, and guiding development toward Apple-compatible peer-to-peer Wi-Fi operation.

### Artificial Intelligence — AI-Assisted Development

AI coding assistants, including **OpenAI ChatGPT, Anthropic Claude, and Mistral AI**, generated much of the project's experimental code, modifications, instrumentation, and diagnostic tooling.

AI assistance also contributed to source analysis, firmware research, debugging strategies, and documentation.

Development was directed and validated through human testing.

This acknowledgment applies to ReAWDL-specific development, not the original code written by upstream developers.

---

## Original Driver and Technical Foundations

### [OpenIntelWireless / itlwm](https://github.com/OpenIntelWireless/itlwm)

The original Intel Wi-Fi driver for macOS and the foundation of this project.

Credit goes to zxystd and the OpenIntelWireless contributors for the driver architecture, hardware support, and years of development.

### [OpenBSD](https://www.openbsd.org/)

An important source of networking and Intel wireless driver foundations used by itlwm, including `net80211`, `iwn`, `iwm`, and `iwx`.

### [Acidanthera / MacKernelSDK](https://github.com/acidanthera/MacKernelSDK)

Kernel development headers and supporting components used to build the macOS driver.

### [Intel / Linux iwlwifi](https://wireless.docs.kernel.org/en/latest/en/users/drivers/iwlwifi.html)

An important technical reference for Intel firmware commands, station contexts, transmit queues, firmware interfaces, and device behavior.

Intel wireless firmware and documentation also provided essential information for understanding AX210 hardware operation.

---

## KGP — Intel Driver Engineering Reference

### [KGP / GitHub](https://github.com/kgp-macPro/)

KGP's AirportItlwm development provided valuable implementation references for improving driver reliability, particularly lower-level packet handling and firmware operation management.

| Area | Contribution to Our Research |
|---|---|
| Packet transmission | DMA buffer mapping, packet ownership, and safe resource cleanup |
| Queue management | Deferred processing when the driver cannot immediately acquire its workloop |
| Firmware commands | Command-slot tracking, command lifetimes, and completion safety |
| Reset recovery | Preventing stale operations and queued work from crossing reset boundaries |
| AWDL interface lifecycle | Reference approaches for creating, attaching, enabling, and publishing Apple-compatible P2P interfaces |

The deferred-drain and workloop-handling mechanisms were particularly useful references during our management-frame transmission investigations.

KGP's Tahoe implementation uses a different macOS wireless framework architecture from our Sonoma Skywalk-based implementation.

We studied and adapted relevant engineering approaches rather than treating it as a direct replacement.

We also appreciate KGP's acknowledgment of Maddog860's earlier work on direct AWDL virtual-interface registration.

---

## Linux AirDrop Project — AWDL Protocol Research

### [jedbillyb / airdrop-mt7921](https://github.com/jedbillyb/airdrop-mt7921)

This project was an especially valuable reference for understanding how a non-Apple Wi-Fi chipset can communicate using Apple's AWDL protocol.

Although it targets MediaTek hardware rather than Intel, its practical experiments and documentation helped guide several aspects of our AX210 investigation.

### AWDL MAC Identity Synchronization

The Linux research reinforced the importance of maintaining a consistent identity between the virtual AWDL interface and its underlying radio context.

Our Intel implementation subsequently synchronized firmware MAC1 with Apple's live `awdl0` address, with matching addresses confirmed in runtime diagnostics.

### Independent Peer-to-Peer Operation

The Linux project demonstrated alternative P2P radio configurations operating alongside ordinary Wi-Fi.

This informed our investigation of Intel MAC1, PHY2, firmware bindings, and P2P session scheduling.

### Actual Radio-Channel Selection

Its experiments highlighted why a requested channel does not always represent the channel actually used by the radio.

This was particularly relevant to discovery investigations involving channels 6 and 149.

### AWDL Synchronization and Availability Windows

We studied its channel sequences, synchronization offsets, peer election, channel alignment, and transmission timing.

These concepts helped guide our scheduling and synchronization investigations.

### Discovery Versus Data Transfer

The Linux work reinforced the distinction between receiving AWDL advertisements, discovering another device, establishing bidirectional networking, and completing an actual AirDrop transfer.

This distinction helped structure our diagnostics around meaningful functional milestones.

The Linux implementation served as a protocol and engineering reference. Its MediaTek-specific driver code was not directly transplanted into our Intel driver.

---

## Additional AWDL Research and Open-Source Projects

### [Open Wireless Link (OWL) — SEEMOO Lab](https://github.com/seemoo-lab/owl)

An open-source implementation of Apple's AWDL protocol.

Its research into peer discovery, synchronization, master election, channel sequences, frame construction, and IPv6 networking helped establish important technical foundations for understanding AWDL outside Apple's hardware ecosystem.

OWL also underpins the Linux AirDrop implementation referenced above.

### [OpenDrop — SEEMOO Lab](https://github.com/seemoo-lab/opendrop)

An open-source AirDrop implementation demonstrating the higher-level file-transfer protocol operating over an AWDL network.

It provides important context for distinguishing link-layer functionality from complete AirDrop compatibility.

These projects represent valuable independent research into Apple's wireless protocols.

---

## Acknowledgment of Upstream Contributors

Additional recognition belongs to the many developers credited by the original OpenIntelWireless project, including those responsible for macOS wireless compatibility, Intel device support, firmware integration, network-stack adaptation, and bug fixes.

Their contributions remain part of the foundation on which this experimental work was built.

---

## Project Scope and Disclaimer

Sonoma ReAWDL is an independent, experimental Intel Wi-Fi development project.

The work described here involves a mixture of upstream open-source code, engineering references, protocol research, AI-assisted development, and physical hardware testing.

Acknowledging a project as a technical reference does not necessarily imply that its source code was directly incorporated.

Likewise, successful AWDL interface creation, peer discovery, or synchronization should not be interpreted as proof of complete AirDrop functionality.

This project is not affiliated with or endorsed by Apple, Intel, OpenIntelWireless, KGP, or any of the other projects acknowledged here.

---

### Dedicated to my Mom

