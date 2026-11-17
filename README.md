Sonoma ReAWDL Project

Experimental Intel Wi-Fi Support for Apple Wireless Direct Link (AWDL)

Project Overview

The Sonoma ReAWDL Project is an experimental modification of the OpenIntelWireless AirportItlwm driver, primarily developed for the Intel AX210 Wi-Fi 6E chipset under macOS Sonoma.
The original goal was to enable native Apple Wireless Direct Link (AWDL) functionality on Intel Wi-Fi hardware, allowing direct communication with Apple devices without requiring a conventional Wi-Fi network.
The ultimate objectives were functional AirDrop, peer-to-peer AirPlay, native device discovery, and reliable bidirectional wireless communication, without compromising ordinary Wi-Fi connectivity.
Although complete compatibility was not achieved, the project made substantial progress in driver functionality, packet handling, firmware integration, and stability.

What the Project Achieved

Native AWDL Integration

The project successfully established a native awdl0 interface through Apple's IO80211 and Skywalk networking frameworks.
Implemented functionality included interface registration, state management, IPv6 link-local networking, and native packet transmission and reception pathways.
AWDL Discovery and Synchronization

Experimental support was developed for AWDL management frames, radio scheduling, channel alignment, and secondary Intel MAC/PHY operation.
A recorded test demonstrated:
	•	5,259 AWDL presence/synchronization frame transmissions, with zero reported transmission errors.
	•	5,083 P2P session-rearm events, demonstrating sustained scheduling activity.
	•	Reception and processing of AWDL management frames and multicast traffic.
These results established meaningful AWDL activity, although they did not prove successful bidirectional communication.
MAC Address Synchronization

The driver gained the ability to synchronize Intel firmware MAC1 with Apple's native awdl0 address.
Runtime diagnostics confirmed matching addresses, resolving an important identity-consistency issue in the observed configuration.
Functional Multicast Reception

The project achieved native AWDL multicast packet delivery through Apple's Skywalk networking stack.
A receive-path correction also addressed unsafe packet handling associated with earlier system freezes.
Partial Peer-to-Peer AirPlay

An iPhone successfully initiated media playback through the experimental Intel setup without requiring a shared infrastructure Wi-Fi network.
However, playback controls such as pause, seek, and skipping did not reliably synchronize. This demonstrated partial rather than complete AirPlay functionality.
Driver Reliability and Diagnostics

Additional improvements addressed DMA buffer management, packet ownership, firmware command handling, deferred transmission processing, queue safety, and reset recovery.
The project also introduced advanced diagnostics capable of displaying:
	•	Intel Wi-Fi hardware model and capabilities.
	•	Actual loaded Intel firmware image and version.
	•	Firmware command capabilities.
	•	AWDL radio scheduling, transmission, and reception statistics.
	•	Packet completion and firmware error information.
Detailed instrumentation could be enabled using the optional -itlwm-diag boot argument.

Performance Improvements

The project's primary gains involved additional functionality, packet-handling correctness, and specific reliability improvements, rather than increased raw wireless speed.
Area
Result
Native AWDL interface
Operational
AWDL management-frame exchange
Demonstrated
P2P session scheduling
Operational in recorded tests
AWDL multicast reception
Functional
Firmware MAC synchronization
Confirmed in runtime testing
Peer-to-peer AirPlay
Partially functional
Packet handling and recovery
Improved
Hardware and firmware diagnostics
Significantly expanded
Ordinary infrastructure Wi-Fi remained functional during successful tests.
No controlled improvement in Wi-Fi throughput, latency, or battery efficiency was established. Performance gains should therefore be understood primarily as improvements in driver functionality and reliability.

Where the Project Fell Short

Despite considerable development, several important challenges remained unresolved.
Bidirectional unicast communication: The driver could transmit management frames and handle multicast traffic, but reliable peer-directed unicast transmission was not achieved. One experiment recorded 505 unicast attempts ending at the Intel firmware retry limit.
AirDrop discovery: Although the driver participated in AWDL discovery and synchronization, reliable reciprocal visibility between Intel and Apple devices was not established.
AirDrop file transfers: No complete Intel-to-Apple or Apple-to-Intel AirDrop file transfer was demonstrated.
AirPlay compatibility: Initial peer-to-peer playback worked in certain experiments, but media controls and session synchronization remained unreliable.
Long-term reliability: Consistent operation after sleep, automatic recovery, arbitrary-channel coexistence, and broad compatibility were not fully validated.
The most significant unresolved challenge was establishing a dependable, bidirectional AWDL unicast data path integrated with Apple's native discovery and networking services.

Final Outcome

Sonoma ReAWDL did not achieve complete AirDrop compatibility, but it progressed well beyond simply exposing an AWDL interface.
The project demonstrated native interface integration, AWDL frame exchange, multicast networking, experimental P2P scheduling, firmware MAC synchronization, and partial peer-to-peer AirPlay functionality.
It also delivered meaningful packet-handling corrections, reliability improvements, and significantly expanded Intel hardware and firmware diagnostics.
The resulting source code remains a valuable experimental foundation for understanding and extending Apple-compatible peer-to-peer wireless networking on Intel hardware.
Project status: Development concluded. Source preserved for reference, research, and potential future community contributions.
Based on OpenIntelWireless AirportItlwm. Not affiliated with or endorsed by Apple or Intel.
An Ambitious project to bring Airdrop functionality to Mac OS Sonoma
Credits: # Credits & Acknowledgments
This project builds upon the work of the OpenIntelWireless community and several independent efforts to understand and implement Apple Wireless Direct Link (AWDL).
Special thanks go to the developers and researchers whose work helped make our Intel Wi-Fi experiments possible.
Project Development

NorthKoreanNoodles (Maddog860) Project direction, extensive hardware testing, experimental design, troubleshooting, and validation of driver changes.
Contributions include investigating native AWDL interface creation and registration, identifying functional limitations, interpreting real-world results, and guiding continued development toward Apple-compatible peer-to-peer Wi-Fi operation.
Artificial Intelligence — AI-Assisted Development AI coding assistants, including OpenAI ChatGPT, and Anthropic Claude generated much of the project's experimental code, modifications, instrumentation, and diagnostic tooling.
AI assistance also contributed to source analysis, firmware research, debugging strategies, and documentation. Development was guided and validated through human testing.
This acknowledgment applies to our project-specific development, not the original code written by upstream developers.

Original Driver and Technical Foundations

OpenIntelWireless / itlwm The original Intel Wi-Fi driver for macOS and the foundation of this project. Credit goes to zxystd and the OpenIntelWireless contributors for the driver architecture, hardware support, and years of development.
OpenBSD The source of important networking and Intel wireless driver foundations used by itlwm, including net80211, iwn, iwm, and iwx.
Acidanthera / MacKernelSDK Kernel development headers and supporting components used to build the macOS driver.
Intel / Linux iwlwifi An important technical reference for Intel firmware commands, station contexts, transmit queues, firmware interfaces, and device behavior. Intel's wireless firmware and documentation also provided essential information for understanding AX210 hardware operation.

KGP — Intel Driver Engineering Reference

KGP / AirportItlwm-Tahoe
KGP's AirportItlwm development provided valuable implementation references for improving the reliability of our Intel driver, particularly its lower-level packet handling and management of firmware operations.
Area
Contribution to our research
Packet transmission
DMA buffer mapping, packet ownership, and safe resource cleanup
Queue management
Deferred transmission processing when the driver cannot immediately acquire its workloop
Firmware commands
Command-slot tracking, command lifetimes, and completion safety
Reset recovery
Preventing stale operations and queued work from crossing reset boundaries
AWDL interface lifecycle
Reference implementations for creating, attaching, enabling, and publishing Apple-compatible P2P interfaces
The deferred-drain and workloop handling mechanisms were particularly useful references for our management-frame transmission investigations.
KGP's Tahoe implementation uses a different macOS wireless framework architecture from our Sonoma Skywalk-based implementation. We studied and adapted relevant engineering approaches rather than treating it as a direct replacement.
We also appreciate KGP's acknowledgment of Maddog860's earlier work on direct AWDL virtual-interface registration.

Linux AirDrop Project — AWDL Protocol Research

jedbillyb / airdrop-mt7921
This project was an especially valuable reference for understanding how a non-Apple Wi-Fi chipset can communicate using Apple's AWDL protocol.
Although it targets MediaTek hardware rather than Intel, its practical experiments and documentation helped guide several aspects of our AX210 investigation.
Key areas of influence:
	1	AWDL MAC identity synchronization Reinforced the importance of maintaining a consistent identity between the virtual AWDL interface and its radio context. Our implementation synchronized Intel firmware MAC1 with Apple's live awdl0 address, with matching addresses confirmed in runtime diagnostics.
	2	Independent peer-to-peer operation Demonstrated alternative P2P radio configurations and their interaction with ordinary Wi-Fi. This informed our investigation of Intel MAC1, PHY2, firmware binding, and P2P session scheduling.
	3	Actual radio-channel selection Highlighted why a requested channel does not always reflect the channel the radio actually uses. This was particularly relevant to discovery failures involving channels 6 and 149.
	4	AWDL synchronization and availability windows Provided practical examples of 16-slot channel sequences, synchronization offsets, peer election, channel alignment, and transmission timing.
	5	Discovery versus data transfer Helped establish the distinction between receiving AWDL advertisements, establishing a usable peer-to-peer network connection, and completing an actual AirDrop transfer.
The Linux implementation served as a protocol and engineering reference; its MediaTek-specific driver code was not directly transplanted into our Intel driver.

Additional AWDL Research and Open-Source Projects

Open Wireless Link (OWL) — SEEMOO Lab An open-source implementation of Apple's AWDL protocol. Its work on peer discovery, synchronization, master election, channel sequences, frame construction, and IPv6 networking helped establish the technical foundations for understanding AWDL outside Apple's hardware ecosystem.
OWL also underpins the Linux AirDrop implementation referenced above.
OpenDrop — SEEMOO Lab An open-source AirDrop implementation demonstrating the higher-level file-transfer protocol operating over an AWDL network. It provides useful context for distinguishing link-layer functionality from complete AirDrop compatibility.
These projects represent important independent research into Apple's proprietary wireless protocols.

Acknowledgment of Upstream Contributors

Additional recognition belongs to the many developers credited by the original OpenIntelWireless project, including those responsible for macOS wireless compatibility, Intel device support, firmware integration, network-stack adaptation, and bug fixes.
Their contributions remain part of the foundation on which this experimental work was built.
Project Scope

This is an independent, experimental Intel Wi-Fi development project.
The work described above involves a mixture of upstream open-source code, engineering references, protocol research, AI-assisted development, and physical hardware testing.
Acknowledging a project as a technical reference does not necessarily imply that its source code was directly incorporated.
Likewise, successful AWDL interface creation, peer discovery, or synchronization should not be interpreted as proof of complete AirDrop functionality.
This project is not affiliated with or endorsed by Apple, Intel, OpenIntelWireless, KGP, or the other projects acknowledged here.
