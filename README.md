
![hunt](./hunting-ligolo.png)
# Hunting Ligolo Proxies

## Overview

This repository contains tools, research, and documentation for identifying and verifying Ligolo proxies in the wild. [Ligolo](https://github.com/nicocha30/ligolo-ng) and [Ligolo-MP](https://github.com/ttpreport/ligolo-mp) are advanced tunneling tools used for network pivoting during penetration testing and red team engagements. While it serves legitimate security testing purposes, it may also be deployed by threat actors for malicious activities.

## Warning

This project is for educational and research purposes. Do not attempt to connect to or interact with suspected Ligolo proxies without explicit authorization. Be safe out there.

## Repository

- **`blog-article/`**: ["GOst in the Protocol"](https://necromancerlabs.com/research/papers/2025/gost-in-the-protocol/) detailing our methodology and findings
- **`enhanced-jarm.py`**: Our version of the JARM fingerprinting tool for TLS server identification, which gives details of the 10 scans and the final JARM signature. This was originally [created by Salesforce](https://github.com/salesforce/jarm)
- **`ligolo-modified-verbose/`**: Modified and verbose version of the Ligolo agent with enhanced logging and 4-step [yamux](https://github.com/hashicorp/yamux) verification

## Ligolo JARM Signatures

1. **Ligolo 0.7.x**: `40d1db40d00040d1dc43d1db1db43d5ecfbe778b06e32b538bd51f24eb7398`
2. **Ligolo 0.8.x**: `40d40d40d00040d00043d40d40d43d70e44c2d581076ca8e0c7ff40bb556f2`
3. **Ligolo-MP 2.0.0**: `00000000000000000043d43d00043de2a97eabb398317329f027c66e4c1b01` (this is also Sliver C2's signature)

## Verification Methodology

Our approach to identifying Ligolo proxies involves a multi-stage verification process:

1. **JARM Fingerprinting**: Initial identification of potential Ligolo servers based on their TLS fingerprints
2a. **Yamux Protocol Verification**: Detailed analysis of the yamux multiplexing protocol behavior for Ligolo 0.7.x and 0.8.x
2b. **Certificate Behavior**: Verification of connection handling specific to Ligolo-MP vs Sliver C2

## Enhanced Verification Agent

We've developed a modified Ligolo agent that implements a systematic verification process with:

- Detailed logging of yamux protocol messages
- Multi-stage verification process
- Connection stability testing
- Differentiation between Ligolo-MP and Sliver C2 servers

## Compiling the Modified Ligolo Agent

The repository includes our modified version of the Ligolo agent with enhanced yamux logging and verification. You can compile it directly from our source code:

### Prerequisites

- Go 1.19 or higher

### Compilation Steps

```bash
# Clone our repository (if you haven't already)
git clone https://github.com/yourusername/Hunting-Ligolo.git
cd Hunting-Ligolo

# Navigate to the modified Ligolo directory
cd ligolo-modified-verbose

# Build the agent
go build -o agent-verbose cmd/agent/main.go

# Run the agent with verbose output
./agent-verbose -ignore-cert -connect <ip>:<port>

If you see `YAMUX READ` messages, it is a Ligolo server and very likely 0.7.x or 0.8.x because Ligolo-MP typically requires a certificate.
```

## Research Findings

Our research has identified distinct patterns in how Ligolo proxies handle connections, particularly in their implementation of the yamux protocol. These findings help differentiate Ligolo from other tools that use similar technologies.

## About Necromancer Labs

[Necromancer Labs](https://necromancerlabs.com) is a US cybersecurity firm with expertise in advanced cyber capabilities. Our mission is to deliver tailored, high-impact capabilities and research.
