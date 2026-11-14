<div align="center">

# Decentralized Cyber Threat Sharing Platform using zk-SNARKs
**Privacy-Preserving Threat Intelligence Sharing, IOC Extraction, and Cross-Organization Threat Matching**

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg?logo=python&logoColor=white)](https://python.org)
[![Circom](https://img.shields.io/badge/ZK--Proofs-Circom%20%2F%20SnarkJS-purple.svg)]()
[![Ethereum](https://img.shields.io/badge/Blockchain-Ethereum%20%2F%20Solidity-363636.svg?logo=ethereum)](https://ethereum.org)
[![IPFS](https://img.shields.io/badge/Storage-IPFS-65C2CB.svg?logo=ipfs&logoColor=white)](https://ipfs.tech)

*Enabling organizations to share, verify, and match cyber threat intelligence in real time without exposing proprietary infrastructure or sensitive internal logs.*

</div>

---

## Problem Statement & Motivation
Organizations frequently face identical cyberattacks, yet cross-organizational threat intelligence sharing remains broken due to three critical barriers:
1. **Privacy & Compliance Risk:** Sharing raw threat reports exposes sensitive internal IP addresses, compromised endpoints, and proprietary infrastructure details.
2. **Centralized Single Points of Failure:** Traditional threat-sharing platforms rely on central repositories vulnerable to breaches, tampering, and single-admin manipulation.
3. **Lack of Trust & Verification:** Without cryptographic guarantees, organizations cannot verify whether incoming threat alerts are genuine without inspecting confidential underlying payloads.

### Solution Overview
We engineered a decentralized, zero-trust threat-sharing platform combining **NLP/Regex IOC Extraction**, **Circom zk-SNARKs**, **IPFS**, and **Ethereum Smart Contracts**. Entities upload unstructured threat reports, extract structured Indicators of Compromise (IOCs), generate zero-knowledge proofs confirming threat validity, store encrypted payloads on IPFS, and automatically detect overlapping threats across organizations using cryptographic hash matching.

---

## System Architecture & Data Flow

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                     OFF-CHAIN (ORGANIZATION NODE)                       │
│                                                                         │
│  [Threat Report Upload: PDF / DOCX / JSON]                              │
│                     │                                                   │
│                     ▼                                                   │
│  ┌────────────────────────────────────┐                                 │
│  │ 1. IOC Extraction (Regex + NLP)    │──► Extracts IPs, File Hashes,   │
│  └──────────────────┬─────────────────┘    Malware Signatures -> JSON   │
│                     │                                                   │
│         ┌───────────┴───────────┐                                       │
│         ▼                       ▼                                       │
│  ┌──────────────────┐   ┌───────────────────────────────┐               │
│  │ 2a. Encrypt &    │   │ 2b. Circom zk-SNARK Circuit   │               │
│  │ Store on IPFS    │   │ • Generates Proof + Nullifier │               │
│  └────────┬─────────┘   └───────────────┬───────────────┘               │
└───────────┼─────────────────────────────┼───────────────────────────────┘
            │ Returns IPFS CID            │ Outputs { proof, publicSignals }
            └──────────────┬──────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       ON-CHAIN & CROSS-NODE LAYER                       │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ 3. Ethereum Smart Contract (submitThreatReport & verifyZKProof)    │ │
│  │    • Verifies zk-SNARK proof & prevents replay via ZK Nullifiers   │ │
│  │    • Anchors IPFS CID + Threat Metadata Hash immutably on-chain    │ │
│  └─────────────────────────────────┬──────────────────────────────────┘ │
│                                    ▼                                    │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ 4. Privacy-Preserving Threat Matching Engine                       │ │
│  │    • Compares hashed IOCs across organizations                     │ │
│  │    • Triggers real-time alerts on overlapping threat signatures    │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
