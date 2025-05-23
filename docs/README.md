# Connection by Jamie

**Owner:** Jamie Terpening  
**Project:** Connection byJamie  
**Copyright:** © 2025 Jamie Terpening. All rights reserved.

---

## Overview

Connection byJamie is the world’s first **fully self-proving, quantum-secure, user-owned digital civilization mesh network**, designed for the **AWS Breaking Barriers Virtual Challenge 2025**. It integrates **AWS generative AI** (SageMaker, Bedrock), **post-quantum cryptography (PQC)**, **real-time auditability**, and **radical user sovereignty** to create a decentralized, transparent, and resilient platform for global human rights defense and community governance.

### Key Features
- **Quantum-Resilient Mesh Network**: Built with **AWS IoT**, **Greengrass**, **Lambda**, **SageMaker**, **Bedrock**, and **Amplify**, ensuring secure, scalable, and low-latency communication across distributed nodes.
- **Truth Beacon Protocol**: Every node, AI component, and admin action broadcasts **PQC-signed** (Kyber, Dilithium) and **zk-SNARK-attested** integrity proofs, enabling instant quarantine and reversion of compromised components (`bedrock.py`, `anomaly_gnn.py`).
- **Radical User Agency**: Empowers users with **micro-playbooks** (`playbook_synth.py`), **mesh democratization**, **crowdsourced healing**, and **mesh law** governance (`mesh_law.py`, `law_params.yaml`).
- **Global Transparency**: All events, actions, and incidents are logged immutably to **AWS QLDB** (`qldb_logger.py`) and published to a public S3 feed (`public_feed.py`) with real-time cryptographic proofs.
- **Decentralized Human Rights Defense**: **Lighthouse Mode** (`lighthouse.py`) supports **onion-routed** whistleblower reports (`onion_router.py`) and **verifiable witness statements** (`witness_statement.py`, `human_rights_monitor.py`, `ngo_api.py`).
- **Next-Gen UI**: The **3D Nexus Console** provides real-time **Harmony/Truthfulness maps**, **Time Machine replay** (`time_machine.py`), and verifiable user privacy status.
- **No Single Point of Trust**: Every component is cryptographically accountable, leveraging **zk-SNARKs** (`zkp.py`, `verifier.py`), **Merkle trees** (`merkle_tools.py`), and **Hyperledger Fabric** (`fabric_bridge.py`).

### System Architecture
See [WHITEPAPER.md](./WHITEPAPER.md) for a detailed system and architecture description, including:
- **AI Core**: Cognitive Seed (`bedrock.py`, `ai_config.yaml`) with federated learning and anomaly detection (`anomaly_gnn.py`).
- **Mesh Network**: Quantum-secure routing and consensus (`mesh_settings.yaml`, `mesh_node.py`).
- **Human Rights Defense**: Lighthouse Mode and NGO integration (`lighthouse.py`, `ngo_api.py`, `human_rights_monitor.py`).
- **Compliance and Governance**: Mesh law and privacy compliance (`mesh_law.py`, `law_params.yaml`).

## Ownership, License, and Usage

- **Sole Owner:** Jamie Terpening  
- **Project Built By:** byJamie  
- **Open Source Status**:  
  - Released as **open source** solely to comply with the **AWS Breaking Barriers Hackathon 2025 Official Rules** [](https://aws-breaking-barriers.devpost.com/rules).
  - **Restricted Access**: No rights are granted except for AWS, Devpost, and hackathon judges to access, test, and evaluate the submission per the Official Rules.
  - **Prohibited Actions**: Reuse, redistribution, or creation of derivative works outside hackathon evaluation is **expressly prohibited**.
  - **Contact**: For any questions on use or rights, contact Jamie Terpening directly at [email_jamie@nexxusos.com].

- **License Details**: See [LICENSE](./LICENSE) for precise legal terms.

## Hackathon Requirements & Compliance

- **AWS Integration**: Utilizes **SageMaker** and **Bedrock** for generative AI, **IoT** and **Greengrass** for mesh networking, **Lambda** for serverless processing, **QLDB** for immutable logging, and **Amplify** for UI deployment.
- **Newly Created**: Developed specifically for the AWS Breaking Barriers Hackathon 2025, meeting all project and submission requirements.
- **Judge Access**: Temporary, restricted open-source access is granted for evaluation and testing purposes only.
- **Submission Details**: Fully compliant with hackathon rules, with all required components documented and accessible.

## Getting Started

### Prerequisites
- **AWS Account**: Configured with access to SageMaker, Bedrock, IoT, Greengrass, Lambda, QLDB, S3, and Amplify.
- **Dependencies**: Python 3.9+, `boto3`, `hfc`, `pysnark`, `pyhelib`, `tpm2-pytss`, and other libraries listed in [requirements.txt](./requirements.txt).
- **Hardware**: Nodes require TPM 2.0 for attestation (`tpm_attest.py`) and LoRa/Shortwave/Satellite radios for fallback connectivity (`mesh_settings.yaml`).
- **Network**: Stable internet for initial setup; mesh operates offline with fallback radios.

### Setup Instructions
1. **Clone Repository**:
   ```bash
   git clone [repository-url]
   cd connection-byjamie