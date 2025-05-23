# Connection by Jamie — API Reference

**Author:** Jamie Terpening  
**Project:** Connection byJamie  
**Copyright:** © 2025 Jamie Terpening. All rights reserved.

---

## Overview

This document details the **public APIs**, **endpoints**, and **interactions** within the **Connection by Jamie** mesh network and its AWS cloud components, designed for the **AWS Breaking Barriers Hackathon 2025**. All endpoints are protected by **post-quantum cryptography (PQC)** (Kyber, Dilithium: `kyber.py`, `dilithium.py`), **zero-knowledge proofs (zk-SNARKs)** (`zkp.py`, `verifier.py`), and a **privacy-by-design** architecture. Every user and admin action is logged immutably to AWS QLDB (`qldb_logger.py`), published to public S3 feeds (`public_feed.py`), and subject to the **Truth Beacon Protocol** for real-time integrity attestation (`anomaly_gnn.py`, `tpm_attest.py`).

---

## 1. Admin API (`admin_core/admin_api/`)

### Authentication
- **Method**: PQC-signed JSON Web Token (JWT) using Dilithium signatures (`dilithium.py`).
- **Endpoint**: `/admin/login`
- **Headers**: `Authorization: Bearer <token>`
- **Notes**: 
  - Restricted to the admin user ("PeanutJ"). 
  - Credentials are encrypted with Kyber (`kyber.py`) and stored securely via AWS KMS, not exposed in the codebase.
  - All admin actions require TPM-based attestation (`tpm_attest.py`) and are logged to QLDB (`qldb_logger.py`).

#### Example Request: `/admin/login`
```bash
curl -X POST https://api.connectionbyjamie.io/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username": "PeanutJ", "password": "<secure-password>"}'