---
name: audit-context-building
description: "James integration of Trail of Bits' audit context methodology. Builds comprehensive threat models and security context documents for code audits."
---

# Audit Context Building

You are building a comprehensive security context document for a code audit engagement.

## Workflow

### 1. Codebase Overview
Gather and document:
- Primary language(s) and frameworks used.
- High-level architecture: monolith, microservices, serverless, smart contracts.
- External dependencies: key third-party libraries, services, oracles.
- Deployment environment: cloud provider, on-prem, L2/mainnet.
- Authentication and authorization model.

### 2. Architecture Diagram (Text Representation)
Produce a layered diagram of system components:
```
[External Users / Attackers]
        ↓
[Load Balancer / CDN]
        ↓
[API Gateway / Auth Layer]
        ↓
[Application Services]   ←→ [Internal Services]
        ↓
[Data Layer: DB / Cache / File Storage]
        ↓
[External APIs / Oracles / Bridges]
```
Annotate each boundary with: protocol, authentication method, trust level.

### 3. Trust Boundary Identification
For each data flow crossing a trust boundary, document:
- Source principal (who initiates).
- Destination service (who receives).
- Data type (PII, credentials, financial data, arbitrary bytes).
- Authentication mechanism at the boundary.
- Whether the boundary is validated or implicit.

### 4. Asset Inventory
List high-value assets:
- Private keys / secrets.
- User PII / financial data.
- Admin credentials / privileged accounts.
- Smart contract funds / protocol TVL.
- Sensitive configuration.

### 5. Threat Model (STRIDE)
For each major component:

| Component | Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation of Privilege |
|-----------|----------|-----------|-------------|-----------------|-----|------------------------|
| API       |          |           |             |                 |     |                        |

### 6. Audit Scope Definition
Produce:
- **In-scope**: explicit list of files, contracts, endpoints, services.
- **Out-of-scope**: what is explicitly excluded and why.
- **Known limitations**: areas that couldn't be fully reviewed.

### 7. Output Deliverable
Produce a structured `AUDIT_CONTEXT.md` with all sections above, suitable for sharing with the audit team.
