# /blockchain-audit

Orchestrates a full blockchain security audit across all sub-skills.

## Usage

```
/blockchain-audit <target> [--chain <chain>] [--scope <scope>]
```

## Parameters

- `target`: Contract address, repository URL, or protocol name
- `--chain`: Target blockchain (ethereum, solana, cosmos, arbitrum, optimism, polygon, etc.) [default: ethereum]
- `--scope`: Audit scope (full, contracts, defi, bridge, consensus) [default: full]

## Workflow

1. **Contract analysis** (`contract-audit` skill) — enumerate contracts, run static analysis, identify vulnerability patterns
2. **DeFi protocol review** (`defi-security` skill) — flash loan vectors, oracle risk, MEV exposure, liquidity pool security
3. **Bridge security assessment** (`bridge-audit` skill) — message verification, nonce management, mint authority
4. **Wallet security review** (`wallet-security` skill) — approval patterns, key entropy, transaction simulation
5. **ZK proof system audit** (`zk-audit` skill, if applicable) — circuit constraints, trusted setup, nullifier enforcement
6. **Consensus mechanism analysis** (`consensus-analysis` skill) — attack thresholds, validator distribution, finality
7. **Unified findings report** — aggregated CVSS-scored findings with remediation roadmap

## Examples

```
/blockchain-audit 0x1234567890abcdef1234567890abcdef12345678 --chain ethereum
/blockchain-audit https://github.com/protocol/contracts --scope contracts
/blockchain-audit myprotocol --chain cosmos --scope defi,bridge
/blockchain-audit 0xabcd... --chain arbitrum --scope full
```

## Output

The command produces a structured audit report containing:

- Executive summary with overall risk rating
- Per-category findings table with severity and CVSS scores
- Detailed finding writeups with PoC and remediation
- Remediation priority matrix (Critical → Low)
- Appendix: tool output, methodology notes
