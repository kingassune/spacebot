---
name: consensus-analysis
description: "Consensus mechanism security analysis covering attack thresholds (51% PoW, 33.4% BFT/PoS), validator scoring, stake distribution analysis, finality analysis, and nothing-at-stake and grinding attacks."
allowed-tools: ["shell", "file", "exec"]
---

# Consensus Mechanism Security Analysis

You are analyzing the security of a blockchain consensus mechanism within an authorized engagement. Consensus vulnerabilities can enable double-spends, censorship, finality reversals, and complete network takeover.

## Pre-Analysis Setup

- Identify consensus type: Nakamoto PoW, Tendermint BFT, Casper FFG, Gasper (Ethereum), Avalanche, HotStuff, PBFT, PoA, or custom.
- Document validator/miner set size, stake distribution data source, and block time.
- Identify finality model: probabilistic (PoW), deterministic (BFT), or hybrid.
- Obtain current validator set, stake amounts, and geographic/operator distribution.

## Attack Thresholds

### Proof of Work (51% Attack)

```bash
# Calculate current network hashrate from block header difficulty
# Ethereum Classic example
python3 -c "
import requests
resp = requests.get('https://api.blockchair.com/ethereum-classic/stats')
data = resp.json()['data']
hashrate_th = data['hashrate_24h'] / 1e12
print(f'Network hashrate: {hashrate_th:.2f} TH/s')
print(f'Attack cost (1hr): ~\${hashrate_th * 0.05 * 1:.2f}K USD (estimate)')
"

# Check NiceHash attack feasibility
# Compare target hashrate vs NiceHash available rental capacity
```

**Analysis criteria:**

| Metric | Safe Threshold | Risk Indicator |
|---|---|---|
| Hashrate concentration (top miner) | <25% | >40% |
| Hashrate concentration (top 3 miners) | <50% | >60% |
| NiceHash rental / network hashrate | <5% | >20% |
| Reorganization depth (last 30 days) | 0–1 | >3 |
| Merge mining share | <30% | >50% |

### BFT / Proof of Stake (33.4% Attack)

For Byzantine Fault Tolerant protocols (Tendermint, Casper, HotStuff), safety fails if ≥1/3 of voting power is Byzantine.

```bash
# Fetch validator set and compute Nakamoto coefficient
# Example: Cosmos chain via API
curl -s "$NODE_API/cosmos/staking/v1beta1/validators?status=BOND_STATUS_BONDED&pagination.limit=500" \
  | jq '[.validators[] | {moniker: .description.moniker, tokens: (.tokens | tonumber)}]' \
  | jq 'sort_by(-.tokens)' > validator_set.json

# Compute Nakamoto coefficient (min validators needed for 33.4%)
python3 -c "
import json, sys
validators = json.load(open('validator_set.json'))
total = sum(v['tokens'] for v in validators)
threshold = total * 0.334
cumulative = 0
for i, v in enumerate(validators):
    cumulative += v['tokens']
    if cumulative >= threshold:
        print(f'Nakamoto coefficient: {i+1}')
        print(f'Top validator share: {validators[0][\"tokens\"]/total*100:.1f}%')
        break
"
```

**Analysis criteria:**

| Metric | Safe | At Risk | Critical |
|---|---|---|---|
| Nakamoto coefficient (33.4%) | ≥20 | 7–19 | <7 |
| Top validator stake share | <10% | 10–20% | >20% |
| Exchange-controlled validators | <15% | 15–30% | >30% |
| Foundation-controlled stake | <10% | 10–20% | >20% |

## Validator Scoring and Stake Distribution Analysis

### Distribution Metrics

```bash
# Gini coefficient of stake distribution (Rust reference: src/blockchain_security/consensus.rs)
python3 -c "
import json
validators = json.load(open('validator_set.json'))
stakes = sorted([v['tokens'] for v in validators])
n = len(stakes)
total = sum(stakes)
gini = (2 * sum((i+1)*s for i,s in enumerate(stakes)) - (n+1)*total) / (n * total)
print(f'Gini coefficient: {gini:.4f} (0=equal, 1=monopoly)')
print(f'Validator count: {n}')
print(f'Top 10 share: {sum(stakes[-10:])/total*100:.1f}%')
"
```

### Operator Concentration

- Map validator operators to known entities (exchanges, foundations, staking providers).
- Identify validators sharing infrastructure (same ASN, same data center).
- Flag validators with correlated slashing risk (co-located, same client software).

```bash
# Check client diversity
curl -s "$NODE_API/cosmos/base/node/v1beta1/config" | jq '.minimum_gas_prices'

# For Ethereum: check client diversity via clientdiversity.org data
curl -s "https://clientdiversity.org/api/data" | jq '.execution, .consensus'
```

### Slashing History

- Query slashing events for the past 30 days.
- High slashing frequency may indicate buggy validator software or attack attempts.
- Sudden mass slashing could indicate a coordinated censorship or equivocation attack.

## Finality Analysis

### Deterministic Finality (BFT)

- Confirm that once a block is finalized (2/3+ signed), it cannot be reverted.
- Assess the finality time (≤6 seconds in Tendermint, ~12 min in Ethereum Casper FFG).
- Verify the liveness condition: can the chain stall if validators are offline?

```bash
# Check finality checkpoints (Ethereum beacon chain)
curl -s "$BEACON_API/eth/v1/beacon/states/head/finality_checkpoints" | jq '.'

# Measure finality lag
# Justified epoch should trail current epoch by ≤2
```

### Long-Range Attack Assessment

Long-range attacks target PoS chains: an attacker acquires old private keys of validators who have since unbonded and rewrites history from a deep block.

**Mitigations to verify:**

- [ ] Weak subjectivity checkpoints are distributed and clients enforce them.
- [ ] Unbonding period is long enough to prevent key acquisition (≥21 days typical).
- [ ] Social consensus layer (trusted checkpoint sources) is documented.

## Nothing-at-Stake and Grinding Attacks

### Nothing-at-Stake

In naive PoS, validators can sign multiple competing forks at no cost (no physical resource expended).

**Mitigations to verify:**

- [ ] Slashing conditions defined for equivocation (signing two blocks at the same height).
- [ ] Slashing conditions defined for surround votes (Ethereum Casper).
- [ ] Slashers / watchtowers are operational and submit evidence within the proof window.

```bash
# Check slashing condition configuration
grep -rn "slash\|equivocation\|double_sign\|surround" config/ genesis.json
```

### Grinding Attacks (VRF-Based PoS, RANDAO)

Validators may attempt to grind through block proposals to influence future leader selection.

**For RANDAO (Ethereum):**

- Assess last-revealer bias: the last proposer can choose to reveal or not to manipulate the RANDAO output.
- Verify RANDAO is not the sole entropy source for applications requiring unpredictable randomness.

**For VRF-Based (Cardano, Algorand, Solana PoH):**

- Verify the VRF output is verifiable and deterministic — no grinding possible.
- Confirm the VRF key is bound to the validator's stake key (cannot be refreshed to get a better output).

```bash
# Check VRF configuration
grep -rn "vrf\|randao\|vdf\|randomness\|leader_election" config/ src/
```

## Reference Module

```
src/blockchain_security/consensus.rs — ConsensusAnalyzer
```

## Output Checklist

- [ ] Consensus type identified and appropriate thresholds applied
- [ ] Nakamoto coefficient computed
- [ ] Stake Gini coefficient and top-N concentration measured
- [ ] Operator and infrastructure concentration assessed
- [ ] Client software diversity evaluated
- [ ] Finality mechanism verified
- [ ] Long-range attack mitigations confirmed
- [ ] Nothing-at-stake slashing conditions verified
- [ ] Grinding attack resistance assessed
- [ ] All findings CVSS-scored with remediation guidance
