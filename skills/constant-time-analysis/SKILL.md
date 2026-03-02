---
name: constant-time-analysis
description: "James integration of Trail of Bits' constant-time code analysis. Reviews cryptographic implementations for timing side-channel vulnerabilities."
---

# Constant-Time Analysis

You are reviewing cryptographic code for timing side-channel vulnerabilities.

## Core Principle
Cryptographic code must not branch on secret data, must not use secret data as memory indices, and must not perform variable-time operations whose timing can be observed by an attacker.

## Workflow

### 1. Identify Secret-Dependent Operations
Scan for constructs where a secret value influences:
- **Conditional branches**: `if secret == expected { ... }`
- **Loop counts**: `for i in 0..secret_len { ... }`
- **Array indices**: `table[secret[i] as usize]`
- **Early exits**: `return false` inside a comparison loop

### 2. Variable-Time Comparisons
**Insecure**:
```rust
// Short-circuit: exits as soon as bytes differ
if a == b { ... }
// Or explicit loop with early return
for i in 0..n { if a[i] != b[i] { return false; } }
```

**Secure** (constant-time equality):
```rust
use subtle::ConstantTimeEq;
if a.ct_eq(&b).into() { ... }
```

Flag all equality comparisons involving:
- MAC tags / HMAC values.
- Passwords or password hashes.
- Session tokens / API keys.
- Cryptographic keys.

### 3. Table Lookups (Cache Timing)
**Insecure** (AES S-box lookup leaks key bits via cache):
```c
output = sbox[key[i] ^ input[i]];  // cache timing attack
```

**Secure**: use bit-sliced implementations or hardware AES instructions.

Flag all array lookups where the index depends on secret data.

### 4. Modular Arithmetic
**Insecure** (variable-time division in modular reduction):
```python
result = (a * b) % modulus  # Python's % is variable-time
```

Flag: `%` operator on secrets in Python/Go. Use constant-time Montgomery multiplication for RSA/ECC primitives.

### 5. Rust-Specific Checks
- Verify `subtle` crate is used for all secret comparisons: `ConstantTimeEq`, `ConstantTimeLess`, `ConditionallySelectable`.
- Verify no `PartialEq` derived for types containing secrets (derives `==` which short-circuits).
- Check `zeroize` is used on secret types (sensitive to memory timing as well).

### 6. Compiler / Optimizer Risk
Note: compilers can optimize away constant-time constructs. Verify:
- `#[inline(never)]` or memory fences where optimizer might eliminate branches.
- Use `core::hint::black_box` to prevent dead-code elimination of secret operations.
- In C: use `volatile` reads or compiler memory barriers for zeroing secrets.

### 7. Output Format
```
[SEVERITY: Critical/High/Medium]
Location: <file:line>
Issue: <type: Branch/Comparison/Table-Lookup/Arithmetic>
Secret: <what secret value is involved>
Observable timing: <how an attacker measures the timing>
Fix: <constant-time alternative>
```
