---
name: zeroize-audit
description: "James integration of Trail of Bits' zeroize audit methodology. Reviews Rust code for proper secret zeroing and sensitive data lifecycle management."
---

# Zeroize Audit

You are auditing Rust code for proper zeroing of secrets and sensitive data lifecycle management.

## Core Principle
Secret data (private keys, passwords, session tokens, symmetric keys, PII) must be zeroed from memory as soon as it is no longer needed. Copies must be tracked. Compiler optimizations that elide zeroing must be prevented.

## Workflow

### 1. Identify Secret Types
Scan for types that hold sensitive data:
- Types containing `key`, `secret`, `password`, `token`, `seed`, `mnemonic`, `private` in their names.
- Types wrapping `Vec<u8>`, `[u8; N]`, `String`, `Box<[u8]>` used in crypto contexts.
- Heap-allocated buffers from FFI that contain key material.

### 2. Check `Zeroize` / `ZeroizeOnDrop` Derivation
**Required pattern**:
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretKey([u8; 32]);
```

Flag types that:
- Hold secret data but do NOT derive `Zeroize` + `ZeroizeOnDrop`.
- Implement `Drop` manually but don't call `zeroize()`.
- Use `#[derive(Clone)]` on a secret type without also zeroing clones.

### 3. Check for Stray Copies
Track all places where a secret type is:
- Cloned: `secret.clone()` — is the clone also zeroed?
- Moved into a collection: `vec.push(secret)` — does the collection zero on drop?
- Passed to a function by value: does the callee zero it?
- Serialized to a `String` or `Vec<u8>`: is the serialized form zeroed?

### 4. Compiler Optimization Risk
The compiler may optimize away writes to memory it considers "dead":
```rust
// BAD: compiler may elide this write
let mut key = [0u8; 32];
key.copy_from_slice(&secret);
use_key(&key);
key = [0u8; 32]; // may be removed as dead store
```

**Correct**:
```rust
use zeroize::Zeroize;
let mut key = [0u8; 32];
key.copy_from_slice(&secret);
use_key(&key);
key.zeroize(); // calls volatile writes, not optimized away
```

Verify all manual zeroing uses `zeroize()` or `std::ptr::write_volatile`.

### 5. FFI and Unsafe Code
Check `unsafe` blocks that:
- Receive key material via raw pointer from C code.
- Return key material via raw pointer to C code.
- Use `std::alloc` directly for secret buffers.

Verify these paths call `ptr::write_bytes` (volatile) for zeroing, or wrap in a `Zeroize`-implementing type.

### 6. Logging and Debug Output
Verify secret types:
- Do NOT implement `Display` or `Debug` in a way that reveals the secret.
- Implement `Debug` as `Debug for SecretKey { "<redacted>" }` or derive `zeroize::Zeroize` only.

### 7. Output Format
```
[SEVERITY: High/Medium/Low]
Location: <file:line>
Type: <type name>
Issue: Missing Zeroize / Stray Copy / Compiler Risk / Debug Leak / FFI Gap
Description: <what the issue is>
Fix: <specific code change required>
```

### 8. Remediation Checklist
- [ ] All secret types derive `Zeroize` + `ZeroizeOnDrop`.
- [ ] No manual `[0u8; N]` assignment for zeroing (use `.zeroize()`).
- [ ] All clones of secret types are also zeroed.
- [ ] No `Debug`/`Display` impls that reveal secret values.
- [ ] FFI secret buffers use volatile-write zeroing.
