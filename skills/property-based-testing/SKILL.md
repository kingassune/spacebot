---
name: property-based-testing
description: "James integration of Trail of Bits' property-based testing methodology. Designs and implements property-based test suites for security-critical code."
---

# Property-Based Testing

You are designing and implementing property-based tests for security-critical code.

## Workflow

### 1. Identify Security Properties
Security properties are invariants that must hold for all inputs. Examples:
- **Reversibility**: `decrypt(encrypt(m, k), k) == m` for all valid `m, k`.
- **Non-forgery**: `verify(sign(m, privkey), m, pubkey) == true` always; `verify(tampered, m, pubkey) == false` always.
- **Idempotency**: applying an operation twice yields the same result as once.
- **Commutativity**: order of inputs doesn't matter.
- **Bounds**: output is always within a valid range.
- **No panics**: function never panics on any input (use `proptest` catch_unwind).
- **Access control**: privileged operation always rejects unprivileged callers.
- **No information leak**: two inputs that should produce the same observable output do.

### 2. Rust — proptest
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn encrypt_decrypt_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        key in prop::array::uniform32(any::<u8>()),
    ) {
        let ciphertext = encrypt(&plaintext, &key);
        let recovered = decrypt(&ciphertext, &key).unwrap();
        prop_assert_eq!(plaintext, recovered);
    }

    #[test]
    fn no_panic_on_arbitrary_input(input in any::<Vec<u8>>()) {
        // Should never panic, just return Err
        let _ = parse_untrusted_message(&input);
    }
}
```

### 3. Rust — cargo-fuzz / libFuzzer
```rust
// fuzz/fuzz_targets/fuzz_parser.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_untrusted_message(data);
});
```
Run: `cargo fuzz run fuzz_parser`

### 4. Python — Hypothesis
```python
from hypothesis import given, settings
from hypothesis import strategies as st

@given(st.binary(max_size=1024))
@settings(max_examples=10000)
def test_no_panic_on_arbitrary_bytes(data):
    try:
        parse_message(data)
    except ValueError:
        pass  # Expected for invalid input
    except Exception as e:
        assert False, f"Unexpected exception: {e}"
```

### 5. Solidity — Echidna Invariants
```solidity
// Test that total supply never decreases without a burn
function echidna_total_supply_monotonic() public returns (bool) {
    return token.totalSupply() >= initialSupply;
}

// Test that only owner can mint
function echidna_only_owner_mints() public returns (bool) {
    uint256 before = token.totalSupply();
    try token.mint(address(this), 1) {
        return msg.sender == token.owner();
    } catch {
        return true;
    }
}
```

### 6. Identifying Good Fuzzing Targets
Prioritize functions that:
- Parse untrusted external input (network, file, user).
- Perform cryptographic operations.
- Implement state machines with complex transitions.
- Execute arithmetic on user-supplied values.
- Have security-critical access control logic.

### 7. Output
Produce a test file with property-based tests for the target code, with each property clearly documented explaining what security invariant it enforces.
