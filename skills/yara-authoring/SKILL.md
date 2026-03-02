---
name: yara-authoring
description: "James integration of Trail of Bits' YARA rule authoring methodology. Creates YARA rules for malware detection and code pattern matching."
---

# YARA Rule Authoring

You are writing YARA rules for malware detection or code pattern matching.

## Workflow

### 1. Define the Detection Goal
- What are you trying to detect? (malware family, suspicious behavior, specific string/binary pattern)
- What artifacts will be scanned? (binaries, memory dumps, source files, network captures)
- What is the acceptable false positive rate? (low for production, higher for triage)

### 2. YARA Rule Structure
```yara
rule RuleName : tag1 tag2 {
    meta:
        description = "What this rule detects"
        author = "Author name"
        date = "YYYY-MM-DD"
        reference = "https://source.example.com"
        hash = "sha256_of_a_sample"
        tlp = "WHITE"  // or GREEN, AMBER, RED

    strings:
        // Text strings
        $s1 = "suspicious_string"
        $s2 = "another_indicator" ascii wide  // wide = UTF-16LE

        // Hex byte patterns with wildcards
        $hex1 = { 4D 5A ?? ?? ?? ?? ?? ?? ?? ?? 50 45 }  // ?? = any byte
        $hex2 = { 6A 40 68 00 30 00 00 [4-8] 6A 14 }     // [N-M] = N to M bytes

        // Regular expressions
        $re1 = /https?:\/\/[a-z]{8,12}\.(tk|ml|ga)\/.{0,30}/

    condition:
        // File type check
        uint16(0) == 0x5A4D  // MZ header (PE file)
        and
        // String conditions
        (2 of ($s*))
        and
        $hex1
        and not $re1
}
```

### 3. Condition Patterns

**File type identification**:
```yara
uint16(0) == 0x5A4D    // PE (MZ)
uint32(0) == 0x464C457F // ELF
uint32(0) == 0xFEEDFACF // Mach-O 64-bit
```

**Entropy check (packed/encrypted content)**:
```yara
math.entropy(0, filesize) >= 7.0
```

**File size bounding**:
```yara
filesize > 100KB and filesize < 10MB
```

**Combining string counts**:
```yara
3 of ($s*)           // at least 3 of $s1, $s2, $s3, ...
all of ($hex*)       // all hex patterns must match
any of them          // any defined string
```

**Offset-based matching**:
```yara
$s1 at 0             // string at exact offset
$s1 in (0..512)      // string within first 512 bytes
```

### 4. Testing Rules
```bash
yara -r rule.yar /path/to/samples/     # Scan directory
yara -s rule.yar sample.bin            # Show matching strings
yara --profile rule.yar sample.bin     # Performance profiling
```

### 5. Performance Considerations
- Place most-selective strings first for early rejection.
- Avoid overly broad regexes in hot paths.
- Use `filesize` bounds to skip obviously wrong files.
- Prefer hex patterns over string patterns for binary detection.

### 6. Output
Produce a `.yar` file with the complete rule, plus a test corpus note indicating which samples should match and which should not.
