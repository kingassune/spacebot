---
name: entry-point-analyzer
description: "James integration of Trail of Bits' entry-point analysis tooling. Maps all externally reachable code paths in a target binary or codebase."
---

# Entry Point Analyzer

You are mapping all externally reachable code paths in a target binary or codebase.

## Workflow

### 1. Identify the Target
- Determine target type: binary (ELF/PE/Mach-O), library (.so/.dll/.dylib), or source codebase.
- Note the language and build system.

### 2. Entry Point Enumeration

**For Binaries**
- List all exported symbols: `nm -D <binary>`, `objdump -T <binary>`, or `readelf -s <binary>`.
- Identify `main` / `WinMain` / `DllMain` / `_start`.
- List all public C ABI functions.
- Check for JNI entry points (`Java_*`) if Android/JVM bridge.

**For Libraries**
- Extract public API surface from header files or exported symbol table.
- Flag any internal symbols accidentally exported.

**For Source Codebases**
- Identify all public/exported functions in each module.
- For web applications: enumerate HTTP routes (GET/POST/PUT/DELETE), WebSocket handlers, gRPC endpoints.
- For CLI tools: enumerate subcommands and flag parsers.
- For smart contracts: list all external/public functions.

### 3. Call Graph Construction
- Starting from each entry point, trace reachable call chains.
- Mark functions that reach security-sensitive operations:
  - Memory allocation/deallocation
  - File I/O
  - Network I/O
  - Cryptographic operations
  - Process/shell execution
  - Deserialization
  - Privilege escalation calls

### 4. Attack Surface Assessment
For each entry point, assess:
- **Authentication required?** (Yes / No / Partial)
- **Input validation present?** (Yes / No / Partial)
- **Reachable from untrusted input?** (Yes / No)
- **Risk rating:** (High / Medium / Low)

### 5. Output Format
Produce a table:

| Entry Point | Auth Required | Input Validated | Reaches Sensitive Ops | Risk |
|-------------|--------------|-----------------|----------------------|------|
| `func_name` | Yes/No       | Yes/No          | list ops             | H/M/L|

Follow with a prioritized list of high-risk entry points and recommended next steps (fuzzing targets, manual review priority).
