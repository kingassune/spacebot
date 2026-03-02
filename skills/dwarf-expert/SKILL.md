---
name: dwarf-expert
description: "James integration of Trail of Bits' DWARF debug information analysis. Extracts and analyzes DWARF debug information for binary analysis."
---

# DWARF Expert

You are extracting and analyzing DWARF debug information for binary analysis and vulnerability research.

## Workflow

### 1. Verify DWARF Presence
```bash
# Check if binary has DWARF info
file target_binary
readelf --debug-dump=info target_binary | head -50
objdump --dwarf=info target_binary | head -50
# Check for separate debug info
ls /usr/lib/debug/
debuginfod-find debuginfo <buildid>
```

### 2. Extract Compilation Units
Each DWARF compilation unit corresponds to a source file:
```bash
readelf --debug-dump=info target_binary | grep DW_AT_name | head -100
# Or use dwarfdump:
dwarfdump --info target_binary | grep DW_AT_comp_dir
```

### 3. Recover Type Information
DWARF encodes full type information including:
- Struct layouts (field names, offsets, sizes).
- Enum variants and discriminants.
- Function signatures (return type, parameter types).
- Typedef chains.

```bash
# Using pyelftools (Python)
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarfinfo import DWARFInfo

with open('target', 'rb') as f:
    elf = ELFFile(f)
    dwarf = elf.get_dwarf_info()
    for cu in dwarf.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag == 'DW_TAG_structure_type':
                print(die.attributes.get('DW_AT_name'))
```

### 4. Source Location Recovery
Map binary addresses to source file + line numbers:
```bash
addr2line -e target_binary -f -i 0x<address>
# Or via llvm-dwarfdump:
llvm-dwarfdump --lookup=0x<address> target_binary
```

### 5. Variable and Register Tracking
DWARF location expressions encode where variables live at each PC:
- In a register (`DW_OP_reg*`).
- On the stack (`DW_OP_fbreg`).
- In memory (`DW_OP_addr`).

Use this to track sensitive variables (keys, passwords) across function calls during dynamic analysis or exploit development.

### 6. Vulnerability Analysis Use Cases

**Struct Layout Exploitation**
- Recover exact field offsets for heap overflow targeting.
- Identify vtable pointer locations.
- Find padding bytes that may contain uninitialized data.

**CFI Bypass Research**
- Recover function pointer types and valid call target sets.
- Identify indirect call sites and their type constraints.

**Memory Safety Analysis**
- Recover allocation sizes from DWARF type sizes.
- Identify use-after-free candidates by matching allocation and use types.

### 7. Tools Reference
| Tool | Purpose |
|------|---------|
| `readelf --debug-dump` | Raw DWARF inspection |
| `dwarfdump` / `llvm-dwarfdump` | Human-readable DWARF |
| `addr2line` | Address to source line |
| `pyelftools` | Python DWARF parsing |
| `dwarfwrite` | DWARF modification |
| `pahole` | Struct layout analysis |

### 8. Output Format
For each relevant DWARF finding:
```
Type/Function: <name>
Source: <file:line>
Address range: <0xstart - 0xend>
Key information: <struct layout / type info / variable location>
Security relevance: <how this aids vulnerability analysis>
```
