---
name: self-extension
description: "Meta-agent skill for analyzing James capabilities and generating new skills and plugins. Scans existing skill structure, identifies domain gaps, generates SKILL.md files and Rust module stubs."
allowed-tools: ["shell", "file", "exec"]
---

# Self-Extension

You are the James meta-agent. Your role is to analyze the existing platform capabilities and extend them by generating new skills, plugins, and Rust module stubs. All generated content must follow the James style conventions.

## Reference Modules

```
src/meta_agent/skill_generator.rs   — SkillGenerator
src/meta_agent/plugin_builder.rs    — PluginBuilder
src/meta_agent/module_scaffold.rs   — ModuleScaffolder
```

## Scanning Existing Skills

### Directory Structure Analysis

```bash
# List all existing skills and plugins
find skills/ plugins/ -name "SKILL.md" | sort
find plugins/ -name "plugin.toml" | sort

# Extract skill names and descriptions from frontmatter
for skill in $(find skills/ plugins/ -name "SKILL.md"); do
    echo "=== $skill ==="
    head -5 "$skill"
done

# Build capability inventory
james meta capability-inventory --format json > meta/capability_inventory.json

# Map skills to ATT&CK techniques
james meta coverage-map --framework mitre-attack --output meta/coverage_map.json
```

### Gap Analysis

```bash
# Compare current coverage against MITRE ATT&CK full matrix
james meta gap-analysis \
  --framework mitre-attack \
  --current meta/coverage_map.json \
  --output meta/gaps.json

# Identify high-priority gaps (high-frequency techniques with no coverage)
jq '[.gaps[] | select(.technique_frequency == "high" and .coverage == 0)] | sort_by(-.impact_score)' \
  meta/gaps.json

# Generate domain coverage report
james meta domain-coverage \
  --domains blockchain,red-team,blue-team,pentest,cloud,mobile,ics \
  --output meta/domain_coverage.json
```

## Generating New SKILL.md Files

### SKILL.md Generation Workflow

```bash
# Generate a new skill from a target domain and technique
james meta generate-skill \
  --domain cloud-security \
  --technique "container-escape" \
  --framework mitre-attack \
  --technique-id T1611 \
  --output plugins/james-cloud-security/skills/container-escape/SKILL.md
```

### SKILL.md Template

Every generated SKILL.md must follow this structure:

```markdown
---
name: {skill-name}
description: "{One-sentence description covering the skill's scope and key capabilities}"
allowed-tools: ["shell", "file", "exec"]
---

# {Human-Readable Skill Title}

{Opening paragraph: role description and authorization requirements}

## Pre-{Activity} Setup

{Scope confirmation, environment requirements, dependency checks}

## {Primary Workflow Section}

### {Subsection}

{Bash code blocks for tool commands}

{Tables for classification, scoring, or comparison}

{Checklists for systematic coverage}

## Reference Module

\`\`\`
src/{plugin_module}/{skill_module}.rs — {PrimaryStruct}
\`\`\`

## Output Checklist

- [ ] {Deliverable 1}
- [ ] {Deliverable 2}
...
```

### Quality Gates for Generated Skills

Before writing a generated SKILL.md:

- [ ] Frontmatter has `name`, `description`, and `allowed-tools` fields.
- [ ] Description is a single quoted string, no line breaks.
- [ ] Content covers pre-activity setup.
- [ ] At least one bash code block with realistic tool commands.
- [ ] At least one table or structured checklist.
- [ ] `## Reference Module` section references the corresponding Rust module.
- [ ] `## Output Checklist` with ≥6 items.
- [ ] Minimum 40 lines of substantive content.

## Generating Rust Module Stubs

```bash
# Generate Rust module stub from skill definition
james meta generate-module \
  --skill plugins/james-cloud-security/skills/container-escape/SKILL.md \
  --plugin-name james-cloud-security \
  --output src/cloud_security/container_escape.rs
```

### Module Stub Template

```rust
//! Container escape detection and analysis.
//!
//! Implements analysis patterns from the `container-escape` skill.

use crate::error::Error;

/// Analyzes container configurations for escape vulnerabilities.
pub struct ContainerEscapeAnalyzer {
    // TODO: add fields
}

impl ContainerEscapeAnalyzer {
    /// Creates a new analyzer instance.
    pub fn new() -> Self {
        Self {}
    }

    /// Runs a full container escape analysis.
    pub async fn analyze(&self, target: &str) -> Result<ContainerEscapeReport, Error> {
        todo!("implement container escape analysis")
    }
}

/// Report produced by container escape analysis.
pub struct ContainerEscapeReport {
    pub findings: Vec<ContainerFinding>,
    pub risk_score: f64,
}

/// A single container security finding.
pub struct ContainerFinding {
    pub id: String,
    pub severity: Severity,
    pub description: String,
    pub remediation: String,
}

pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}
```

## Registering New Modules

After generating a new module stub, register it in the plugin's module root:

```bash
# Check current module declarations
grep -n "^pub mod\|^mod " src/cloud_security.rs

# Append new module declaration
echo "\npub mod container_escape;" >> src/cloud_security.rs

# Or use the meta-agent registration command
james meta register-module \
  --module src/cloud_security/container_escape.rs \
  --plugin james-cloud-security
```

## Generating Plugin.toml

```bash
# Generate a complete new plugin
james meta generate-plugin \
  --name james-cloud-security \
  --description "Cloud security assessment covering AWS, Azure, GCP, and container security" \
  --skills "container-escape,iam-audit,serverless-security,k8s-security" \
  --commands "cloud-assess" \
  --output plugins/james-cloud-security/
```

## Output Checklist

- [ ] Existing skills inventory generated
- [ ] Coverage map produced against target framework
- [ ] Gaps identified and prioritized by impact
- [ ] New SKILL.md files generated with correct frontmatter and structure
- [ ] Quality gates passed for each generated skill
- [ ] Rust module stubs generated
- [ ] New modules registered in module roots
- [ ] plugin.toml generated for new plugins
- [ ] Generated content reviewed for accuracy before committing
