---
name: agentic-actions-auditor
description: "James integration of Trail of Bits' agentic system security review. Audits AI agent tool definitions, permission scopes, and trust boundaries."
---

# Agentic Actions Auditor

You are performing a security review of an AI agent system's tool definitions, permission scopes, and trust boundaries.

## Workflow

### 1. Inventory All Tools
- List every tool the agent can invoke.
- For each tool, document: name, description, input schema, output schema, and side effects.
- Identify tools that perform destructive or irreversible actions.

### 2. Permission Scope Analysis
For each tool, assess:
- **Minimum necessary privilege**: Does the tool request only the permissions it needs?
- **Scope creep**: Can the tool be used to access resources beyond its stated purpose?
- **Transitive permissions**: Does the tool call other tools or services that grant elevated access?

Flag over-privileged tools with:
```
[OVER-PRIVILEGE] Tool: <name>
Current scope: <what it can access>
Minimum required scope: <what it should access>
Risk: <what an attacker could do>
```

### 3. Prompt Injection Vectors
- Check if any tool accepts free-form string input that gets passed to an LLM or shell.
- Check for indirect prompt injection: tools that read external content (URLs, files, emails) that could contain adversarial instructions.
- Verify tool descriptions do not contain injection payloads that redirect agent behavior.

### 4. Trust Boundary Review
- Map data flows from untrusted sources (user input, external APIs, file system) into tool calls.
- Identify where tool outputs are trusted without validation.
- Check for confused deputy scenarios: agent acting on behalf of one principal but being manipulated by another.

### 5. Sandbox Escape Analysis
- Review tools that execute code or shell commands.
- Check for path traversal in file tools.
- Verify sandboxing boundaries (container, chroot, seccomp) are enforced.
- Check for SSRF in URL-fetching tools.

### 6. Output Format
Produce findings as:
```
[SEVERITY: Critical/High/Medium/Low]
Category: Over-Privilege / Prompt Injection / Trust Boundary / Sandbox Escape
Tool: <tool name>
Description: <what the issue is>
Attack Scenario: <how an attacker exploits this>
Recommendation: <how to fix>
```

### 7. Remediation Checklist
- [ ] All tools use minimum necessary permissions.
- [ ] No tool accepts unvalidated external content passed to an LLM.
- [ ] All shell/code execution tools are sandboxed.
- [ ] Trust boundaries are explicit and enforced.
- [ ] Destructive tools require explicit confirmation.
