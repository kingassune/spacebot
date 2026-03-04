---
name: social-engineering
description: "Social engineering assessment covering phishing campaign setup and tracking, pretext scenario development, vishing script templates, physical access assessment, and ROE and ethical guidelines."
allowed-tools: ["shell", "file", "exec"]
---

# Social Engineering Assessment

You are conducting a social engineering assessment within a fully authorized engagement. Explicit written authorization covering social engineering tactics is mandatory. Do not target individuals beyond the defined scope.

## Rules of Engagement and Ethics

Before beginning any social engineering activity:

- Verify written authorization explicitly covers social engineering (phishing, vishing, physical access).
- Confirm the list of authorized target employees or roles.
- Identify individuals explicitly excluded from targeting (HR, legal, executives if requested).
- Establish emergency stop procedure — a single call to the CISO stops all activity immediately.
- Confirm data handling: no collection of real passwords or sensitive personal data.
- Document all lures and pretexts before deploying — changes require re-authorization.

## Phishing Campaign Setup and Tracking

Reference module: `src/pentest/social_engineering.rs — PhishingCampaign`

### Infrastructure Setup

```bash
# Register lookalike domain (requires ROE authorization)
# Example: target is acmecorp.com → lookalike: acmec0rp.com or acme-corp-it.com
# Set up MX, SPF, DKIM, DMARC records for deliverability

# Deploy Gophish campaign server
gophish &
# Access UI at https://localhost:3333

# Configure campaign:
# 1. Sending profile (SMTP server, from address)
# 2. Landing page (credential harvester or simulated malware download)
# 3. Email template (lure content)
# 4. Target group (authorized employee list)
```

### Phishing Lure Templates

**IT Helpdesk — Password Expiry:**

```
Subject: ACTION REQUIRED: Your password expires in 24 hours

Your corporate network password will expire in 24 hours.
Click here to reset it before losing access:
https://[lookalike-domain]/reset

IT Support Team
[Company Name]
```

**Finance — Invoice Approval:**

```
Subject: Urgent: Invoice #INV-2024-8821 requires your approval

Please review and approve the attached invoice at your earliest convenience.
Access the finance portal: https://[lookalike-domain]/invoices

Accounts Payable
```

### Campaign Tracking Metrics

Track these metrics in the Gophish dashboard:

| Metric | Description | Industry Baseline |
|---|---|---|
| Open rate | % who opened the email | 30–50% |
| Click rate | % who clicked the link | 15–30% |
| Submission rate | % who entered credentials | 5–15% |
| Report rate | % who reported to security | <5% (typical) |
| Time to click | Median time from send to click | Track for urgency analysis |

```bash
# Export campaign results
james security social-eng phishing-report --campaign-id $ID --format csv

# Identify high-risk departments
james security social-eng analyze --campaign-id $ID --by-department
```

## Pretext Scenario Development

A pretext is a fabricated identity or scenario used to establish trust with a target.

### Scenario Templates

**IT Support Technician:**
- Identity: Remote IT support contractor
- Trigger: "We're seeing unusual login attempts from your account"
- Goal: Convince target to install remote access software or provide credentials
- Props: Fake ticket number, knowledge of internal systems from OSINT

**New Employee Onboarding:**
- Identity: HR or IT onboarding specialist
- Trigger: "We need to complete your account setup before you lose access to the VPN"
- Goal: Obtain MFA codes or install "onboarding agent"
- Props: Target's name, start date, manager name (from LinkedIn OSINT)

**Vendor/Auditor:**
- Identity: External auditor or compliance vendor
- Trigger: "We're conducting the annual SOC 2 review and need access to verify controls"
- Goal: Physical access to server room or sensitive documentation
- Props: Printed fake badge, business cards, clipboard with checklist

### Pretext Quality Criteria

- [ ] OSINT performed to personalize scenario (name, role, manager, recent projects).
- [ ] Scenario creates urgency without being implausible.
- [ ] Pretext does not require target to do anything clearly policy-violating.
- [ ] Fallback story prepared if target becomes suspicious.
- [ ] Exit strategy defined (graceful conclusion of interaction).

## Vishing Script Templates

Vishing (voice phishing) is among the highest-success social engineering vectors.

### IT Support Vishing Script

```
[OPENER]
"Hi [Name], this is [Alex] from the IT Security team. 
I'm calling because our monitoring system flagged some unusual login activity on your account 
from an IP address in [foreign country]. 
Can I verify a few things to make sure your account hasn't been compromised?"

[BUILD RAPPORT — use OSINT detail]
"I can see you're in the [Department] team — you'd be using the [internal system name], right?"

[REQUEST]
"To lock out the attacker, I need to verify your identity. 
Can you confirm your employee ID and the last four digits of your corporate card?"

[MFA REQUEST — if applicable]
"Perfect. I'm sending a verification code to your phone right now. 
Once you receive it, can you read it to me so I can confirm it's going to your device?"

[CLOSE]
"Great, I've secured the account. You'll receive a confirmation email shortly. 
Have a great day!"
```

**Analyst notes:** The MFA code request is the most common corporate account takeover technique (T1621 — MFA Request Generation). Track which employees comply.

### Vishing Tracking

```bash
# Log vishing call outcome
james security social-eng vishing-log \
  --target-id $EMP_ID \
  --outcome "provided_mfa_code" \
  --pretext "it_support" \
  --duration 180s
```

## Physical Access Assessment

### Physical Intrusion Scenarios

**Tailgating:**
- Approach a secure door immediately behind an authorized employee.
- Carry props (large boxes, coffee tray) to trigger courtesy door-hold.
- Record whether challenged, ignored, or assisted.

**Lost Visitor Badge:**
- Present yourself as a visitor who has lost their badge.
- Assess whether reception issues a replacement without identity verification.

**Dumpster Diving:**
- Examine disposal bins for sensitive documents, media, or hardware.
- Document: printed credentials, org charts, network diagrams, unwiped drives.

### Physical Security Checklist

- [ ] Doors require active badge scan on both entry AND exit (anti-tailgating).
- [ ] Visitors escorted at all times — unescorted visitor challenged within 2 minutes.
- [ ] Server room requires dual authentication (badge + PIN).
- [ ] Clean desk policy enforced — sensitive documents locked when unattended.
- [ ] Printers clear their output trays and require authentication to retrieve print jobs.
- [ ] Sensitive waste shredded; bins not accessible from outside the secure perimeter.

## Output Checklist

- [ ] ROE verified and social engineering explicitly authorized
- [ ] Phishing campaign deployed with authorized target list
- [ ] Campaign metrics collected (open, click, submission, report rates)
- [ ] High-risk departments and individuals identified
- [ ] Pretext scenarios documented and authorized
- [ ] Vishing calls conducted and outcomes logged
- [ ] Physical access scenarios attempted and documented
- [ ] Training recommendations generated per finding
- [ ] Findings reported to CISO/security team with remediation guidance
