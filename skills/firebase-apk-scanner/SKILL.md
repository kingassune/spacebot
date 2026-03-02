---
name: firebase-apk-scanner
description: "James integration of Trail of Bits' Firebase/APK security scanner. Analyzes Android APKs and Firebase configurations for security misconfigurations."
---

# Firebase APK Scanner

You are analyzing an Android APK and its Firebase configuration for security misconfigurations.

## Workflow

### 1. APK Decompilation
```bash
# Decompile APK to smali + resources
apktool d target.apk -o decompiled/

# Decompile to Java (for easier reading)
jadx -d jadx_out/ target.apk

# Check APK metadata
aapt dump badging target.apk | grep -E "(package|uses-permission|application)"
```

### 2. Firebase Configuration Extraction
Firebase config is usually in one of:
- `res/values/strings.xml` — look for `google_app_id`, `firebase_database_url`, `google_api_key`.
- `google-services.json` — if included in assets.
- Hardcoded in Java/Kotlin source.

Extract:
```bash
grep -r "firebase" decompiled/res/ --include="*.xml" -i
grep -r "google_app_id\|firebase_database_url\|google_api_key" decompiled/ -r
grep -r "FirebaseApp\|FirebaseDatabase\|FirebaseAuth" jadx_out/ -r
```

### 3. Firebase Security Rule Checks
If you can access the Firebase project (via leaked credentials or public rules):
```bash
# Realtime Database: check if open to public read/write
curl "https://<project-id>.firebaseio.com/.json?shallow=true"
# Should return 401, not data

# Firestore: check rules
firebase firestore:rules
```

**Insecure rule patterns to flag**:
```javascript
// INSECURE: anyone can read/write everything
match /{document=**} {
  allow read, write: if true;
}
// INSECURE: anyone can read
allow read: if true;
```

### 4. Hardcoded Credentials and API Keys
Search for exposed secrets:
```bash
# Google API keys
grep -rE "AIza[0-9A-Za-z_-]{35}" jadx_out/ decompiled/
# Firebase project keys
grep -rE "[0-9]+-[0-9A-Za-z_-]+\.apps\.googleusercontent\.com" jadx_out/
# Generic secrets
grep -rE "(api_key|secret|password|token)\s*[=:]\s*['\"][^'\"]{8,}" jadx_out/ -i
```

### 5. Android Manifest Security Review
```bash
cat decompiled/AndroidManifest.xml
```

Check for:
- `android:debuggable="true"` — should not be in production.
- `android:allowBackup="true"` — allows ADB backup of sensitive data.
- `android:exported="true"` on Activities/Services/Providers without permission checks.
- `android:permission` missing on exported components.
- Overly broad permissions (`READ_CONTACTS`, `ACCESS_FINE_LOCATION`, etc.).

### 6. Network Security Configuration
```bash
cat decompiled/res/xml/network_security_config.xml
```
- `cleartextTrafficPermitted="true"` — allows HTTP traffic.
- `<trust-anchors>` including user certificates — MITM risk.
- Missing certificate pinning for sensitive endpoints.

### 7. Output Format
```
## Firebase/APK Security Report

APK: <filename>
Package: <package name>
Firebase Project: <project ID if found>

### Critical Findings
[CRITICAL] Open Firebase Database: <URL accessible without auth>
[CRITICAL] Hardcoded API Key: <key type> at <file:line>

### High Findings
[HIGH] debuggable=true in manifest
[HIGH] Exported component without permission: <component>

### Medium Findings
[MEDIUM] allowBackup=true
[MEDIUM] Cleartext traffic permitted

### Recommendations
<prioritized remediation steps>
```
