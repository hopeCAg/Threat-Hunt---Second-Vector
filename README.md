# Threat-Hunt--Second-Vector
## Threat hunt scenario report




---

## Table of Contents

- [Overview](#overview)
- [Environment](#environment)
- [Executive Summary](#executive-summary)
- [Phase 00 — Incident Handoff](#phase-00--incident-handoff)
- [Phase 01 — Triage](#phase-01--triage)
- [Phase 02 — Session Scope](#phase-02--session-scope)
- [Phase 03 — Directory Recon](#phase-03--directory-recon)
- [Phase 04 — The Fraud](#phase-04--the-fraud)
- [Phase 05 — Persistence Hunt](#phase-05--persistence-hunt)
- [Phase 06 — Data Theft](#phase-06--data-theft)
- [Phase 07 — The Plant and the Trigger](#phase-07--the-plant-and-the-trigger)
- [Phase 08 — Correlation & Containment](#phase-08--correlation--containment)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Indicators of Compromise](#indicators-of-compromise)
- [Containment Actions](#containment-actions)
- [Recommendations](#recommendations)

---

## Overview

| Field | Detail |
|---|---|
| Operation | Second Vector: M365 Identity Compromise |
| Environment | Microsoft Defender XDR + Microsoft Sentinel |
| Workspace | lognpacific.org tenant |
| Investigation Window | 11 June 2026, 03:00 UTC — 13:00 UTC |
| Anchor Timestamp | 11 June 2026, 03:13 UTC |
| Scope | Cloud-only intrusion; identity, mail, files, Graph |
| Phases | 8 gated |
| Target Account | m.smith @lognpacific.org |

---

## Environment

The investigation took place across the **lognpacific.org** Microsoft 365 tenant, pivoting between Microsoft Defender XDR (incident triage, asset records, response actions) and a Microsoft Sentinel workspace. Schema discovery was performed using `take 1` and `getschema` queries at each new table. Evidence was traced across `SigninLogs`, `AADUserRiskEvents`, `MicrosoftGraphActivityLogs`, `EmailEvents`, `OfficeActivity`, and `CloudAppEvents`. There was no endpoint to image and no malware to reverse. Every action the attacker took was through identity, mail, files, and cloud services.

---

## Executive Summary

The Low-severity "anonymized IP" alert that night shift left in the queue was a full account compromise, not a false positive. Entra ID Protection's own model auto-dismissed five of six risk detections on this session as "ai-confirmed safe," leaving only one flagged. While the same session, riding a single replayed token that never completed live MFA, reached seven applications, exfiltrated three targeted files, built two Exchange inbox rules, stood up an independent Power Automate flow, and sent a fraudulent banking-details email to a finance colleague.

The recipient's reply six hours later was automatically intercepted and forwarded out of the tenant by infrastructure the attacker no longer needed to be signed in to operate. Conditional Access did not fail to stop this session — it never evaluated it. The authentication path (token replay, not a fresh interactive logon) sits outside the events CA inspects. Session and token lifecycle control is the actual control surface that mattered here.

---

## Phase 00 — Incident Handoff

### Q00 — Acceptance Gate

Night shift triaged Incident 87241: a Microsoft Entra ID Protection alert on a finance user, rated Low, flagged for a sign-in from an anonymous IP address on `m.smith`. They found nothing they could act on and left it in the queue. The hunt was picked up at day shift.

> **Finding:** Low-severity identity alerts on finance staff are exactly where a patient operator hides. The detection caught one sign-in. It did not ask what happened next.

---

## Phase 01 — Triage

### Q01: The Compromised Principal

**Question:** Open the incident. Who's the account this fired on. Full UPN.

| Field | Value |
|---|---|
| UPN | `m.smith@lognpacific.org` |
| Display Name | Mark Smith |
| Department | Finance |
| Table | `SigninLogs` |

**Answer: `m.smith@lognpacific.org`**

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where IPAddress == "103.69.224.136"
| project TimeGenerated, UserPrincipalName, UserDisplayName, AppDisplayName, IPAddress, ResultType
| take 1
```

> **Finding:** All 29 successful sign-ins from the flagged IP share a single UPN: `m.smith@lognpacific.org`. The dataset was consistent across every row with no ambiguity.

---

### Q02: The Flagged Source

**Question:** Same incident. What address did the flagged sign-in come from.

**Answer: `103.69.224.136`**

| Field | Value |
|---|---|
| IP Address | `103.69.224.136` |
| Geolocation | Amsterdam, NL |
| Classification | Anonymous IP (anonymized proxy / Tor exit node class) |

> **Finding:** This IP remained the pivot point for the entire hunt as it appears literally in 7 distinct in-scope log tables.

---

### Q03: The Client OS

**Question:** Read the user-agent on that sign-in. What client OS is it.

**Answer: `Linux`**

| Field | Value |
|---|---|
| Client OS | Linux |
| Source | UserAgent field on the flagged sign-in row |

> **Finding:** A Linux client OS on a finance user account accessing Microsoft 365 is anomalous. The tenant's normal baseline for this user showed no Linux sign-ins. Consistent with an attacker controlled machine rather than a legitimate work device.

---

### Q04: The Stored Detection Type

**Question:** The incident title is the friendly name. Pull the risk telemetry and give me the detection type as it's stored.

**Answer: `anonymizedIPAddress`**

| Field | Value |
|---|---|
| RiskEventType (as stored) | `anonymizedIPAddress` |
| Friendly name (incident title) | Anonymous IP address |
| Table | `AADUserRiskEvents` |
| Confirmed at | 03:35:27 UTC, IP 103.69.224.136 |

```kql
AADUserRiskEvents
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| project TimeGenerated, RiskEventType, RiskLevel, RiskState, RiskDetail, IpAddress
```

> **Finding:** The friendly incident title ("Anonymous IP address") is a display label. The stored enum value — `anonymizedIPAddress` — is what appears in the raw telemetry and is what analysts should reference when writing detection rules or cross-referencing with threat intel.

---

### Q05: Audit the Verdict

**Question:** This user has more than one risk detection. Aggregate them by state and tell me where most of them ended up.

**Answer: `dismissed`**

| RiskState | Count |
|---|---|
| **dismissed** | **5** |
| atRisk | 1 |

| Field | Detail |
|---|---|
| Total detections | 6 |
| Auto-dismissed by | `aiConfirmedSigninSafe` (machine learning model) |
| Surviving detection | 1 — RiskDetail: none, the one night shift saw |

> **Finding:** Five of six detections were auto-cleared by Entra ID Protection's own ML before a human ever saw them. The model classified them as safe. It was wrong. The tight timestamp clustering (three events within 11 seconds at 03:13, then a second cluster at 03:35–03:38) indicates multiple distinct token-evaluation events from the same session being independently scored.
---

### Q06: Live Exposure

**Question:** Check the asset record on the incident. What's the account's status.

**Answer: `Enabled`**

| Field | Value |
|---|---|
| Account status | Enabled |
| Source | Incident 87241 → Assets tab → Mark Smith entity panel |
| Console | security.microsoft.com (Defender XDR) |

> **Finding:** The account was active and enabled throughout the intrusion window. No prior lockout or disable action had been taken. The attacker operated against a fully live identity with no friction from the directory layer.

---

## Phase 02 — Session Scope

### Q07: How the Session Beat MFA

**Question:** Tenant enforces MFA. Their session ran anyway. Pull the successful sign-ins from that address and give me the field that explains it.

**Answer: `singleFactorAuthentication`**

| Field | Value |
|---|---|
| AuthenticationRequirement (all 29 successes) | `singleFactorAuthentication` |
| ConditionalAccessStatus (all 29 successes) | `notApplied` |
| Table | `SigninLogs` |

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| project TimeGenerated, AppDisplayName, AuthenticationRequirement, ConditionalAccessStatus, AuthenticationDetails
```

> **Finding:** Every successful sign-in from the flagged IP has `AuthenticationRequirement: singleFactorAuthentication` and `ConditionalAccessStatus: notApplied`. The tenant enforces MFA, but Conditional Access never evaluated these sign-ins. This is the signature of token replay. A stolen session credential asserting "authentication already happened" rather than a fresh interactive logon being challenged.

---

### Q08: The Control Surface That Let Them In

**Question:** Some attempts were stopped, one app let them in. Order the sign-ins from that address and name the app on the first success.

**Answer: `One Outlook Web`**

| Field | Value |
|---|---|
| First successful app | `One Outlook Web` |
| Timestamp | 03:45:11 UTC |
| AuthenticationRequirement | `singleFactorAuthentication` |

> **Finding:** The first successful entry point was the web Outlook client. Once that session was established, the attacker spread laterally to six more applications without re-authenticating  all by using the same token.

---

### Q09: Failed Attempts Before Entry

**Question:** Before the session took, the same address failed on credentials. How many times. Bad-password failures only.

**Answer: `2`**

| Field | Value |
|---|---|
| Bad-password failures (ResultType 50126) | 2 |
| Source IP | 103.69.224.136 |
| Table | `SigninLogs` |

> **Finding:** Two bad-password attempts preceded the successful session. This is not a spray pattern, it is a targeted attempt on a specific account where the attacker had partial credential knowledge, consistent with a credential-stuffing or purchased-credential scenario.

---

### Q10: Blast Radius of One Token

**Question:** That session reached multiple apps with no re-prompt. Count the distinct apps it got into.

**Answer: `7`**

| Application | Sign-in Count |
|---|---|
| One Outlook Web | 8 |
| OfficeHome | 5 |
| Microsoft Teams Web Client | 9 |
| Office 365 SharePoint Online | 2 |
| SharePoint Online Web Client Extensibility | 2 |
| Microsoft Flow Portal | 2 |
| App Service | 1 |

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| summarize count() by AppDisplayName
```

> **Finding:** A single replayed token provided access to seven distinct Microsoft 365 applications with zero MFA re-prompts. Of particular concern: `Microsoft Flow Portal` (automation; not a normal finance-user destination) and `App Service` (developer/deployment surface). Both are persistence-capable and do not belong in a finance account's normal access pattern.

---

### Q11: One Continuous Session

**Question:** I want the sign-in and the later activity tied to one session. Find the identifier that's in both and give it to me.

**Answer: `005d431a-380b-1f5e-e554-16d5010dc28e`**

| Field | Value |
|---|---|
| SessionId | `005d431a-380b-1f5e-e554-16d5010dc28e` |
| Shared across | SigninLogs (all 29 successes) and MicrosoftGraphActivityLogs |
| Table | `SigninLogs` → `SessionId` field |

> **Finding:** Every one of the 29 successful sign-ins from the attacker IP shares a single `SessionId`. This GUID is also embedded in the `SignInActivityId` field on the later Graph API calls  including the automated forward fired at 12:41:09 UTC, tying the initial logon and the later automation back to a single stolen session.

---

## Phase 03 — Directory Recon

### Q12: MFA-Posture Profiling

**Question:** Early in the session there's a Graph reports call profiling this account's auth posture. Name the resource they queried.

**Answer: `userRegistrationDetails`**

| Field | Value |
|---|---|
| Resource | `userRegistrationDetails` |
| Full URI | `https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?$filter=userPrincipalName eq 'm.smith@lognpacific.org' and isMfaCapable eq true` |
| Times called | 3 (03:09:37, 03:10:07, 03:12:26 UTC) |
| Status | 200 (success each time) |
| Table | `MicrosoftGraphActivityLogs` |

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where IPAddress == "103.69.224.136"
| where RequestUri contains "userRegistrationDetails"
| project TimeGenerated, RequestMethod, RequestUri, ResponseStatusCode
```

> **Finding:** The attacker queried the victim's MFA registration status three times in three minutes at the very start of the session. This is deliberate pre-operation reconnaissance confirming whether the account has MFA registered and what methods are in use before deciding how to proceed. The triple call pattern suggests polling, not a one-off lookup.

---

### Q13: Group Enumeration

**Question:** There's a Graph call enumerating the victim's own group membership. Give me the request path.

**Answer: `/v1.0/me/memberOf`**

| Field | Value |
|---|---|
| Request path | `/v1.0/me/memberOf` |
| Timestamp | 03:45:42 UTC |
| Status | 200 |
| Table | `MicrosoftGraphActivityLogs` |

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where IPAddress == "103.69.224.136"
| where RequestUri contains "/me/memberOf"
| project TimeGenerated, RequestMethod, RequestUri, ResponseStatusCode
```

> **Finding:** The `/me/memberOf` call returns the full list of security groups, Microsoft 365 groups, and distribution lists the signed-in token's user belongs to. For an attacker, this maps the blast radius of the compromised identity. Shared mailboxes, SharePoint sites, and privileged groups are now reachable. The timing (immediately after the failed MFA push at 03:44, right before the pivot into mail and file access) confirms this was scoping what the existing token could reach before deciding what to do with it.

---

## Phase 04 — The Fraud

### Q14: The Fraudulent Request

**Question:** From the mailbox they sent an internal email to redirect a payment. Find it. Subject line, exact.

**Answer: `Updated Banking Details - Pacific IT Monthly`**

| Field | Value |
|---|---|
| Subject | `Updated Banking Details - Pacific IT Monthly` |
| Sender | `m.smith@lognpacific.org` |
| Recipient | `j.reynolds@lognpacific.org` |
| Timestamp | 04:13:54 UTC |
| Direction | Intra-org |
| Table | `EmailEvents` |

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where SenderFromAddress == "m.smith@lognpacific.org"
| where EmailDirection == "Intraorg"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction
```

> **Finding:** The fraud email was sent approximately 45 minutes after the file downloads that provided the supporting detail (`Vendor-Banking-Details.txt`, `Book.xlsx`). The sequencing is deliberate: exfiltrate the data needed to make the request credible, then send the request. The subject line mimics a routine vendor payment update, exactly the kind of email a finance team processes without escalating.

---

### Q15: The Thread They Mined

**Question:** During recon they read an internal thread about the payment-approval process to price the fraud. It predates the intrusion by months. Find that thread and give me its subject line, exact.

**Answer: `Q1 Vendor Payment Schedule - Review Required`**

| Field | Value |
|---|---|
| Subject | `Q1 Vendor Payment Schedule - Review Required` |
| Age | Predates the intrusion by months |
| Table | `EmailEvents` |

> **Finding:** The attacker accessed historical mail threads to understand how the victim organization handles vendor payments like approval thresholds, who signs off, which vendors are routine. This pre-intrusion mail mining is what made the fraudulent request credible and sized correctly. Operators who do this kind of research are not opportunistic; they are methodical.

---

### Q16: The Fraud Target

**Question:** Who received the fraudulent request. Full UPN.

**Answer: `j.reynolds@lognpacific.org`**

| Field | Value |
|---|---|
| UPN | `j.reynolds@lognpacific.org` |
| Role | Finance (payment processing) |
| Also flagged | Risk event same day from IP 185.130.187.4 — remediated via MFA |

> **Finding:** Jay Reynolds was both the social-engineering target for the fraud and himself a risk-flagged identity on the same day. His own sign-in anomaly (different IP, different geo, same date) was remediated via risk-based MFA challenge, suggesting he may have been targeted in parallel, or that the attacker probed his account as a secondary path.

---

### Q17: Second Channel Reinforcement

**Question:** They pushed the same request through a second service, not just mail. Name it.

**Answer: `Microsoft Teams`**

| Field | Value |
|---|---|
| Second channel | Microsoft Teams |
| Purpose | Reinforce the fraudulent banking-details request via a second trusted channel |

> **Finding:** Sending the same fraud request through both email and Teams is a deliberate social-engineering technique by creating the appearance of urgency and legitimacy. A single-channel request is easier to dismiss but two channels from the same trusted colleague make it harder to question without appearing obstructive.

---

## Phase 05 — Persistence Hunt

### Q18: The Concealment Rule

**Question:** They changed something on the mailbox so a conversation wouldn't be seen. Find the rule and give me its name.

**Answer: `Invoice Processing`**

| Field | Value |
|---|---|
| Rule name | `Invoice Processing` |
| Created | 03:28:22 UTC |
| Source IP | 103.69.224.136 |
| Action | MoveToFolder: Archive |
| Filter | From: j.reynolds@lognpacific.org |
| StopProcessingRules | True |
| Table | `OfficeActivity` (Operation: New-InboxRule) |

```kql
OfficeActivity
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where Operation == "New-InboxRule"
| where ClientIP contains "103.69.224.136"
| project TimeGenerated, Operation, Parameters, ClientIP, MailboxOwnerUPN
```

> **Finding:** The rule was named to look entirely mundane. "Invoice Processing" is exactly the kind of rule a finance employee might create legitimately. It silently moves any reply from Reynolds to Archive, with `StopProcessingRules: True` ensuring no other rule processes that mail. The real Mark Smith, signing in days later, has no reason to check the Archive folder for a conversation he doesn't know happened.

---

### Q19: Where the Hidden Mail Goes

**Question:** That rule doesn't delete the mail it catches, it moves it to a normal-looking folder. Tell me why an attacker moves instead of deletes, and what the choice of an ordinary folder buys them.

**Answer: Evading Suspicion**

Moving to Archive rather than deleting is a deliberate evasion choice. A deletion can trigger mail-flow anomaly detection, empty trash analysis, or raise questions if the legitimate account owner notices messages are missing. An Archive move leaves the message present and puts it somewhere the account owner is unlikely to look during normal use. If the attacker's presence is suspected and a cursory review is done, the inbox and sent items look clean. The conversation is still there if someone goes looking, but it will not surface without deliberate forensic review of the Archive folder.

> **Finding:** The choice of a real, normal-looking folder over deletion reflects operational patience. The attacker was optimizing for not being noticed during the fraud window, not for permanent concealment. The message surviving in Archive is actually useful to the analyst: it becomes evidence.

---

### Q20: The Exfiltration Rule

**Question:** There's a second rule that sends mail outside the org. Give me the destination address.

**Answer: `merovingian1337@proton.me`**

| Field | Value |
|---|---|
| Rule name | `Backup Copy` |
| Created | 03:32:31 UTC |
| Source IP | 103.69.224.136 |
| Action | ForwardTo: merovingian1337@proton.me |
| Filter | From: j.reynolds@lognpacific.org |
| StopProcessingRules | True |
| External destination | Proton Mail (end-to-end encrypted, anonymous) |

> **Finding:** The destination is a Proton Mail address, a deliberate choice of an encrypted, privacy-focused service with no corporate logging or subpoena-accessible records. The attacker receives a copy of every Reynolds reply at an address with zero connection to the tenant, with no need to ever sign back into the compromised account to read it.

---

### Q21: Who Both Rules Target

**Question:** Both mailbox rules act on inbound mail from one person. Tell me why the persistence rules single out THEIR mail specifically. What conversation are the rules built to stop the victim from seeing.

**Answer: Suppressing target replies and warnings**

Both rules filter on `From: j.reynolds@lognpacific.org` , which acts on mail *coming back in* from the fraud target, not on outbound mail. The rules are built around one specific conversation thread: Reynolds' reply to the "Updated Banking Details" email. That reply, whether it's a confirmation, a question, or a pushback, is information that would have unravel the fraud if the real Mark Smith saw it. `Invoice Processing` hides it from Smith (Archive, no notification). `Backup Copy` simultaneously sends it to the attacker. Two rules, two sides of one conversation, one of which the victim is now blind to.

> **Finding:** This is textbook **MITRE T1564.008 — Email Hiding Rules**. The surgical precision (both rules targeting exactly one sender, not broad inbox traffic) confirms the attacker understood the specific conversation thread they needed to control.

---

## Phase 06 — Data Theft

### Q22: The Exfil Operation

**Question:** This user opens files all day, that's their job and it's noise. One operation in the attacker's session is them taking copies OUT, not reading in place. Name that operation, and tell me how you separated it from the user's ordinary file activity.

**Answer: `FileDownloaded` — distinguished by population contrast against m.smith's baseline**

| Field | Value |
|---|---|
| Operation | `FileDownloaded` |
| Table | `CloudAppEvents` |
| Attacker IP rows | 27 (includes 3 FileDownloaded) |
| Baseline rows (other IPs) | 38 (zero FileDownloaded) |

The separation method: splitting `CloudAppEvents` for Mark Smith by IP address reveals a clean population contrast. In his 38 baseline rows (normal working IPs), `FileDownloaded` never appears once. His ordinary pattern is `FileModified`, `FileUploaded`, `MailItemsAccessed` the logs of someone editing and uploading their own work. `FileDownloaded` appears exclusively in the 27 attacker-IP rows, making it a zero-to-three contrast between the two populations and an unambiguous signal.

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where AccountDisplayName == "Mark Smith"
| summarize count() by ActionType, IPAddress
| sort by IPAddress asc
```

> **Finding:** The contrast between populations is what separates "this user's job" from "this session's operation." Noise removal by IP before looking at ActionType is the technique. Reference: **MITRE T1530 — Data from Cloud Storage**.

---

### Q23: Volume Taken

**Question:** Count the files they pulled in the session. Then tell me what that number says about the theft.

**Answer: `3` 

| File | Timestamp |
|---|---|
| `Vendor-Banking-Details.txt` | 03:37:22 UTC |
| `VPN-Access-Credentials.txt` | 03:37:23 UTC |
| `Book.xlsx` | 03:37:23 UTC |

Three files, pulled in a ~1-second window, after a browse of the folder structure. A smash-and-grab against an account with this level of access. OneDrive, SharePoint, Teams, Flow all reachable in the same session would look like dozens or hundreds of downloads, or a sync/bulk export. Three is not a smash-and-grab. It is the count of someone who already knew what they wanted before they opened the folder. Each file maps directly to a later action: banking details → fraud email, VPN credentials → independent foothold, spreadsheet → supporting ledger data.

> **Finding:** Restraint is itself a signal. Octo Tempest-pattern operators do not bulk-exfiltrate and trip DLP. They take the minimum needed to serve the fraud and nothing more.

---

### Q24: The Credential Document

**Question:** One of those files widens this past the mailbox. Name it.

**Answer: `VPN-Access-Credentials.txt`**

| Field | Value |
|---|---|
| Filename | `VPN-Access-Credentials.txt` |
| Significance | Provides a network-level foothold independent of the Entra session |

> **Finding:** This file widens the scope of the compromise beyond the Microsoft 365 identity layer. VPN credentials give the attacker a path into the organization's network that does not depend on m.smith's Entra token at all — a second, parallel persistence path that would survive even a full Entra session revocation and password reset.

---

### Q25: The Vault Pointer

**Question:** They opened a file that points to a credential store, didn't download it. Look at access. Name the file.

**Answer: `yomark.pdf`**

| Field | Value |
|---|---|
| Filename | `yomark.pdf` |
| ActionType | `FileAccessed` (not FileDownloaded) |
| Timestamp | 03:39:12 UTC |
| Table | `CloudAppEvents` |

> **Finding:** A PDF opened in place but not downloaded points to a document read for its *contents* (a URL, a password manager reference, a credential store location) rather than taken as a payload. Reference: **MITRE T1555 — Credentials from Password Stores**. The file was accessed immediately after the three targeted downloads, consistent with the attacker following a breadcrumb toward a credential repository.

---

## Phase 07 — The Plant and the Trigger

### Q26: Disprove the Innocent Explanation

**Question:** Call's coming in that this is just the user on a VPN. Read the authentication detail across the session and count how many times MFA was actually satisfied.

**Answer: `0`**

| Field | Value |
|---|---|
| Live MFA completions | 0 |
| AuthenticationMethod across all 29 successes | `Previously satisfied` |
| AuthenticationStepResultDetail | `MFA requirement satisfied by claim in the token` / `First factor requirement satisfied by claim in the token` |
| Only live MFA invocation | 03:44:26 UTC — **failed** (error 50074, push not completed) |

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| mv-expand AuthDetails = parse_json(AuthenticationDetails)
| project TimeGenerated, AppDisplayName,
    AuthMethod = AuthDetails.authenticationMethod,
    StepDetail = AuthDetails.authenticationStepResultDetail
```

> **Finding:** Zero. A legitimate user on a VPN still authenticates. Their device presents a token that was itself issued after a real MFA completion. What is happening here is different: the session is replaying pre-existing token claims, asserting "MFA was satisfied" as a historical fact baked into the token, without anyone (attacker or user) ever completing an MFA step during this window. The "VPN" explanation does not survive contact with this field.

---

### Q27: Catch the Plant

**Question:** Walk the apps that session touched. One of them is where automation gets built, not where a finance user works. Name it.

**Answer: `Microsoft Flow Portal`**

| Field | Value |
|---|---|
| Application | `Microsoft Flow Portal` |
| Sign-ins | 03:46:32 and 03:48:11 UTC (both successful) |
| Why anomalous | Finance users do not routinely build Power Automate flows |
| Relevance | Platform for building event-triggered automation which supports T1546 persistence |

> **Finding:** Five of the seven apps are the normal daily surfaces of a finance employee (Outlook, Teams, SharePoint, OfficeHome). Flow Portal is not. The attacker signed in twice, with a 99-second gap which is consistent with building or configuring something rather than just browsing. Reference: **MITRE T1546 — Event Triggered Execution**.

---

### Q28: The Cause Behind the Forward

**Question:** The forward's in the mail logs. No rule made it, user wasn't online. Find the table that records what actually fired it.

**Answer: `MicrosoftGraphActivityLogs`**

| Field | Value |
|---|---|
| Table | `MicrosoftGraphActivityLogs` |
| Why not OfficeActivity | Covers Exchange admin operations — inbox rule creation already confirmed there; the forward was not a rule-executed event |
| Why not EmailEvents | Shows the result (the forwarded message) not the mechanism (the API call that fired it) |
| Why MicrosoftGraphActivityLogs | Records every raw Graph API call, the layer at which a Power Automate flow executes a `forward` action programmatically |

> **Finding:** The table that records the mechanism (but not the result)  of a programmatic mail action is `MicrosoftGraphActivityLogs`. Reference: **MITRE T1020 — Automated Exfiltration**.

---

### Q29: Prove It With the Sequence

**Question:** That forward is recorded twice, an API call and a mail event. Put them in order and tell me which came first.

**Answer: The Graph call came first**

| Record | Table | Timestamp (UTC) |
|---|---|---|
| `POST /v1.0/me/messages/{id}/forward` — Status 202 | `MicrosoftGraphActivityLogs` | **12:41:09.129** |
| `m.smith → merovingian1337@proton.me` "FW: Updated Banking Details..." Outbound Delivered | `EmailEvents` | **12:41:14.000** |

**Gap: ~5 seconds. Graph call precedes the mail event.**

> **Finding:** A human manually forwarding mail in Outlook generates the mail event simultaneously with their own action meaning there is no separate, preceding API call. The 5-second lead of the Graph call over the mail event is the signature of a programmatic actor calling the Graph API against the message object, with the forwarded message only existing as a result of that API call completing. This proves the forward was machine-executed, not human-composed. Reference: **MITRE T1020 — Automated Exfiltration**.

---

## Phase 08 — Correlation & Containment

### Q30: The Automation Source IP

**Question:** That forward didn't come from the attacker's address or the user's machine. Where did it come from.

**Answer: `20.150.129.194`**

| Field | Value |
|---|---|
| IP on the Graph forward call | `20.150.129.194` |
| Attacker's IP | `103.69.224.136` |
| m.smith's normal IPs | Neither |
| Owner | Microsoft Azure / Power Automate execution infrastructure |

> **Finding:** The forward call originates from Microsoft's own cloud infrastructure and not from any human IP. This is the key characteristic of automation-layer persistence: once the flow is built, it executes from Microsoft's servers, making IP-based detection of the attacker's ongoing activity impossible. The attacker no longer needs to be online.

---

### Q31: The Automation Identity

**Question:** The forward call is signed by an app. Give me the app id off that record.

**Answer: `7ab7862c-4c57-491e-8a45-d52a7e023983`**

| Field | Value |
|---|---|
| AppId | `7ab7862c-4c57-491e-8a45-d52a7e023983` |
| UserAgent on the call | `azure-logic-apps/1.0 ... microsoft-flow/1.0` |
| Scopes | `Mail.Send`, `Mail.ReadWrite`, `Mail.ReadWrite.Shared` |
| SessionId | `005d431a-380b-1f5e-e554-16d5010dc28e` (same GUID as the original compromise) |

> **Finding:** The AppId is a Microsoft first-party identifier for the Power Automate / Microsoft Flow service. The `SessionId` on the forward call matches the original hijacked session GUID identified in Phase 02; tying the initial token theft directly to the automation layer built under that same identity.

---

### Q32: Name the Abused Service

**Question:** The app they signed into, the call that fired, the app id behind it. Name the service they used to forward the mail.

**Answer: `Power Automate`**

| Signal | Value |
|---|---|
| App signed into | `Microsoft Flow Portal` (03:46:32 / 03:48:11 UTC) |
| API call that fired | `POST /v1.0/me/messages/{id}/forward` |
| AppId | `7ab7862c-4c57-491e-8a45-d52a7e023983` |
| UserAgent | `azure-logic-apps/1.0 ... microsoft-flow/1.0` |
| Service | **Power Automate** (Microsoft Flow) |

> **Finding:** The attacker used Microsoft's own Power Automate service, a first-party, fully trusted M365 application, to execute the forward. This is the Octo Tempest pattern: building persistence inside a trusted automation platform rather than an external C2, so the forwarding activity originates from Microsoft infrastructure and carries no attacker IP. Reference: Microsoft Threat Intelligence — Octo Tempest profile.

---

### Q33: One Actor, Every Source

**Question:** One address runs through the whole case. Count how many distinct log sources it appears in.

**Answer: `7`**

| Table | Field | Evidence |
|---|---|---|
| `SigninLogs` | `IPAddress` | All 29 successful sign-ins |
| `AADUserRiskEvents` | `IpAddress` | All 6 risk detections |
| `MicrosoftGraphActivityLogs` | `IPAddress` | All Graph recon and session calls |
| `OfficeActivity` | `ClientIP` | Both New-InboxRule events |
| `CloudAppEvents` | `IPAddress` | All file access and download events |
| `EmailEvents` | `SenderIPv4` | The fraud send at 04:13:54 UTC |
| *(7th per data dictionary)* | *(field)* | *(in-scope table confirmed in workspace)* |

> **Finding:** A single IP appearing literally across this many distinct log sources is the clearest possible indicator of a single, sustained attacker session. The breadth of coverage reflects the full cloud attack surface: identity layer, Graph API, Exchange, file storage, and mail transit all logged the same address independently.

---

### Q34: Containment Ordering

**Question:** Before you delete a rule or a flow, one action comes first or they're straight back in. What is it.

**Answer: Revoke the user's refresh tokens**

| Step | Action | Why |
|---|---|---|
| **1 — must be first** | Revoke sessions / refresh tokens | Invalidates the hijacked token. Without this, a live session can simply rebuild any deleted rule or flow within seconds |
| 2 | Reset m.smith's password | Closes the path for a new token being issued against the old credential. A reset alone is insufficient — see Q37 |
| 3 | Delete inbox rules | Safe to remove once the session is dead |
| 4 | Delete the Power Automate flow | Safe to remove once the session is dead |

> **Finding:** Every action in this session rode the same hijacked token (`SessionId: 005d431a-380b-1f5e-e554-16d5010dc28e`). Cleaning up persistence mechanisms while that token remains valid is cosmetic since the operator can reconstruct the entire setup in minutes. Reference: Microsoft Learn — Revoke user access in an emergency in Microsoft Entra ID.

---

### Q35 — Where the Flow Is Removed

**Question:** That flow can't be removed from Sentinel or the Exchange rules. Where do you go to find and delete it.

**Answer: `Power Platform admin center`**

| Field | Value |
|---|---|
| Console | Power Platform admin center |
| URL | admin.powerautomate.microsoft.com / admin.powerplatform.microsoft.com |
| Path | Environment → Flows → filter by owner m.smith@lognpacific.org |
| Action | Delete (not disable. a disabled flow can be re-enabled if the credential becomes live) |

> **Finding:** The flow is not an Exchange object and is not visible in Sentinel. It lives entirely in Power Automate's own management plane. An analyst checking `Get-InboxRule` or reviewing Sentinel alerts would walk past it entirely. This governance gap in which two admin teams (Exchange/Security and Power Platform) own overlapping surfaces is a structural problem worth raising beyond this individual incident.

---

### Q36: The Control That Never Fired

**Question:** A foreign single-factor sign-in should have been the easiest thing in the world for Conditional Access to stop. What did CA actually do, and why did that let them in.

**Answer: Conditional Access wasn't applied — the session authenticated via token replay, outside the evaluation path CA inspects**

| Field | Value |
|---|---|
| ConditionalAccessStatus (all 29 successes) | `notApplied` |
| Meaning | CA was never invoked: not evaluated-and-passed, not evaluated-and-failed |

`notApplied` is not a CA decision — it is the absence of a CA decision. The session authenticated via a replayed token claiming prior satisfaction of authentication requirements. Conditional Access evaluates fresh, interactive sign-in events. A token-replay path that asserts "authentication already happened" does not re-trigger CA's evaluation pipeline. There was no policy to fail as there was no policy evaluation.

> **Finding:** This is **MITRE T1078.004 — Valid Accounts: Cloud Accounts**. Tightening CA policy logic will not close this gap. The access rode in through a channel that bypasses CA entirely, not through a channel that defeated it. The fix is session and token lifecycle control (revocation), not stricter policy conditions.

---

### Q37: Why Revoke Before Reset

**Question:** Someone on the bridge wants to reset m.smith's password and call it done. You know better. Tell me why a password reset alone doesn't lock this attacker out, and what action has to come first.

**Answer: The refresh token survives a password reset — revoking sessions is what actually kills it**

| | |
|---|---|
| What a password reset does | Blocks new sign-ins on the old credential |
| What a password reset does NOT do | Invalidate already-issued refresh tokens |
| What the attacker holds | A valid refresh token issued before the reset |
| What that means | The attacker's session continues working after the reset — they never typed the password in the first place |
| What kills it | Session revocation (`Revoke sessions` in Entra ID / `Confirm user compromised` in Defender XDR) |

Every successful sign-in in this session carried `authenticationMethod: "Previously satisfied"` — the attacker was never authenticating with a password. Reset it, and they do not notice. Their token remains valid, the inbox rules stay live, the Power Automate flow keeps forwarding Reynolds' replies, and nothing about the operator's position changes. Session revocation is the only action that actually invalidates what they are holding.

> **Finding:** Password reset without session revocation is theater. It satisfies the question "did we do something" while leaving the actual access entirely intact. Revoke first, reset second. Reference: Microsoft Learn — Revoke user access in an emergency in Microsoft Entra ID.

---

## MITRE ATT&CK Mapping

| Technique ID | Technique | Tactic | Observed Behavior |
|---|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | Token replay — stolen session credential reused across 29 sign-ins |
| T1110.001 | Brute Force: Password Guessing | Credential Access | 2 bad-password attempts preceding session establishment |
| T1538 | Cloud Service Dashboard | Discovery | Graph recon — directory enumeration, MFA posture profiling |
| T1087.004 | Account Discovery: Cloud Account | Discovery | `/v1.0/me/memberOf` — group membership enumeration |
| T1530 | Data from Cloud Storage | Collection | Targeted file access and download from OneDrive (3 files) |
| T1567 | Exfiltration Over Web Service | Exfiltration | `FileDownloaded` via OneDrive/SharePoint |
| T1555 | Credentials from Password Stores | Credential Access | `yomark.pdf` opened — points to credential store |
| T1566.002 | Phishing: Spearphishing | Initial Access | Fraudulent banking-details email to j.reynolds |
| T1534 | Internal Spearphishing | Lateral Movement | Teams message reinforcing the fraud request |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Defense Evasion | Two inbox rules controlling both sides of the fraud conversation |
| T1546 | Event Triggered Execution | Persistence | Power Automate flow built to trigger on inbound mail from Reynolds |
| T1020 | Automated Exfiltration | Exfiltration | Flow-driven forward to external Proton address — no live session required |

---

## Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| Account | `m.smith@lognpacific.org` | Compromised identity |
| IP Address | `103.69.224.136` | Attacker session IP — Amsterdam, NL |
| IP Address | `20.150.129.194` | Power Automate execution infrastructure — source of automated forward |
| Session ID | `005d431a-380b-1f5e-e554-16d5010dc28e` | Hijacked session GUID — ties all activity from sign-in through automation |
| AppId | `7ab7862c-4c57-491e-8a45-d52a7e023983` | Microsoft Flow / Power Automate — app that fired the forward call |
| Workflow ID | `89a996b4a5ce4cde938ab27e21018d0f` | Power Automate flow built during the attacker's Flow Portal session |
| Email address | `merovingian1337@proton.me` | External exfiltration destination |
| Inbox Rule | `Invoice Processing` | Hides Reynolds' replies in Archive — concealment mechanism |
| Inbox Rule | `Backup Copy` | Forwards Reynolds' mail to proton.me — exfiltration mechanism |
| File | `Vendor-Banking-Details.txt` | Exfiltrated from OneDrive — used to construct the fraud email |
| File | `VPN-Access-Credentials.txt` | Exfiltrated from OneDrive — independent network-level foothold |
| File | `Book.xlsx` | Exfiltrated from OneDrive — supporting ledger/contact data |
| File | `yomark.pdf` | Accessed in place — points to credential store (T1555) |
| Email subject | `Updated Banking Details - Pacific IT Monthly` | Fraudulent payment-redirect email |
| Secondary account | `j.reynolds@lognpacific.org` | Fraud target — risk event same day from 185.130.187.4 |
| Secondary account | `mohammed_admin@lognpacific.com` | Risk event same day — remediated via MFA |

---

## Containment Actions

| Priority | Action | Rationale |
|---|---|---|
| **Critical** | Revoke m.smith's sessions/refresh tokens immediately | Must happen first — cleanup before revocation can be rebuilt by the live session |
| **Critical** | Reset m.smith's password (after revocation) | Prevents a new token being issued against the old credential |
| **Critical** | Delete inbox rules `Invoice Processing` and `Backup Copy` | Stops concealment and exfiltration at the Exchange layer |
| **Critical** | Delete the Power Automate flow in Power Platform admin center | The flow survives if only the inbox rules are removed — must be killed separately |
| **High** | Notify Finance and Jay Reynolds via out-of-band channel | The compromised mailbox cannot be trusted for notification |
| **High** | Hold any pending payments to Pacific IT pending verification | Determine whether a fraudulent payment was actually redirected |
| **High** | Review j.reynolds and mohammed_admin risk events independently | Both show same-day risk detections — confirm neither was independently compromised |
| **Medium** | Audit the Power Automate flow's run history before deletion | Establish how many of Reynolds' replies were exfiltrated |
| **Medium** | Review VPN access logs for m.smith credentials post-11 June | `VPN-Access-Credentials.txt` was exfiltrated — assume those credentials are burned |
| **Medium** | Check for additional flows under m.smith in Power Automate | Confirm there is no second flow before closing the incident |

---

## Recommendations

| Priority | Recommendation | Context |
|---|---|---|
| **Critical** | Implement Continuous Access Evaluation (CAE) | CAE propagates session revocation near-instantly to M365 services |
| **Critical** | Close the Conditional Access gap for token-replay paths | CA evaluated zero of 29 sign-ins — `notApplied` at this volume is a coverage gap, not a policy failure |
| **High** | Implement Power Automate governance: DLP policies and flow creation approval gates | A standard finance account created a flow with `Mail.Send`/`Mail.ReadWrite.Shared` scopes with no approval gate |
| **High** | Alert on `New-InboxRule` operations creating external forward rules | The auto-alert fired but was sent by email to a shared inbox — not actioned. The signal existed; the workflow failed |
| **High** | Alert on Flow Portal or App Service sign-ins for non-developer accounts | Finance users authenticating to automation platforms is an anomaly signal that should generate a SIEM alert |
| **Medium** | Tune Entra ID Protection auto-dismissal for finance accounts | Five of six detections were auto-cleared during an active compromise — finance accounts need a lower threshold |
| **Medium** | Monitor inbox rules forwarding to external consumer mail domains | Proton Mail, Gmail as forward destinations is a BEC signal monitorable via `OfficeActivity` continuously |
| **Low** | Require MFA step-up for high-risk operations | Token replay worked because no step required a fresh factor — step-up auth on file downloads and rule creation would have broken the session |

---

*Threat Hunt Report — Operation Second Vector: M365 Identity Compromise, BEC & Silent Exfiltration*  
*Conducted in Microsoft Defender XDR + Microsoft Sentinel
