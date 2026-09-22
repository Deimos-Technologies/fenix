# FENIX / AnonNet — Network Document
**How the network works | Rules | Administration powers | Legal-risk scenarios | User protection | ToS**
*v1.0 — 2026-07-19 (draft; not legal advice)*

## 1. Introduction and document status
This document describes how the Fenix Network operates, its Rules, the closed catalogue of Administration powers, legal-risk scenarios and the mechanisms protecting Users. It forms an integral supplement to the Terms of Service (ToS) v1.0.
This is an informational working draft. It is not legal advice for any party. Publication and rollout should be preceded by review with counsel familiar with the Network's target jurisdictions.
In case of divergence, the Polish version prevails; the English and Russian versions are informational.

> **IN PLAIN TERMS: **This is the map of the whole network written in two voices: legal and human. Read both.

## 2. How the Fenix Network works
- Peer-to-peer network with no central server: content and accounts exist solely on Users' devices. No Administration infrastructure stores user data — there is nothing to seize or hand over.
- Identity = Wallet Address + Username + UID + Rank; public registry on the FNX blockchain, without personal data.
- End-to-end encrypted messaging; private keys never leave the device; per-message one-time keys (forward secrecy).
- Transport: proprietary protocol with a camouflage layer (camo) hindering traffic identification (DPI); onion routing hop-by-hop — no relay knows sender, recipient and content at once.
- FNX economy: 0.001% burn fee + 0.055% owner treasury; CPU proof-of-work mining coupled with hosting of data fragments (proof-of-storage).
- Defense: AI-Sentry operated exclusively by the Administration (D17); verdicts public with reasoning; Proof-of-Uptime reputation (30 days = VOTER status and vote).
- Ranks: voluntary FNX payments for perks (hosting, QoS, cosmetics) — NEVER in exchange for power, votes or others' data.

> **IN PLAIN TERMS: **No company server — nothing to seize. Only sender and recipient can read a letter. A rank buys comfort, not power.

## 3. Network Rules
3.1 Permitted: private and group communication; hosting lawful content; FNX mining; voting (VOTER); purchasing ranks and perks; setting one's own telemetry slider.
3.2 Prohibited (grounds for automatic ban):
- ROUTE_LEAKAGE — routing Fenix traffic through unsecured proxies / extracting data out of the Network;
- PROTO_FLOOD — volumetric floods of the protocol; INVALIDTAG_STORM — mass forged packets;
- SYBIL_RING — rings of fake identities; STORAGE_FRAUD — proof-of-storage fraud;
- MSG_SPAM — bulk sending (metadata-pattern analysis, NEVER content); CAMO_VIOLATION — traffic without the camouflage layer;
- DOXXING — publishing third parties' personal data; plus all unlawful content and conduct (sec. 5).
3.3 Enforcement: automatic, with reasoning. Content is not scanned (technically impossible under E2E); security patterns and a warned-hash registry are enforced — consensus suspends distribution of a flagged fragment without reading its content.

> **IN PLAIN TERMS: **Privacy — always. But attacking the network, defrauding the protocol and unlawful dealing end in a ban — with its name and reason, publicly.

## 4. What the Administration may do (closed catalogue)
4.1 The Administration MAY only:
- sign and publish Software updates (owner key, D14);
- operate the AI-Sentry defense system (D17) and issue ban verdicts with reasoning (D18);
- accept or reject ban buyouts — decision final;
- collect the 0.055% protocol fee to the owner treasury (D15) and manage the treasury;
- maintain seed nodes, bootstrap and the official announcement channel;
- amend the Terms with at least 14 days' notice;
- suspend distribution of hash-flagged fragments, solely via consensus.
4.2 The Administration expressly CANNOT (design undertakings):
- read message content or activity logs (they do not exist);
- recover a User's lost key or password (D9);
- deanonymize Users by systemic means;
- reverse on-chain transactions or alter balances outside consensus rules;
- disclose data it does not possess — to any parties (ToS sec. 4).

> **IN PLAIN TERMS: **Admin power ends at engine maintenance. It cannot read mail, does not know passwords, holds no keys — so there is nothing to hand over.

## 5. Legal-risk scenarios and the Administration's position
The Fenix Network is NOT created or maintained to facilitate unlawful activity. Each scenario below carries: (a) a prohibition, (b) the perpetrator's sole liability, (c) exclusion of the Administration's liability to the maximum extent permitted by law, (d) mitigating mechanisms.
### 5.1 Unlawful content, including child-abuse material (CSAM)
Zero tolerance; categorical prohibition; sole liability of the perpetrator. The Administration does not scan content (E2E) but maintains a warned-hash registry and suspends distribution of flagged fragments (consensus). Cooperation with authorities is limited to data that is public on-chain by nature.
### 5.2 Identity theft and impersonation
Prohibited. Protective mechanisms: signature-based identity, name protection (rank perk), public wallet fingerprints for out-of-band verification. The Administration is not liable for harm caused by a User's failure to verify fingerprints.
### 5.3 Cryptocurrency fraud ('scams')
Prohibited. The Administration does not broker P2P exchanges, does not vouch for counterparties and does not custody user funds. Iron rule: the Administration NEVER requests a key, seed, advance payment or 'verification deposit'. Consensus-confirmed scam addresses enter the SCAM_ALERT registry. Contracts and their consequences burden the parties alone.
### 5.4 Trade in unlawful goods and services (drugs, weapons, stolen data, etc.)
Prohibited; sole liability of the parties; the Administration is not responsible for offers, contracts or their outcomes.
### 5.5 Malicious software, ransomware, phishing
Prohibited; patterns enforced via ban codes; SCAM_ALERT for confirmed campaigns; Administration not liable for resulting damage.
### 5.6 Money laundering and sanctions evasion
Prohibited; the User is responsible for compliance with their own jurisdiction (incl. AML and tax). The Administration provides no financial services, performs no KYC (design decision) and guarantees neither liquidity nor any value of FNX.
### 5.7 Terrorism, violence, incitement
Categorically prohibited; Administration liability excluded; only naturally public on-chain data can be indicated.
### 5.8 Third parties' personal data, doxxing, intellectual-property infringement
Prohibited; liability of the publisher; the Administration is not responsible.
### 5.9 Attacks on the Network itself (incl. the camo layer and consensus)
Handled automatically via ban codes; the Administration is not liable for damage caused by third-party attacks.
### 5.10 Limitation of clauses
No provision excludes liability that mandatory law does not allow to be excluded. This document is drafted in good faith to minimize harm for all participants.

> **IN PLAIN TERMS: **Private does not mean lawless. Whoever sells stolen goods here, scams or impersonates — answers alone. The network cannot 'peek' at them for the same reasons it cannot peek at you. That is the price and the gift of privacy.

## 6. User-protection mechanisms
- E2E encryption with one-time keys (forward secrecy) — even a compromised long-term key does not open history.
- No logs or content network-side: RAM session capsules, session-key burning on logout (crypto-shred).
- Transport camouflage (camo) + onion routing — against DPI, profiling and traffic analysis.
- Public security verdicts: every ban with a code and PL/EN explanation plus evidence hash; public register.
- Telemetry slider off/minimal/full (default minimal) — the User decides.
- Proof-of-Uptime instead of personal data — reputation without deanonymization.
- Unban procedure: 30 days for the Administration's decision, 99% refund on rejection or timeout.
- Anti-scam alerts (SCAM_ALERT), wallet-fingerprint verification, registry of fake 'Administration' identities.
- Panic password (silent crypto-shred), 'clean screen', duress-password self-destruct (D3).
- Hygiene rules published to Users: verify ISO SHA256 sums; the Administration never initiates contact about funds; never asks for key, seed or password.

> **IN PLAIN TERMS: **The network defends you with mathematics, not promises. Against scams there is one iron rule: support will never ask for your key. Ever.

## 7. Terms of Service — key provisions (summary)
- Provided 'as is', without warranties; full text: docs/ToS.md.
- Content and liability for it: Users alone.
- No data = no possibility of disclosing it; no account recovery (D9).
- Ranks: payments final; perks evolve only within protocol bounds.
- Automatic bans with reasoning; unban 1,000,000 USD XMR, 30 days, 99% refund; one buyout per wallet; re-ban permanent.
- The protection system (AI) is in the Administration's exclusive control; users cannot communicate with it.
- Administration liability limited to USD 0 to the maximum extent permitted.
- Amendments: published at least 14 days ahead; continued use = acceptance.

> **IN PLAIN TERMS: **Same as above — fridge-door bullet points.

## 8. User responsibility and age
Service intended for adults (18+). The User is responsible for: compliance with the law of their own jurisdiction, security of keys and passwords, the content they create and host, and the consequences of transactions concluded with other users. Ignorance of the law is no excuse — as everywhere.

## 9. Final provisions
Severability of provisions; amendments with 14 days' notice; the Polish version prevails; contact exclusively via official announcement channels inside the Network; document date: 2026-07-19.

## Annex A — Ranks and Perks (price list)
### ghost — starter (0 FNX)
- hosting: 1 site (Web Builder)
- generated avatar (wallet identicon)
- dark theme, 1 group (25 people)
- offline buffer 7 days, tier 0
- full PoU/vote after 30 days uptime

### Donor — 0.000001 FNX
- custom avatar (encrypted upload)
- Donor badge + brown nickname
- hosting: 3 sites
- username reservation (name protection)
- buffer 30 days, tier 1

### VIP — 0.000002 FNX
- animated avatar + profile banner
- hosting: 5 sites + premium site themes
- 2 username changes/year
- groups 3x100, custom GUI themes
- tier 2 + priority seed connections

### VIP+ — 0.000003 FNX
- glowing avatar frame + supporter badge
- hosting: 10 sites + vanity path /nick/site
- beta features access
- groups 5x250
- signed account security reports, tier 3

### SVIP — 0.00001 FNX
- hosting: 25 sites + panel (aggregates, ZERO visitor logs)
- interactive avatar frame
- storage x2, groups 10x500
- announcement feed on own sites
- buffer 180 days, tier 4

### ELITE — 0.0001 FNX
- hosting: 100 sites + custom Web Builder templates (CSS sandbox)
- guaranteed E2E fast-lane
- RC builds + advisory polls (non-binding)
- unlimited group count (2k each)
- vanity wallet (prefix grind), aura badge, tier 5

### SELITE — 0.01 FNX
- hosting: 500 sites + white-label
- network announcement channel (admin moderated)
- supporters page listing (opt-in), test builds + dev channel
- premium vanity, sub-channels, groups 5k
- LIMIT: 10 accounts/year, tier 6

### FENIX — 100.1 FNX
- LIFETIME; hosting without hard limit (fair-use)
- dedicated priority relay E2E
- advisory council seat (quarterly, NO protocol power)
- co-design of 1 cosmetic feature; unique shard badge
- Wall of Legends (opt-in); LIMIT: 21 in network history

### Overriding rank rules
- A rank = a network perk. It NEVER grants: a vote (PoU >=30 days only), access to the security AI (owner/admin only), others' data, an unban, or power over the protocol.
- Rank recorded ON-CHAIN (RANK_UP tx, 6 confirmations); upgrade = pay the difference.
- Until stealth addresses ship, rank purchase is public — a fresh wallet is advised.

## Annex B — Ban & buyout policy (UNBAN)
- Auto-ban = AI consensus (admin tool) -> ON-CHAIN record: reason code + PL/EN explanation + evidence hash (no content!).
- Codes: ROUTE_LEAKAGE (routing via unsecured proxy — extracting data out of Fenix!), PROTO_FLOOD, INVALIDTAG_STORM, SYBIL_RING, STORAGE_FRAUD, MSG_SPAM (metadata, not content), CAMO_VIOLATION, DOXXING.
- UNBAN: only path = 1,000,000 USD in XMR, ONE-TIME (multisig escrow 2-of-3 + timelock).
- Admin has 30 days: accept -> treasury + unban on-chain; reject/timeout -> 99% refund (1% anti-spam). Admin decision final.
- Unban resets PoU/reputation/VOTER to zero; rank does not return.
- One buyout per wallet in network history; re-ban = PERMANENT.
- Public ban register with explanations (GUI + explorer).

*— End of English version —*