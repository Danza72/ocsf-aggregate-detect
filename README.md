# AWS Threat Detection — OCSF Aggregate Detect

A multi-layer threat detection pipeline for AWS environments, normalising
CloudTrail, S3 access, and VPC Flow logs into OCSF format and running four
independent detection strategies: **UEBA**, **network exfil**, **time-based
exfil**, and **session kill-chain detection**. Results are surfaced in a single
unified HTML report.

---

## Detection Strategies

### 1. UEBA — User and Entity Behavior Analytics

Scores each actor's daily behaviour against a 30-day personal baseline across
three log sources.

**How it works:**

Each source computes a score from independent behavioral dimensions. The final
score is the **max across sources** so the strongest evidence channel drives
the result, and an actor missing a source is not penalised.

**CloudTrail** — weighted sum (weights reflect impact on final score):

| Dimension | Weight | What it detects |
|---|---|---|
| `new_operation` | **25%** | API call never seen in baseline |
| `new_resource` | **20%** | AWS resource never accessed before |
| `new_region` | **20%** | AWS region never used in baseline |
| `volume_zscore` | **15%** | Hourly event count statistically abnormal |
| `new_ip_known_region` | **10%** | New source IP in a familiar region (IP rotation) |
| `low_frequency_hour` | **10%** | Activity at an hour rare or absent in baseline |

**S3 and VPC** — equal-weight (each dimension is 1/6 ≈ 16.7%):

| S3 Dimension | VPC Dimension | What it detects |
|---|---|---|
| `new_operation` | `new_dst_ip` | New API operation / new destination IP |
| `new_bucket` | `new_dst_port` | Bucket never accessed / port never seen |
| `new_src_ip` | `reject_ratio` | New source IP / REJECT rate above baseline |
| `error_rate` | `bytes_zscore` | Non-2xx response rate / abnormal bytes volume |
| `bytes_zscore` | `flow_zscore` | Abnormal total bytes / abnormal flow count |
| `event_zscore` | `new_protocol` | Abnormal event count / new network protocol |

**What it catches:**
- Stolen credentials from a new IP, region, or at unusual hours
- Lateral movement to new resources or regions
- Mass data access (volume spikes)
- C2 traffic to new VPC destinations
- Privilege escalation via new IAM operations (e.g. `DeleteTrail`, `CreateUser`)

**What it misses:**
- Attackers using only known operations from a known IP — volume alone is
  insufficient if all other dimensions are zero (see `oscar_ransomprep` in the
  advanced dataset)
- Slow, low-volume patterns spread across many days — each individual day
  looks normal

**Alert threshold:** `final_score >= 0.40`

---

### 2. Network Exfil Detection — Low-and-Slow VPC Analysis

Analyses VPC flow logs for network-level exfiltration patterns: repeated small
transfers, regular beaconing intervals, and large data volumes to rare
destinations.

**How it works:**

For each source ENI or actor, the detector computes:

| Signal | What it means |
|---|---|
| `small_transfer_ratio` | High fraction of flows below 20MB — trickle pattern |
| `interval_cv` | Coefficient of variation of flow intervals — low CV means clockwork beaconing |
| `total_bytes_out` | Cumulative data volume leaving the network |
| `rare_destination_ratio` | Fraction of flows to IPs not seen in baseline |

Scores are split into `network_risk_score` (VPC pattern analysis) and combined
into a `combined_risk_score`.

**What it catches:**
- C2 beaconing — regular small flows to a new external IP
- Bulk exfiltration — large flows to a new destination
- Slow drip — very few flows per day but consistently to a new IP over weeks

**What it misses:**
- Exfil over known destinations (e.g. attacker using a compromised S3 bucket
  already in baseline)
- Low-volume exfil below the minimum bytes threshold

**Alert threshold:** `combined_risk_score >= 40`

---

### 3. Time-Based Exfil Detection — Rolling S3 Elevation

Analyses S3 access logs over time to catch patterns invisible on any single
day: sustained elevation, linear ramps, and periodic spikes.

**How it works:**

The detector splits the log window into a **baseline period** and a **current
period**, then computes per-actor daily byte/event totals and measures
deviation:

| Detection type | Pattern |
|---|---|
| `sustained_elevation` | Average activity ratio >= 2.5x for >= 7 consecutive days |
| `ramp_up` | Monotonically increasing daily volume with positive trend slope |
| `periodic_spikes` | Regular high-volume days with low-volume days between |

The `time_based_risk_score` reflects the magnitude and consistency of the
elevation above baseline.

**What it catches:**
- Insiders gradually increasing their data access over weeks
- Compromised service accounts running at 10x normal volume every day
- Quarterly/seasonal spikes that exceed normal variation

**What it misses:**
- Short bursts (< 3 days) that don't accumulate enough elevation
- Exfil via VPC only (no S3 footprint)

**Alert threshold:** `time_based_risk_score >= 40`

---

### 4. Session Kill-Chain Detection — Sequence Scoring

Groups CloudTrail events into sessions per identity (30-minute inactivity gap)
and scores each session against a global baseline model trained on observed
action-category sequences. Surfaces multi-stage attack chains that are
invisible to per-event rules.

**How it works:**

Every API call is mapped to a broad action category (Discovery, CredentialAccess,
PermissionChange, Persistence, DefenseEvasion, DataAccess, etc.). Each session
is then scored across five components that together produce a 0–100 risk score:

| Component | Max | What it measures |
|---|---|---|
| `sequence_rarity_score` | 25 | Action-category 2-grams and 3-grams absent from baseline — how novel is the *order* of what was done |
| `suspicious_chain_score` | 30 | Hardcoded attacker-playbook patterns: Discovery→CredentialAccess, Discovery→PermissionChange, StopLogging→GetObject, ListBuckets + bulk GetObject, etc. |
| `timing_burst_score` | 20 | Unusually fast event rate vs baseline p95, and fast progression between attack phases (e.g. recon to credential theft in under 10 minutes) |
| `feature_deviation_score` | 15 | Z-score deviation across session shape features: num_events, duration, unique_services, sensitive action count |
| `sensitive_action_score` | 10 | Raw count of high-sensitivity operations: PermissionChange, CredentialAccess, Persistence, DefenseEvasion |

The model is **global, not per-identity** — sessions are compared against
what any identity does in the baseline, not against the specific identity's
own history. This means a service role performing IAM operations for the first
time is anomalous regardless of whether that specific role has been seen before.

Each scored session includes a `flagged_api_sequences` field listing the exact
API calls that triggered each signal (visible via the Details button in the
Session Detection tab of the report).

**What it catches:**
- Multi-stage kill chains invisible to per-event rules — recon followed by
  privilege escalation followed by credential access, all in one session window
- CI/CD pipeline compromise — a deploy role suddenly calling IAM and
  SecretsManager APIs it has never touched
- Privilege escalation via ECS task definition abuse — rogue task running
  under a privileged role with an anomalous session name
- Credential harvesting — a service role calling `GetSecretValue` on multiple
  secrets in one session (normally it calls it once on startup)
- Persistence and defense evasion — `CreateUser` + `AttachUserPolicy` +
  `StopLogging` in a single tight session window

**What it misses:**
- Attacks that use only operations already common in baseline, from the same
  identity, in a familiar sequence — the model has no novelty signal if the
  attacker blends in perfectly
- Multi-session kill chains spread more than 30 minutes apart on separate
  days — sessionization splits them; a cross-session graph detector would be
  required
- Per-identity context — the global model means a new service role appearing
  for the first time has nothing to compare against for its specific expected
  operations

**Alert threshold:** `session_risk_score >= 70` (red) | `>= 40` (amber)

**Session risk explanation — templated vs AI-generated**

Each scored session includes a `risk_explanation` field shown in the Details
popup. Currently this is generated by a template function in
`session_detection/score_sessions.py` (`_build_risk_explanation()`) that
constructs a fixed English sentence from the top-scoring components — e.g.
*"High sequence rarity (rare API ordering) combined with suspicious kill-chain
pattern (Discovery→CredentialAccess) and fast progression (recon to sensitive
action in 5.8 min)."*

This is intentionally kept deterministic and offline so the pipeline runs
without any external dependency. However, the `flagged_api_sequences` field
already contains all the structured evidence needed to produce a much richer
explanation. Replacing the template with a Claude API call is a one-function
swap:

```python
import anthropic

def generate_ai_explanation(session_row: dict, flagged_sequences: str) -> str:
    client = anthropic.Anthropic()
    prompt = f"""You are a cloud security analyst. Explain in 2-3 sentences
why this AWS session is suspicious, in plain English for a SOC analyst.

Identity: {session_row['identity_id']}
Session window: {session_row['session_start']} to {session_row['session_end']}
Risk score: {session_row['session_risk_score']:.0f}/100
Flagged signals: {flagged_sequences}"""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=256,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text
```

Call this in place of `_build_risk_explanation()` for each session row that
exceeds the amber threshold. For a 50-session top-N output this costs roughly
50 API calls; batch the amber/red rows only to keep latency and cost down.

---

### How the four detectors work together

No single detector is sufficient. Real threats tend to fire across multiple
detectors; false positives typically fire only one.

| Actor type | UEBA | Network Exfil | Time-Based Exfil | Session Kill-Chain | Signals |
|---|---|---|---|---|---|
| Compromised creds (mass exfil) | High | High | High | High | 4/4 |
| CI/CD pipeline compromise | Low* | Medium | — | **High** | 2/4 |
| Compromised service account | Medium | High | High | Medium | 4/4 |
| Insider ramp | Medium | Medium | High | Low | 3/4 |
| Privilege escalation + persistence | High | — | — | **High** | 2/4 |
| Credential harvesting (service role) | Low* | Medium | — | **High** | 2/4 |
| C2 beaconing | Medium | Medium | — | Low | 2/4 |
| Authorized pentest (FP) | Medium | — | — | Low | 1/4 |
| Nightly backup (FP) | — | Medium | — | — | 1/4 |

\* UEBA misses attacks where the attacker uses only known operations from a
known IP. Session detection fills this gap by evaluating the *sequence and
combination* of operations rather than novelty of individual ones.

The Findings tab in the report ranks actors by signal count. **Prioritise
actors with 3/4 or 4/4 signals first** — independent agreement across detectors
is strong evidence of a real threat. Session-only signals (1/4) warrant
investigation but may be aggressive service accounts or new deployment patterns.

---

## File Structure

```
ocsf_out/                          # OCSF-normalised log inputs
  cloudtrail_synthetic_baseline.jsonl
  s3_synthetic_baseline.jsonl
  vpcflow_synthetic_baseline.jsonl
  incident/
    2018-08-20/
      cloudtrail_ocsf.jsonl
      s3_accesslogs_ocsf.jsonl
      vpcflow_ocsf.jsonl
    2018-08-21/ ...

session_detection/                 # Kill-chain session scoring module
  normalize_cloudtrail.py          # Normalises OCSF/CloudTrail events to flat schema
  build_sessions.py                # Groups events into sessions (30-min gap), extracts features
  train_global_session_baseline.py # Builds n-gram frequency model from baseline sessions
  score_sessions.py                # Scores new sessions across 5 components, 0-100
  action_categories.py             # Maps raw API event names to action categories
  run_pipeline.py                  # Standalone session detection runner

build_baselines.py                 # Builds 30-day per-actor behavioral baselines
build_incident_profiles.py         # Profiles each actor per incident day
scorer_v3.py                       # UEBA scorer (v1 weights, max cross-source)
detect_low_slow_exfil.py           # Network + time-based exfil detector
report.py                          # Generates unified HTML report
run_analytics.py                   # End-to-end pipeline runner (all 4 detectors)

generate_test_dataset.py           # Basic 10-actor synthetic dataset
generate_advanced_dataset.py       # Advanced 25-actor dataset (Operation Quiet Harvest)
generate_cloudnative_dataset.py    # Cloud-native microservice dataset with CI/CD attack chain
ocsfnormalizer.py                  # Normalises raw AWS logs to OCSF format
utility/                           # Log inspection and extraction helpers
```

---

## How to Run

### Prerequisites

```bash
pip install pandas numpy
```

### Option A — Run on real BOTSv3 data

First normalise your raw logs to OCSF format:

```bash
python ocsfnormalizer.py
```

Then run the full pipeline:

```bash
python run_analytics.py \
    --input  ocsf_out_v2 \
    --output output_v2_scored_v3 \
    --start  2018-08-20 \
    --end    2018-08-28
```

Open the report in a browser:
```
output_v2_scored_v3/risk_report_2018-08-28.html
```

---

### Option B — Run on the basic synthetic dataset (10 actors)

```bash
python generate_test_dataset.py
python run_analytics.py \
    --input  test_data/ocsf_out \
    --output test_data/output \
    --start  2018-08-20 \
    --end    2018-09-02
```

---

### Option C — Run on the advanced synthetic dataset (25 actors)

The advanced dataset ("Operation Quiet Harvest") includes 6 true positive
attack scenarios, 9 realistic false positives, and 10 benign actors across a
30-day baseline and 14-day incident window.

```bash
python generate_advanced_dataset.py
python run_analytics.py \
    --input  test_data_advanced/ocsf_out \
    --output test_data_advanced/output \
    --start  2018-08-20 \
    --end    2018-09-02
```

Open the report:
```
test_data_advanced/output/risk_report_2018-09-02.html
```

See `test_data_advanced/ground_truth.json` for the expected detection results
and documented blind spots.

---

### Option D — Run on the cloud-native microservice dataset

A realistic AWS environment modelling a SaaS payments platform (NovaPay) with
ECS Fargate microservices, Lambda functions, and a GitHub Actions CI/CD
pipeline. Designed specifically to validate session kill-chain detection against
a real-world attack vector: **CI/CD pipeline compromise via leaked OIDC token**,
leading to ECS task-definition privilege escalation, bulk credential harvesting
from Secrets Manager, and IAM backdoor persistence.

```bash
# Generate the dataset (baseline + 14 incident days)
python generate_cloudnative_dataset.py --output ocsf_cloudnative

# Run the full pipeline
python run_analytics.py \
    --input  ocsf_cloudnative \
    --output output_cloudnative \
    --start  2024-03-01 \
    --end    2024-03-14 \
    --report-date 2024-03-14
```

The attack is injected on incident days 10–12 (2024-03-10 through 2024-03-12).
See **Cloud-Native Dataset — NovaPay CI/CD Attack** below for the full
breakdown.

---

### Pipeline flags

| Flag | Default | Description |
|---|---|---|
| `--input` | `ocsf_out_v2` | Directory containing OCSF baseline files and `incident/` subfolder |
| `--output` | `output_v2_scored_v3` | Directory where scores, profiles, and the report are written |
| `--start` | First available day | Start of the incident window (YYYY-MM-DD) |
| `--end` | Last available day | End of the incident window (YYYY-MM-DD) |
| `--report-date` | Last day in range | Which day to generate the HTML report for |

---

## Pipeline Steps (what `run_analytics.py` does)

```
Step 1  build_baselines.py              — 30-day baseline per actor (CT + S3 + VPC)
Step 2  build_incident_profiles.py      — per-day actor profiles for each incident day
        scorer_v3.py                    — UEBA score per actor per day
Step 3  detect_low_slow_exfil.py        — network + time-based exfil across full range
Step 4  session_detection/              — kill-chain session scoring
          normalize_cloudtrail.py       — flatten all incident CloudTrail to event table
          build_sessions.py             — sessionize by identity (30-min gap)
          train_global_session_baseline — build n-gram frequency model from baseline CT
          score_sessions.py             — score each session, 0-100, 5 components
Step 5  report.py                       — unified HTML report with all four detectors
```

---

## Report Structure

```
[ Findings ] [ Exfil Detection ] [ Session Detection ]  |  UEBA: [ Period Overview ] [ day tabs ]
```

| Tab | Contents |
|---|---|
| **Findings** | Summary matrix — every actor, which detectors fired, signal count (0–4). Sort by signal count for triage priority. |
| **Exfil Detection** | Per-actor detail cards for network and time-based exfil alerts — scores, destinations, alert reasons, trend data. |
| **Session Detection** | Ranked table of risky sessions — identity, time window, event count, duration, 0–100 risk score, five sub-score bars. Click **Details ▶** on any row for a popup showing the plain-English risk summary and the exact flagged API call sequences that triggered each signal. |
| **Period Overview** | UEBA aggregate across the full date range — peak scores, top anomalous actors. |
| **Day tabs** | Per-day UEBA deep-dive — dimension-level breakdown, hour grid, volume comparisons, VPC connection pills for each actor. |

### Session Detection — Score colour thresholds

| Colour | Score | Meaning |
|---|---|---|
| 🔴 Red | ≥ 70 | High risk — known-bad kill-chain pattern or maximally rare sequence |
| 🟠 Amber | ≥ 40 | Medium risk — suspicious combination, warrants investigation |
| 🟢 Green | < 40 | Low risk — within normal behavioural range |

### Flagged API Sequence labels (Details popup)

| Label | Triggered by |
|---|---|
| `CHAIN` / `TRIPLE` | Known attacker category pair or triple (e.g. Discovery→CredentialAccess) |
| `EVENT_PAIR` | Hardcoded suspicious API-to-API transition (e.g. StopLogging→GetObject) |
| `RARE_SEQUENCE` | Category n-gram with zero occurrences in baseline — shows actual API calls per step |
| `BULK_ACCESS` | ListBuckets followed by 5+ GetObject calls |
| `DEFENSE_EVASION_FIRST` | DefenseEvasion was the first action in the session |
| `FAST_PROGRESSION` | Discovery to sensitive action in under 10 minutes |
| `BURST_RATE` | Events-per-minute or max-events-in-5min exceeds baseline p95 |
| `DEVIATION` | Numeric session feature more than 3 standard deviations from baseline mean |
| `SENSITIVE` | Lists the actual sensitive API calls (PermissionChange, CredentialAccess, Persistence, DefenseEvasion) |

---

## Cloud-Native Dataset — NovaPay CI/CD Attack

Simulates a realistic SaaS payments platform on AWS. Validates session kill-chain
detection specifically against **service-role-based attacks** that are invisible
to UEBA (no new IPs, no new regions, legitimate API calls used individually).

### Normal Baseline Behaviour

| Identity | Type | Pattern | Daily volume |
|---|---|---|---|
| `api-service-role` | ECS Fargate | `AssumeRole` → DynamoDB Query/GetItem → occasional `GetSecretValue` (cold start, 8%) | 200–380 sessions |
| `worker-service-role` | ECS Fargate | `AssumeRole` → `GetSecretValue` (RDS password, always once) → `GetObject` → `PutObject` | 40–90 sessions |
| `lambda-processor-role` | Lambda | `AssumeRole` → `GetObject` (uploads) → `PutObject` (processed) | 60–140 invocations |
| `lambda-notif-role` | Lambda | `AssumeRole` → occasional `GetObject` (email template, 30%) → outbound HTTPS | 80–180 invocations |
| `cloudwatch-agent-role` | EC2 agent | `PutMetricData` every 10 minutes, 24/7, single fixed instance | 144 events/day |
| `ci-deploy-role` | GitHub Actions | `AssumeRole` → `DescribeTaskDefinition` → `RegisterTaskDefinition` → `UpdateService` → `UpdateFunctionCode` → S3 tf-state read/write | 1–4 runs/weekday |
| `backup-service-role` | AWS Backup | `CreateBackupVault` → `StartBackupJob` → `DescribeBackupJob` → `PutObject`, runs 01:00–02:00 UTC only | 5 events/night |
| `dev.sarah` | IAM user | ECS/Lambda console checks during business hours (09:00–17:00 UTC) | 1–4 events, ~70% of weekdays |
| `ops.james` | IAM user | EC2/CloudWatch checks during business hours | 1–4 events, ~40% of weekdays |

Session names are UUID-suffixed (`ecs-task-{hex}`, `novapay-doc-processor-{hex}`,
`GitHubActions-{run-id}`) — no human-readable names. VPC traffic is east-west
between internal CIDRs (10.0.x.x): ECS→DynamoDB (443), ECS→RDS (5432),
ECS→ElastiCache (6379).

The critical baseline fingerprint for `ci-deploy-role`: **it never calls IAM
APIs, never calls SecretsManager, and never touches anything outside ECS +
Lambda + S3 (tf-state bucket only).** This is what makes the attack detectable.

### Attack Chain

**Day 10 — 2024-03-10, 03:12 UTC — Initial Access + Reconnaissance**

Attacker uses a leaked GitHub Actions OIDC token to call AWS as `ci-deploy-role`
from attacker IP `185.220.101.42` (not a GitHub runner IP) at 03:12 UTC (this
role is never active before 09:00 in baseline).

Session runs 11 recon ops over ~20 minutes — mapping users, roles, permissions,
running ECS tasks, and existing task definitions:

```
AssumeRole → GetCallerIdentity → ListUsers → ListRoles →
GetAccountAuthorizationDetails → ListBuckets → DescribeInstances →
DescribeSecurityGroups → ListTasks → DescribeTaskDefinition (novapay-worker) →
ListAccessKeys
```

The `DescribeTaskDefinition` call on `novapay-worker` is the pivot decision:
it reveals that `worker-service-role` is passed to that task and has
SecretsManager access.

---

**Day 11 — 2024-03-11, 02:05 UTC — Privilege Escalation + Credential Theft**

*Phase 1 — `ci-deploy-role` (02:05 UTC):*

Attacker abuses `ecs:RegisterTaskDefinition` + `iam:PassRole`. Registers a
rogue task definition that looks like a maintenance container but runs attacker
code, passing `worker-service-role` to it. Runs the task immediately:

```
AssumeRole → RegisterTaskDefinition (novapay-worker) →
RunTask → DescribeTasks
```

*Phase 2 — `worker-service-role`, session `rogue-maintenance-d4f8a` (02:15 UTC):*

Rogue container starts. Session name is not the normal `ecs-task-{uuid}` format.
Task calls `GetSecretValue` on every production secret back to back — a pattern
completely absent from the 30-day baseline, where workers always call it exactly
once (RDS password only):

```
AssumeRole → ListSecrets → GetSecretValue (prod/rds/password) →
GetSecretValue (prod/payment-gateway/api-key) →
GetSecretValue (prod/redis/auth-token) →
GetSecretValue (prod/internal-service/jwt-secret) →
PutObject (novapay-logs-archive)
```

The `PutObject` stages harvested secrets in a legitimate bucket. Outbound VPC
flows then carry the actual exfil to `185.220.101.42:443` (40–120KB each, 3
flows).

---

**Day 12 — 2024-03-12, 01:44 UTC — Persistence + Defense Evasion**

Attacker uses `ci-deploy-role` one final time (before OIDC token expires) to
plant a permanent IAM backdoor:

```
AssumeRole → GetCallerIdentity → CreateUser (svc.monitor) →
CreateAccessKey (svc.monitor) → AttachUserPolicy (AdministratorAccess) →
CreateLoginProfile (svc.monitor) → StopLogging (novapay-management-trail)
```

Five C2 beacon flows to `91.108.4.1:8080` every 20 minutes follow, confirming
the backdoor is live.

### Detection Results

| Session | Identity | Risk Score | Primary signals |
|---|---|---|---|
| `GitHubActions-9876543212_s1` | `ci-deploy-role` | **71.5 🔴** | Rarity 25/25 (sequence never in baseline) + Chain 16/30 (Discovery→PermissionChange, Discovery→CredentialAccess, Auth→Discovery→PermissionChange triple) + Timing 12/20 (recon→persistence in 5.8 min) + Sensitive 10/10 (all four sensitive categories hit) |
| `rogue-maintenance-d4f8a_s1` | `worker-service-role` | **39.3 🟠** | Rarity 24.8/25 (CredentialAccess→CredentialAccess→CredentialAccess n-gram absent from baseline) + Deviation 8.5/15 (4 sensitive actions vs baseline mean 0.15) + Sensitive 6/10 (4× GetSecretValue) |

**Why the rogue task scored lower than expected:** the chain scorer looks for
*transitions between different categories*. Since the rogue session goes
almost entirely through `CredentialAccess`, there are no Discovery→CredentialAccess
transitions to fire on — the attacker's pre-loaded knowledge of which secrets
to target meant they skipped in-session recon, which made the chain score zero.
The session is still caught by rarity and deviation, but a well-prepared
attacker who minimises category transitions will consistently score lower on
the chain component.

---

## Advanced Dataset — Operation Quiet Harvest

A validation dataset with a known ground truth for testing all four
detection layers simultaneously.

| Category | Actors | Detected by |
|---|---|---|
| `james_dev` — stolen creds, mass S3 exfil, C2 VPC | TP | UEBA (0.87) + network exfil + time-based + session |
| `svc_data_pipeline` — compromised service account, 10x S3 drain | TP | UEBA + time-based (75) + network exfil (85) + session |
| `mallory_insider` — insider ramp 20→200 events/day + VPC drip | TP | UEBA (0.73) + time-based (145) + network exfil + session |
| `neil_c2` — C2 beaconing, off-hours recon | TP | UEBA (0.73) + network exfil (70) + session |
| `petra_privesc` — DeleteTrail/StopLogging kill chain | TP | UEBA (0.66) + **session (kill-chain)** |
| `oscar_ransomprep` — mass Describe recon, all known ops | TP | UEBA blind spot — **session detects via sequence rarity** |
| `tom_devops` — EU expansion (new region + VPC) | FP | UEBA + network exfil — dismiss via change ticket |
| `carol_pentest` — authorized pentest from new IP | FP | UEBA — dismiss via SOW + approved IP list |
| `bob_analytics` — team transfer, new S3 buckets | FP | UEBA — dismiss via HR transfer record |
| `alice_hr` — annual access review (IAM enumeration) | FP | UEBA — dismiss via compliance calendar |
| `svc_provisioning` — new employee onboarding | FP | UEBA — dismiss via HR tickets |
| `dave_keyrotation` — quarterly key rotation | FP | UEBA — dismiss via rotation schedule |
| `svc_backup` — nightly backup large VPC bytes | FP | Network exfil — dismiss, destination in baseline |
| `sarah_finance` — quarter-end reporting spike | FP | Below threshold — correctly quiet |
| `jenkins_ci` — daily CI builds (was every-other-day) | FP | Below threshold — correctly quiet |
| `eng_01–05`, `svc_*`, `frank_pm` | Benign | No signals |

`oscar_ransomprep` was previously an intentional gap in UEBA. Session kill-chain
detection now catches it via sequence rarity — the combination of
`DescribeInstances → DescribeSecurityGroups → GetSecretValue → CreateAccessKey`
in a tight window is a novel n-gram even if each individual call is in baseline.

---

## Basic Dataset — Operation Data Grab (Extended)

The original 10-actor dataset from `generate_test_dataset.py`. Designed to
validate each detection layer in isolation.

**Baseline:** Jul 21 – Aug 19 (30 days) | **Incident:** Aug 20 – Sep 2 (14 days)

### True Positives

**`alice_m` — Stolen Credentials**
Logs in from `185.220.101.5` in `ap-southeast-1` at 2–4am (new region, new IP),
runs IAM ops and mass S3 access. All detectors fire. **Score ~0.87.**

**`dave_f` — Suspicious Hours + New Resource**
Finance analyst accessing a new bucket at 1–3am. UEBA fires on
`low_frequency_hour`, `new_resource`, `new_operation`. **Score 0.25–0.70.**

**`oscar_r` — Sequence Attack**
Runs a 20-minute kill chain using only known operations from a known IP.
UEBA misses (score ~0.20). **Session detection catches it via sequence rarity
and fast Discovery→CredentialAccess progression.**

**`mallory_t` — Steady 3× S3 Exfiltration**
Reads at 3× baseline every day. Each day looks mildly elevated.
**Caught by time-based exfil** (`sustained_elevation`). UEBA misses.

**`neil_k` — Gradual Ramp**
Ramps from 1.5× to 4× over the incident window.
**Caught by time-based exfil** (`ramp_up`). UEBA misses every single day.

**`petra_v` — Periodic Spikes**
Spikes to 5× on alternate days. **Caught by time-based exfil** (`periodic_spikes`).

### Benign

| Actor | Why it stays clean |
|---|---|
| `bob_d` | Same IP/region/ops/VPC destinations all 14 days |
| `carol_s` | High S3 volume but consistent with baseline |
| `svc_backup` | 2–3am PutObject to `backup-bucket` — perfectly predictable |
| `svc_monthly` | Runs Aug 1 in baseline → Aug 20 incident day looks identical. **Requires 30-day baseline** — a 14-day window would false-positive on Aug 20. |

### Detection coverage

| Actor | UEBA | Session Kill-Chain | Time-Based | Result |
|---|---|---|---|---|
| `alice_m` | ✓ ~0.87 | ✓ | — | Malicious |
| `dave_f` | ✓ ~0.35 | — | — | Suspicious |
| `oscar_r` | ✗ ~0.20 | ✓ sequence rarity | — | Malicious |
| `mallory_t` | ✗ | — | ✓ sustained 3× | Malicious |
| `neil_k` | ✗ | — | ✓ ramp | Malicious |
| `petra_v` | ✗ | — | ✓ periodic spikes | Malicious |
| `bob_d` | ✗ | — | — | Benign |
| `carol_s` | ✗ | — | — | Benign |
| `svc_backup` | ✗ | — | — | Benign |
| `svc_monthly` | ✗ | — | — | Benign (needs 30-day baseline) |

The session kill-chain detector specifically closes the `oscar_r` gap that UEBA
leaves open — surfacing attacks composed entirely of known-good individual API
calls by evaluating the *combination and ordering* of those calls within a
session window.
