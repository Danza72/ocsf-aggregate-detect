# AWS Threat Detection — OCSF Aggregate Detect

A multi-layer threat detection pipeline for AWS environments, normalising
CloudTrail, S3 access, and VPC Flow logs into OCSF format and running three
independent detection strategies: **UEBA**, **network exfil**, and
**time-based exfil**. Results are surfaced in a single unified HTML report.

---

## Detection Strategies

### 1. UEBA — User and Entity Behavior Analytics

Scores each actor's daily behaviour against a 30-day personal baseline across
three log sources.

**How it works:**

Each source computes a score from independent behavioral dimensions. The final
score is the **max across sources** so the strongest evidence channel drives
the result, and an actor missing a source is not penalised.

| Source | Dimensions |
|---|---|
| **CloudTrail** | `new_operation`, `new_resource`, `new_region`, `volume_zscore`, `new_ip_known_region`, `low_frequency_hour` |
| **S3** | `new_operation`, `new_bucket`, `new_src_ip`, `error_rate`, `bytes_zscore`, `event_zscore` |
| **VPC** | `new_dst_ip`, `new_dst_port`, `reject_ratio`, `bytes_zscore`, `flow_zscore`, `new_protocol` |

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

### How the three detectors work together

No single detector is sufficient. Real threats tend to fire across multiple
detectors; false positives typically fire only one.

| Actor type | UEBA | Network Exfil | Time-Based Exfil | Signals |
|---|---|---|---|---|
| Compromised creds (mass exfil) | High | High | High | 3/3 |
| Compromised service account | Medium | High | High | 3/3 |
| Insider ramp | Medium* | Medium | High | 3/3 |
| C2 beaconing | Medium | Medium | — | 2/3 |
| Privilege escalation | High | — | — | 1/3 |
| Authorized pentest (FP) | Medium | — | — | 1/3 |
| Nightly backup (FP) | — | Medium | — | 1/3 |

*UEBA catches the new VPC destination, not the S3 ramp itself.

The Findings tab in the report ranks actors by signal count. **Prioritise
actors with 3/3 signals first** — independent agreement across detectors is
strong evidence of a real threat.

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

build_baselines.py                 # Builds 30-day per-actor behavioral baselines
build_incident_profiles.py         # Profiles each actor per incident day
scorer_v3.py                       # UEBA scorer (v1 weights, max cross-source)
detect_low_slow_exfil.py           # Network + time-based exfil detector
report.py                          # Generates unified HTML report
run_ueba_v3.py                     # End-to-end pipeline runner

generate_test_dataset.py           # Basic 10-actor synthetic dataset
generate_advanced_dataset.py       # Advanced 25-actor dataset (Operation Quiet Harvest)
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
python run_ueba_v3.py \
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
python run_ueba_v3.py \
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
python run_ueba_v3.py \
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

### Pipeline flags

| Flag | Default | Description |
|---|---|---|
| `--input` | `ocsf_out_v2` | Directory containing OCSF baseline files and `incident/` subfolder |
| `--output` | `output_v2_scored_v3` | Directory where scores, profiles, and the report are written |
| `--start` | First available day | Start of the incident window (YYYY-MM-DD) |
| `--end` | Last available day | End of the incident window (YYYY-MM-DD) |
| `--report-date` | Last day in range | Which day to generate the HTML report for |

---

## Pipeline Steps (what `run_ueba_v3.py` does)

```
Step 1  build_baselines.py        — 30-day baseline per actor (CT + S3 + VPC)
Step 2  build_incident_profiles.py — per-day actor profiles for each incident day
        scorer_v3.py              — UEBA score per actor per day
Step 3  detect_low_slow_exfil.py  — network + time-based exfil across full range
Step 4  report.py                 — unified HTML report with all three detectors
```

---

## Report Structure

```
[ Findings ] [ Exfil Detection ]  |  UEBA: [ Period Overview ] [ day tabs ]
```

| Tab | Contents |
|---|---|
| **Findings** | Summary matrix — every actor, which detectors fired, signal count (0/3 – 3/3). Sort by signal count for triage priority. |
| **Exfil Detection** | Per-actor detail cards for network and time-based exfil alerts — scores, destinations, alert reasons, trend data. |
| **Period Overview** | UEBA aggregate across the full date range — peak scores, top anomalous actors. |
| **Day tabs** | Per-day UEBA deep-dive — dimension-level breakdown, hour grid, volume comparisons, VPC connection pills for each actor. |

---

## Advanced Dataset — Operation Quiet Harvest

A validation dataset with a known ground truth for testing all three
detection layers simultaneously.

| Category | Actors | Detected by |
|---|---|---|
| `james_dev` — stolen creds, mass S3 exfil, C2 VPC | TP | UEBA (0.87) + network exfil + time-based |
| `svc_data_pipeline` — compromised service account, 10x S3 drain | TP | UEBA + time-based (75) + network exfil (85) |
| `mallory_insider` — insider ramp 20→200 events/day + VPC drip | TP | UEBA (0.73) + time-based (145) + network exfil |
| `neil_c2` — C2 beaconing, off-hours recon | TP | UEBA (0.73) + network exfil (70) |
| `petra_privesc` — DeleteTrail/StopLogging kill chain | TP | UEBA (0.66) |
| `oscar_ransomprep` — mass Describe recon, all known ops | TP | **Missed (0.28)** — documented blind spot |
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

`oscar_ransomprep` is an intentional gap demonstrating that UEBA alone cannot
catch an attacker who uses only known operations from a known IP at high
volume. A sequence or graph-based detector is required.
