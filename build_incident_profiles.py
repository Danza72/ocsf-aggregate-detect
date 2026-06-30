#!/usr/bin/env python3
"""
build_incident_profiles.py

Builds per-actor profiles from real incident-day logs (Aug 20 2018).
Records what each actor actually did: IPs, regions, operations, resources,
S3 buckets, VPC flows. No scoring — pure evidence collection.

Output:
    incident_profiles.json  -- one profile per actor

Run build_baselines.py first, then scorer.py to generate risk scores.
"""

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

CLOUDTRAIL = Path("ocsf_out/cloudtrail_ocsf.jsonl")
OUTPUT     = Path("incident_profiles.json")
S3_LOGS    = Path("ocsf_out/s3_accesslogs_ocsf.jsonl")
VPC_LOGS    = Path("ocsf_out/vpcflow_ocsf.jsonl")
VPC_ENT_OUT = Path("vpc_entities.json")


def _ms_to_iso(ts_ms: int | None) -> str | None:
    if ts_ms is None:
        return None
    return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _ms_to_hour(ts_ms: int) -> int:
    return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).hour


def build_cloudtrail_profiles() -> dict:
    profiles: dict[str, dict] = {}

    uid_map:       dict[str, str]  = {}
    uid_alt_map:   dict[str, dict] = defaultdict(lambda: defaultdict(lambda: {"first": None, "last": None}))
    uid_type_map:  dict[str, dict] = defaultdict(lambda: defaultdict(lambda: {"first": None, "last": None}))
    is_system:     dict[str, bool] = {}
    known_ips:     dict[str, dict] = defaultdict(lambda: defaultdict(lambda: {"first": None, "last": None}))
    known_regions: dict[str, set]  = defaultdict(set)
    known_ops:     dict[str, set]  = defaultdict(set)
    known_resources: dict[str, set]= defaultdict(set)
    known_hours:   dict[str, dict] = defaultdict(lambda: defaultdict(int))
    event_count:   dict[str, int]  = defaultdict(int)

    # Read CloudTrail Logs to extract identifiers and behavioural facts
    with open(CLOUDTRAIL) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)

            user    = (event.get("actor") or {}).get("user", {})
            name = user.get("name")
            if not name:
                continue

            # Identity fields
            if user.get("uid") and name not in uid_map:
                uid_map[name] = user["uid"]
            if user.get("uid_alt"):
                ts = event.get("time")
                entry = uid_alt_map[name][user["uid_alt"]]
                if entry["first"] is None or ts < entry["first"]:
                    entry["first"] = ts
                if entry["last"] is None or ts > entry["last"]:
                    entry["last"] = ts
            if user.get("type"):
                ts = event.get("time")
                utype = user["type"]
                entry = uid_type_map[name][utype]
                if entry["first"] is None or ts < entry["first"]:
                    entry["first"] = ts
                if entry["last"] is None or ts > entry["last"]:
                    entry["last"] = ts
            if name not in is_system:
                is_system[name] = bool(
                    (event.get("unmapped") or {}).get("is_system_actor", False)
                )

            # Behavioral facts
            ip = (event.get("src_endpoint") or {}).get("ip")
            if ip:
                ts = event.get("time")
                entry = known_ips[name][ip]
                if entry["first"] is None or ts < entry["first"]:
                    entry["first"] = ts
                if entry["last"] is None or ts > entry["last"]:
                    entry["last"] = ts

            region = (event.get("cloud") or {}).get("region")
            if region:
                known_regions[name].add(region)

            operation = (event.get("api") or {}).get("operation")
            if operation:
                known_ops[name].add(operation)

            for res in event.get("resources") or []:
                rname = (res or {}).get("name")
                if rname:
                    known_resources[name].add(rname)

            ts = event.get("time")
            if ts:
                known_hours[name][_ms_to_hour(ts)] += 1

            event_count[name] += 1

    for name in event_count:
        profiles[name] = {
            "uid":      uid_map.get(name),
            "uid_types": [
                {
                    "type":       utype,
                    "first_seen": _ms_to_iso(entry["first"]),
                    "last_seen":  _ms_to_iso(entry["last"]),
                }
                for utype, entry in sorted(uid_type_map[name].items())
            ],
            "uid_alts": [
                {
                    "uid_alt":    key,
                    "first_seen": _ms_to_iso(entry["first"]),
                    "last_seen":  _ms_to_iso(entry["last"]),
                }
                for key, entry in sorted(uid_alt_map.get(name, {}).items())
            ],
            "is_system_actor": is_system.get(name, False),
            "cloudtrail": {
                "event_count":      event_count[name],
                "known_ips": [
                    {
                        "ip":         ip,
                        "first_seen": _ms_to_iso(entry["first"]),
                        "last_seen":  _ms_to_iso(entry["last"]),
                    }
                    for ip, entry in sorted(known_ips[name].items())
                ],
                "known_regions":    sorted(known_regions[name]),
                "known_operations": sorted(known_ops[name]),
                "known_resources":  sorted(known_resources[name]),
                "known_hours":      dict(sorted(known_hours[name].items())),
            },
            "s3":  None,
            "vpc": None,
        }

    return profiles


def link_s3(profiles: dict) -> None:
    """
    Step 2: Enrich profiles with S3 access log data.
    Links by actor.user.name -> fills profiles[name]["s3"].
    """
    if not S3_LOGS.exists():
        print(f"[s3] {S3_LOGS} not found, skipping.")
        return

    # Accumulators keyed by actor name
    event_count: dict[str, int]        = defaultdict(int)
    known_buckets: dict[str, set]      = defaultdict(set)
    known_ops: dict[str, set]          = defaultdict(set)
    bytes_total: dict[str, int]        = defaultdict(int)
    bytes_max:   dict[str, dict]       = defaultdict(lambda: {"bytes": 0, "time": None})
    known_ips: dict[str, dict]         = defaultdict(lambda: defaultdict(lambda: {"first": None, "last": None}))
    response_codes: dict[str, dict]    = defaultdict(lambda: defaultdict(int))

    with open(S3_LOGS) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)

            name = (event.get("actor") or {}).get("user", {}).get("name")
            if not name:
                continue

            ts  = event.get("time")
            operation  = (event.get("api") or {}).get("operation")
            bucket = ((event.get("resources") or [{}])[0] or {}).get("name")
            ip  = (event.get("src_endpoint") or {}).get("ip")
            response_code = (event.get("api") or {}).get("response", {}).get("code")
            bytes_sent = (event.get("unmapped") or {}).get("bytes_sent")

            event_count[name] += 1

            if operation:
                known_ops[name].add(operation)
            if bucket:
                known_buckets[name].add(bucket)
            if response_code:
                response_codes[name][str(response_code)] += 1
            if bytes_sent and str(bytes_sent) != "-":
                try:
                    val = int(bytes_sent)
                    bytes_total[name] += val
                    if val > bytes_max[name]["bytes"]:
                        bytes_max[name]["bytes"] = val
                        bytes_max[name]["time"]  = ts
                except ValueError:
                    pass
            if ip:
                entry = known_ips[name][ip]
                if entry["first"] is None or ts < entry["first"]:
                    entry["first"] = ts
                if entry["last"] is None or ts > entry["last"]:
                    entry["last"] = ts

    # Write into profiles — create entry for actors not in CloudTrail
    all_names = set(event_count.keys())
    for name in all_names:
        if name not in profiles:
            profiles[name] = {
                "uid": None, "uid_types": [], "uid_alts": [],
                "is_system_actor": None,
                "cloudtrail": None, "s3": None, "vpc": None,
            }
        profiles[name]["s3"] = {
            "event_count":   event_count[name],
            "known_buckets": sorted(known_buckets[name]),
            "known_operations": sorted(known_ops[name]),
            "bytes_total":   bytes_total[name],
            "bytes_max_single": {
                "bytes": bytes_max[name]["bytes"],
                "time":  _ms_to_iso(bytes_max[name]["time"]),
            },
            "response_codes": dict(response_codes[name]),
            "known_ips": [
                {
                    "ip":         ip,
                    "first_seen": _ms_to_iso(entry["first"]),
                    "last_seen":  _ms_to_iso(entry["last"]),
                }
                for ip, entry in sorted(known_ips[name].items())
            ],
        }

    print(f"[s3] {sum(event_count.values())} events linked to "
          f"{len(event_count)} actors")


def _eni_accumulators() -> dict:
    return {
        "src_ips":      set(),   # all IPs that appeared as src for this ENI
        "actor_name":   None,
        "event_count":  0,
        "bytes_total":  0,
        "bytes_max":    {"bytes": 0, "time": None},
        "dst_ips":      defaultdict(lambda: {"first": None, "last": None}),
        "dst_ports":    defaultdict(int),
        "dst_conns":    defaultdict(int),
        "protocols":    set(),
        "actions":      defaultdict(int),
        "first_seen":   None,
        "last_seen":    None,
    }


def link_vpc(profiles: dict) -> dict:
    """
    Step 3: Enrich profiles with VPC flow data.

    Pass 1 — group every flow by src_endpoint.interface_uid (ENI).
    Pass 2 — resolve each ENI's src_ip against CloudTrail known_ips;
              resolved ENIs populate profiles[actor]["vpc"] as before.

    Returns vpc_entities dict (all ENIs, resolved or not).
    """
    if not VPC_LOGS.exists():
        print(f"[vpc] {VPC_LOGS} not found, skipping.")
        return {}

    # Build IP -> actor name lookup from CloudTrail known_ips
    ip_to_actor: dict[str, str] = {}
    for name, p in profiles.items():
        ct = p.get("cloudtrail")
        if ct:
            for entry in ct["known_ips"]:
                ip_to_actor[entry["ip"]] = name

    # Pass 1: accumulate per ENI
    eni_data: dict[str, dict] = defaultdict(_eni_accumulators)

    with open(VPC_LOGS) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)

            src    = ev.get("src_endpoint") or {}
            eni    = src.get("interface_uid")
            if not eni:
                continue

            src_ip   = src.get("ip")
            ts       = ev.get("time")
            dst_ip   = (ev.get("dst_endpoint") or {}).get("ip")
            dst_port = (ev.get("dst_endpoint") or {}).get("port")
            proto    = (ev.get("connection_info") or {}).get("protocol_num")
            action   = (ev.get("unmapped") or {}).get("action")
            b        = (ev.get("traffic") or {}).get("bytes", 0) or 0

            d = eni_data[eni]
            if src_ip:
                d["src_ips"].add(src_ip)

            d["event_count"] += 1
            d["bytes_total"] += b

            if b > d["bytes_max"]["bytes"]:
                d["bytes_max"]["bytes"] = b
                d["bytes_max"]["time"]  = ts

            if ts:
                if d["first_seen"] is None or ts < d["first_seen"]:
                    d["first_seen"] = ts
                if d["last_seen"] is None or ts > d["last_seen"]:
                    d["last_seen"] = ts

            if dst_ip:
                entry = d["dst_ips"][dst_ip]
                if entry["first"] is None or ts < entry["first"]:
                    entry["first"] = ts
                if entry["last"] is None or ts > entry["last"]:
                    entry["last"] = ts

            if dst_port:
                d["dst_ports"][dst_port] += 1
            if dst_ip and dst_port:
                d["dst_conns"][f"{dst_ip}:{dst_port}"] += 1

            if proto is not None:
                d["protocols"].add(proto)

            if action:
                d["actions"][action] += 1

    # Pass 2: resolve ENI -> actor, build vpc_entities output
    vpc_entities: dict[str, dict] = {}
    actor_flows:  dict[str, list] = defaultdict(list)

    for eni, d in eni_data.items():
        # First src_ip that matches a known actor; None if all IPs are unresolved
        actor = next(
            (ip_to_actor[ip] for ip in d["src_ips"] if ip in ip_to_actor),
            None,
        )
        # The specific IP that resolved — stored for traceability in vpc_entities.json
        resolved_ip = next(
            (ip for ip in d["src_ips"] if ip in ip_to_actor),
            None,
        )
        d["actor_name"] = actor
        actor_flows[actor or eni].append(d)

        vpc_entities[eni] = {
            "src_ips":     sorted(d["src_ips"]),
            "resolved_ip": resolved_ip,
            "actor_name":  actor,
            "event_count": d["event_count"],
            "bytes_total": d["bytes_total"],
            "bytes_max_single": {
                "bytes": d["bytes_max"]["bytes"],
                "time":  _ms_to_iso(d["bytes_max"]["time"]),
            },
            "first_seen": _ms_to_iso(d["first_seen"]),
            "last_seen":  _ms_to_iso(d["last_seen"]),
            "dst_ips": [
                {
                    "ip":         ip,
                    "first_seen": _ms_to_iso(e["first"]),
                    "last_seen":  _ms_to_iso(e["last"]),
                }
                for ip, e in sorted(d["dst_ips"].items())
            ],
            "dst_ports": dict(sorted(d["dst_ports"].items(), key=lambda x: -x[1])),
            "dst_conns": dict(sorted(d["dst_conns"].items(), key=lambda x: -x[1])),
            "protocols": sorted(d["protocols"]),
            "actions":   dict(d["actions"]),
        }

    # Merge resolved ENIs into actor profiles
    # Create stub profiles for unresolved ENIs so vpc data has somewhere to land
    for actor in actor_flows:
        if actor not in profiles:
            profiles[actor] = {
                "uid": None, "uid_types": [], "uid_alts": [],
                "is_system_actor": False,
                "cloudtrail": None, "s3": None, "vpc": None,
            }

    for actor, flow_list in actor_flows.items():
        merged_dst_ips:   dict[str, dict] = {}
        merged_dst_ports: dict[int, int]  = defaultdict(int)
        merged_dst_conns: dict[str, int]  = defaultdict(int)
        merged_protocols: set             = set()
        merged_actions:   dict[str, int]  = defaultdict(int)
        merged_bytes_max                  = {"bytes": 0, "time": None}
        merged_bytes_total                = 0
        merged_event_count                = 0
        merged_first: int | None          = None
        merged_last:  int | None          = None

        for d in flow_list:
            merged_event_count += d["event_count"]
            merged_bytes_total += d["bytes_total"]

            if d["bytes_max"]["bytes"] > merged_bytes_max["bytes"]:
                merged_bytes_max = d["bytes_max"]

            fs = d["first_seen"]
            ls = d["last_seen"]
            if fs and (merged_first is None or fs < merged_first):
                merged_first = fs
            if ls and (merged_last is None or ls > merged_last):
                merged_last = ls

            for ip, e in d["dst_ips"].items():
                if ip not in merged_dst_ips:
                    merged_dst_ips[ip] = {"first": e["first"], "last": e["last"]}
                else:
                    if e["first"] and (merged_dst_ips[ip]["first"] is None or e["first"] < merged_dst_ips[ip]["first"]):
                        merged_dst_ips[ip]["first"] = e["first"]
                    if e["last"] and (merged_dst_ips[ip]["last"] is None or e["last"] > merged_dst_ips[ip]["last"]):
                        merged_dst_ips[ip]["last"] = e["last"]

            for port, cnt in d["dst_ports"].items():
                merged_dst_ports[port] += cnt
            for conn, cnt in d["dst_conns"].items():
                merged_dst_conns[conn] += cnt

            merged_protocols |= d["protocols"]

            for act, cnt in d["actions"].items():
                merged_actions[act] += cnt

        profiles[actor]["vpc"] = {
            "event_count":  merged_event_count,
            "bytes_total":  merged_bytes_total,
            "bytes_max_single": {
                "bytes": merged_bytes_max["bytes"],
                "time":  _ms_to_iso(merged_bytes_max["time"]),
            },
            "first_seen": _ms_to_iso(merged_first),
            "last_seen":  _ms_to_iso(merged_last),
            "dst_ips": [
                {
                    "ip":         ip,
                    "first_seen": _ms_to_iso(e["first"]),
                    "last_seen":  _ms_to_iso(e["last"]),
                }
                for ip, e in sorted(merged_dst_ips.items())
            ],
            "dst_ports": {
                port: cnt
                for port, cnt in sorted(merged_dst_ports.items(), key=lambda x: -x[1])
                if cnt > 1
            },
            "dst_conns": dict(sorted(merged_dst_conns.items(), key=lambda x: -x[1])),
            "protocols": sorted(merged_protocols),
            "actions":   dict(merged_actions),
        }

    resolved   = sum(1 for d in eni_data.values() if d["actor_name"])
    unresolved = len(eni_data) - resolved
    total_flows = sum(d["event_count"] for d in eni_data.values())
    print(f"[vpc] {total_flows} flows across {len(eni_data)} ENIs — "
          f"{resolved} resolved to actor, {unresolved} unresolved")
    return vpc_entities


def main() -> None:
    print(f"Reading {CLOUDTRAIL} ...")
    profiles = build_cloudtrail_profiles()

    print(f"Reading {S3_LOGS} ...")
    link_s3(profiles)

    print(f"Reading {VPC_LOGS} ...")
    vpc_entities = link_vpc(profiles)

    human  = {k: v for k, v in profiles.items() if not v["is_system_actor"] and v["cloudtrail"]}
    system = {k: v for k, v in profiles.items() if v["is_system_actor"] and v["cloudtrail"]}
    eni    = {k: v for k, v in profiles.items() if not v["cloudtrail"] and not v["s3"]}

    print(f"  {len(human)} human actors")
    print(f"  {len(system)} system actors")
    print(f"  {len(eni)} unresolved ENI entities")
    print()

    for name, p in sorted(profiles.items()):
        tag = "SYSTEM" if p["is_system_actor"] else "human"
        ct  = p["cloudtrail"]
        s3  = p["s3"]
        print(f"  [{tag}]  {name}")
        print(f"    uid          : {p['uid']}")
        print(f"    uid_alts     : {p['uid_alts']}")
        if ct:
            print(f"    ct events    : {ct['event_count']}")
            print(f"    known_ips    : {[e['ip'] for e in ct['known_ips']]}")
            print(f"    known_regions: {ct['known_regions']}")
            print(f"    known_ops    : {len(ct['known_operations'])} distinct operations")
        if s3:
            print(f"    s3 events    : {s3['event_count']}")
            print(f"    s3 buckets   : {s3['known_buckets']}")
            print(f"    s3 ops       : {s3['known_operations']}")
            print(f"    s3 bytes     : {s3['bytes_total']}")
            print(f"    s3 responses : {s3['response_codes']}")
        vpc = p.get("vpc")
        if vpc:
            print(f"    vpc flows    : {vpc['event_count']}")
            print(f"    vpc bytes    : {vpc['bytes_total']}")
            print(f"    vpc dst_ips  : {[e['ip'] for e in vpc['dst_ips']]}")
            print(f"    vpc ports    : {dict(list(vpc['dst_ports'].items())[:5])}")
        print()

    with open(OUTPUT, "w") as f:
        json.dump(profiles, f, indent=2)
    print(f"Saved {len(profiles)} actor profiles -> {OUTPUT}")

    with open(VPC_ENT_OUT, "w") as f:
        json.dump(vpc_entities, f, indent=2)
    print(f"Saved {len(vpc_entities)} ENI profiles -> {VPC_ENT_OUT}")


if __name__ == "__main__":
    main()
