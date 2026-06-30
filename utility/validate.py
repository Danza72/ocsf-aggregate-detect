#!/usr/bin/env python3
"""
validate_ocsf.py

Validates mapped OCSF JSONL output against the REAL, official OCSF schema
(via the ocsf-json-schema package: pip install ocsf-json-schema). This is
the authoritative check -- it doesn't rely on a human (or an LLM) eyeballing
field names, it validates against the actual JSON Schema OCSF publishes.

Usage:
    pip install ocsf-json-schema --break-system-packages
    python3 validate_ocsf.py <ocsf_jsonl_file> <class_name>

Example:
    python3 validate_ocsf.py ocsf_out/cloudtrail_ocsf.jsonl api_activity
    python3 validate_ocsf.py ocsf_out/vpcflow_ocsf.jsonl network_activity
    python3 validate_ocsf.py ocsf_out/s3_accesslogs_ocsf.jsonl api_activity

class_name must match an OCSF class key, e.g. api_activity, network_activity.
"""

import json
import sys

from jsonschema import Draft202012Validator
from jsonschema.validators import validator_for
from referencing import Registry, Resource
from ocsf_json_schema import get_ocsf_schema, OcsfJsonSchemaEmbedded


def make_offline_validator(json_schema: dict):
    """
    Build a jsonschema validator that resolves all $ref / $id lookups
    purely from the given schema document itself, never over the network.

    Without this, jsonschema's default resolver can attempt to fetch
    https://schema.ocsf.io/... or https://json-schema.org/... over HTTP
    when resolving a $ref it doesn't already have inlined -- which can
    hang for a long time on a slow or filtered network connection.
    """
    resource = Resource.from_contents(json_schema)
    registry = resource @ Registry()
    Validator = validator_for(json_schema, default=Draft202012Validator)
    return Validator(json_schema, registry=registry)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <ocsf_jsonl_file> <class_name>")
        sys.exit(1)

    jsonl_path = sys.argv[1]
    class_name = sys.argv[2]

    ocsf_schema = OcsfJsonSchemaEmbedded(get_ocsf_schema(version="1.4.0"))
    json_schema = ocsf_schema.get_class_schema(class_name=class_name, profiles=["cloud", "datetime"])
    validator = make_offline_validator(json_schema)

    total = 0
    valid = 0
    first_errors = []

    with open(jsonl_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            event = json.loads(line)
            errors = list(validator.iter_errors(event))
            if not errors:
                valid += 1
            elif len(first_errors) < 5:
                first_errors.append(str(errors[0]))

    print(f"{jsonl_path}: {valid}/{total} valid against OCSF '{class_name}' schema")
    if first_errors:
        print("\nFirst few validation errors:")
        for err in first_errors:
            print(f"  - {err}")


if __name__ == "__main__":
    main()