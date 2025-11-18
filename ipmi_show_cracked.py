#!/usr/bin/env python3
"""
Join IPMI dump output with a hashcat potfile to show cracked credentials
along with host information.

Expected formats:

Dump file (from IPMI tool):
    10.160.133.27 ADMIN:516a655d81000000...140541444d494e:55bc7c98e16c...

Potfile (hashcat):
    516a655d81000000...140541444d494e:55bc7c98e16c...:SomePassword

Usage:
    ipmi_show_cracked.py -d ipmi-dump.txt -p ipmi_hashes.potfile
"""

import argparse
import os
import sys


def debug(msg: str) -> None:
    print(f"[DEBUG] {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"[WARN] {msg}", file=sys.stderr)


def error(msg: str) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)


def load_potfile(pot_path: str) -> dict:
    """
    Load a hashcat potfile into a dict mapping:
        "hash_part1:hash_part2" (lowercased) -> plaintext password
    """
    mapping = {}
    try:
        with open(pot_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":")
                if len(parts) < 3:
                    warn(f"Unexpected potfile format on line {line_no}, skipping")
                    continue

                # Everything except the last field is the hash string
                password = parts[-1]
                ipmi_hash = ":".join(parts[:-1]).lower()

                mapping[ipmi_hash] = password

        debug(f"Loaded {len(mapping)} unique cracked hashes from potfile")
    except FileNotFoundError:
        error(f"Potfile not found: {pot_path}")
        sys.exit(1)
    except OSError as e:
        error(f"Error reading potfile '{pot_path}': {e}")
        sys.exit(1)

    return mapping


def process_dump(dump_path: str, cracked_map: dict) -> None:
    """
    Read the IPMI dump file, join with cracked_map, and print results.
    """
    total_lines = 0
    matched = 0
    unmatched = 0

    try:
        with open(dump_path, "r", encoding="utf-8", errors="ignore") as f:
            # Header
            print("{:<15} {:<10} {:<20} {}".format(
                "HOST", "USER", "STATUS", "PASSWORD"
            ))
            print("-" * 70)

            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                total_lines += 1

                # Expect: "<host> <user>:<hash1>:<hash2>"
                try:
                    host, rest = line.split(None, 1)
                except ValueError:
                    warn(f"Line {line_no}: could not split host and rest, skipping")
                    unmatched += 1
                    continue

                rest_parts = rest.split(":")
                if len(rest_parts) < 3:
                    warn(f"Line {line_no}: unexpected dump format, skipping")
                    unmatched += 1
                    continue

                user = rest_parts[0]
                hash_part1 = rest_parts[1]
                hash_part2 = rest_parts[2]

                ipmi_hash = f"{hash_part1}:{hash_part2}".lower()

                if ipmi_hash in cracked_map:
                    password = cracked_map[ipmi_hash]
                    status = "CRACKED"
                    matched += 1
                else:
                    password = ""
                    status = "UNCRACKED"
                    unmatched += 1

                print("{:<15} {:<10} {:<20} {}".format(
                    host, user, status, password
                ))

    except FileNotFoundError:
        error(f"Dump file not found: {dump_path}")
        sys.exit(1)
    except OSError as e:
        error(f"Error reading dump file '{dump_path}': {e}")
        sys.exit(1)

    debug(f"Processed {total_lines} dump lines")
    debug(f"Matched (cracked): {matched}")
    debug(f"Unmatched (uncracked or bad format): {unmatched}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Join IPMI hash dump with hashcat potfile to show cracked credentials"
    )
    parser.add_argument(
        "-d", "--dump",
        help="IPMI hash dump file (with host info)",
        required=False
    )
    parser.add_argument(
        "-p", "--pot",
        help="hashcat potfile containing cracked IPMI hashes",
        required=False
    )

    args = parser.parse_args()

    # Enforce required args and show help if missing (per your preference)
    if not args.dump or not args.pot:
        print("[ERROR] Both --dump and --pot are required.\n", file=sys.stderr)
        parser.print_help(sys.stderr)
        sys.exit(1)

    return args


def main() -> None:
    args = parse_args()

    debug(f"Using dump file: {args.dump}")
    debug(f"Using potfile : {args.pot}")

    # Quick existence checks for extra robustness
    for path_label, path_value in (("dump file", args.dump), ("potfile", args.pot)):
        if not os.path.isfile(path_value):
            error(f"Specified {path_label} does not exist or is not a file: {path_value}")
            sys.exit(1)

    cracked_map = load_potfile(args.pot)
    process_dump(args.dump, cracked_map)


if __name__ == "__main__":
    main()
