import os
import json
import re

REPORTS_DIR = "reports"
OUTPUT_FILE = os.path.join(REPORTS_DIR, "normalized_events.json")

def normalize_report(file_path, filename):
    with open(file_path, "r") as f:
        data = json.load(f)

    events = []
    target = data.get("target") or data.get("domain") or "unknown"

    for key, value in data.items():
        if key in ["target", "domain"]:
            continue

        # Case 1: list values
        if isinstance(value, list):
            for v in value:
                events.append({
                    "type": key.upper(),
                    "value": v,
                    "target": target,
                    "source_file": filename
                })

        # Case 2: dict values
        elif isinstance(value, dict):
            for k, v in value.items():
                events.append({
                    "type": f"{key.upper()}_{k.upper()}",
                    "value": v,
                    "target": target,
                    "source_file": filename
                })

        # Case 3: plain values
        else:
            events.append({
                "type": key.upper(),
                "value": value,
                "target": target,
                "source_file": filename
            })

    return events


def main():
    all_events = []

    # Match files like "<tool>_report_<domain>.json"
    for filename in os.listdir(REPORTS_DIR):
        if re.match(r".+_report_.*\.json", filename):
            file_path = os.path.join(REPORTS_DIR, filename)
            try:
                events = normalize_report(file_path, filename)
                all_events.extend(events)
                print(f"[✔] Normalized {filename} ({len(events)} events)")
            except Exception as e:
                print(f"[!] Failed to process {filename}: {e}")

    with open(OUTPUT_FILE, "w") as f:
        json.dump({"events": all_events}, f, indent=2)

    print(f"\n[✔] All normalized events saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
