import json
from datetime import datetime
from pathlib import Path

from baseline import MONITORED_KEYS, read_registry_values


BASELINE_FILE = Path("baseline/registry_baseline.json")
REPORT_FILE = Path("reports/integrity_report.txt")


def load_baseline():
    """Load the saved registry baseline."""

    if not BASELINE_FILE.exists():
        print(f"ERROR: Baseline file not found: {BASELINE_FILE}")
        return None

    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except json.JSONDecodeError:
        print("ERROR: Baseline JSON file is invalid.")
        return None

    except OSError as error:
        print(f"ERROR: Could not read baseline: {error}")
        return None


def normalize_values(values):
    """Convert registry values into a simple name -> data dictionary."""

    normalized = {}

    if not isinstance(values, dict):
        return normalized

    for name, information in values.items():

        if isinstance(information, dict):
            data = information.get("data", "")
        else:
            data = information

        normalized[str(name)] = str(data)

    return normalized


def get_baseline_values(baseline, registry_key):
    """Get baseline values for one monitored registry key."""

    key_name = registry_key["name"]

    if not isinstance(baseline, dict):
        return {}

    registry_data = baseline.get("registry", {})

    if not isinstance(registry_data, dict):
        return {}

    key_data = registry_data.get(key_name, {})

    if not isinstance(key_data, dict):
        return {}

    values = key_data.get("values", {})

    return normalize_values(values)


def compare_values(baseline_values, current_values):
    """Compare baseline and current registry values."""

    changes = {
        "added": [],
        "modified": [],
        "deleted": []
    }

    baseline_names = set(baseline_values.keys())
    current_names = set(current_values.keys())

    # Added values
    for name in sorted(current_names - baseline_names):

        changes["added"].append({
            "name": name,
            "new_value": current_values[name]
        })

    # Deleted values
    for name in sorted(baseline_names - current_names):

        changes["deleted"].append({
            "name": name,
            "old_value": baseline_values[name]
        })

    # Modified values
    for name in sorted(baseline_names & current_names):

        old_value = baseline_values[name]
        new_value = current_values[name]

        if old_value != new_value:

            changes["modified"].append({
                "name": name,
                "old_value": old_value,
                "new_value": new_value
            })

    return changes


def write_report(results):
    """Write the integrity analysis to a text report."""

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(REPORT_FILE, "w", encoding="utf-8") as file:

        file.write("WINDOWS REGISTRY INTEGRITY REPORT\n")
        file.write("=" * 80 + "\n")

        file.write(
            f"Scan time: {datetime.now().astimezone().isoformat()}\n"
        )

        file.write("=" * 80 + "\n\n")

        total_added = 0
        total_modified = 0
        total_deleted = 0

        for result in results:

            file.write(f"KEY: {result['key']}\n")
            file.write(f"PATH: {result['path']}\n")
            file.write("-" * 80 + "\n")

            added = result["changes"]["added"]
            modified = result["changes"]["modified"]
            deleted = result["changes"]["deleted"]

            total_added += len(added)
            total_modified += len(modified)
            total_deleted += len(deleted)

            if not added and not modified and not deleted:
                file.write("STATUS: NO CHANGES DETECTED\n\n")
                continue

            if added:

                file.write("\n[ADDED VALUES]\n")

                for item in added:
                    file.write(f"Name: {item['name']}\n")
                    file.write(f"New : {item['new_value']}\n")

            if modified:

                file.write("\n[MODIFIED VALUES]\n")

                for item in modified:
                    file.write(f"Name: {item['name']}\n")
                    file.write(f"Old : {item['old_value']}\n")
                    file.write(f"New : {item['new_value']}\n")

            if deleted:

                file.write("\n[DELETED VALUES]\n")

                for item in deleted:
                    file.write(f"Name: {item['name']}\n")
                    file.write(f"Old : {item['old_value']}\n")

            file.write("\n")

        file.write("=" * 80 + "\n")
        file.write("INTEGRITY SUMMARY\n")
        file.write("=" * 80 + "\n")

        file.write(f"Added values    : {total_added}\n")
        file.write(f"Modified values : {total_modified}\n")
        file.write(f"Deleted values  : {total_deleted}\n")
        file.write(
            f"Total changes   : "
            f"{total_added + total_modified + total_deleted}\n"
        )

        if total_added + total_modified + total_deleted == 0:
            file.write("Integrity status : PASS\n")
        else:
            file.write("Integrity status : CHANGES DETECTED\n")

        file.write("=" * 80 + "\n")


def run_integrity_check():

    print()
    print("=" * 80)
    print("WINDOWS REGISTRY INTEGRITY CHECKER")
    print("=" * 80)

    baseline = load_baseline()

    if baseline is None:
        return

    results = []

    total_added = 0
    total_modified = 0
    total_deleted = 0

    for registry_key in MONITORED_KEYS:

        key_name = registry_key["name"]
        key_path = registry_key["path"]

        print()
        print("-" * 80)
        print(f"KEY: {key_name}")
        print(f"PATH: {key_path}")
        print("-" * 80)

        baseline_values = get_baseline_values(
            baseline,
            registry_key
        )

        current_raw = read_registry_values(
            registry_key["root"],
            registry_key["path"]
        )

        current_values = normalize_values(current_raw)

        changes = compare_values(
            baseline_values,
            current_values
        )

        results.append({
            "key": key_name,
            "path": key_path,
            "changes": changes
        })

        added = changes["added"]
        modified = changes["modified"]
        deleted = changes["deleted"]

        total_added += len(added)
        total_modified += len(modified)
        total_deleted += len(deleted)

        if not added and not modified and not deleted:

            print("STATUS: NO CHANGES DETECTED")

        else:

            if added:
                print("\n[ADDED]")

                for item in added:
                    print(f"Name: {item['name']}")
                    print(f"New : {item['new_value']}")

            if modified:
                print("\n[MODIFIED]")

                for item in modified:
                    print(f"Name: {item['name']}")
                    print(f"Old : {item['old_value']}")
                    print(f"New : {item['new_value']}")

            if deleted:
                print("\n[DELETED]")

                for item in deleted:
                    print(f"Name: {item['name']}")
                    print(f"Old : {item['old_value']}")

    print()
    print("=" * 80)
    print("INTEGRITY SUMMARY")
    print("=" * 80)

    print(f"Added values    : {total_added}")
    print(f"Modified values : {total_modified}")
    print(f"Deleted values  : {total_deleted}")
    print(
        f"Total changes   : "
        f"{total_added + total_modified + total_deleted}"
    )

    if total_added + total_modified + total_deleted == 0:
        print("Integrity status : PASS")
    else:
        print("Integrity status : CHANGES DETECTED")

    print("=" * 80)

    write_report(results)

    print()
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    run_integrity_check()