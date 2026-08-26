import json
import winreg
from datetime import datetime
from pathlib import Path

from baseline import MONITORED_KEYS, read_registry_values


BASELINE_FILE = (
    Path(__file__).resolve().parent.parent
    / "baseline"
    / "registry_baseline.json"
)


def load_baseline():
    """Load the previously saved registry baseline."""

    if not BASELINE_FILE.exists():
        print("ERROR: Baseline file not found.")
        print(f"Expected location: {BASELINE_FILE}")
        return None

    with open(
        BASELINE_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def compare_registry_values(baseline_values, current_values):
    """
    Compare baseline values with current registry values.

    Returns:
        added
        modified
        deleted
    """

    added = []
    modified = []
    deleted = []

    baseline_names = set(baseline_values.keys())
    current_names = set(current_values.keys())

    # Values that exist now but did not exist in the baseline.
    for value_name in sorted(current_names - baseline_names):

        added.append({
            "name": value_name,
            "current": current_values[value_name]
        })

    # Values that existed in the baseline but no longer exist.
    for value_name in sorted(baseline_names - current_names):

        deleted.append({
            "name": value_name,
            "old": baseline_values[value_name]
        })

    # Values that exist in both but have changed.
    for value_name in sorted(
        baseline_names & current_names
    ):

        old_value = baseline_values[value_name]
        new_value = current_values[value_name]

        if old_value != new_value:

            modified.append({
                "name": value_name,
                "old": old_value,
                "new": new_value
            })

    return added, modified, deleted


def detect_changes():
    """Compare current Registry state against the saved baseline."""

    baseline = load_baseline()

    if baseline is None:
        return

    print()
    print("=" * 80)
    print("REGISTRY CHANGE DETECTION")
    print("=" * 80)

    total_added = 0
    total_modified = 0
    total_deleted = 0

    for registry_key in MONITORED_KEYS:

        name = registry_key["name"]
        root = registry_key["root"]
        path = registry_key["path"]

        baseline_info = baseline["registry"].get(
            name,
            {}
        )

        baseline_values = baseline_info.get(
            "values",
            {}
        )

        current_values = read_registry_values(
            root,
            path
        )

        added, modified, deleted = compare_registry_values(
            baseline_values,
            current_values
        )

        print()
        print("-" * 80)
        print(f"KEY: {name}")
        print(f"PATH: {path}")
        print("-" * 80)

        if not added and not modified and not deleted:
            print("Status: NO CHANGES DETECTED")

        else:

            if added:
                print("\n[ADDED]")

                for item in added:
                    print(f"  Name: {item['name']}")
                    print(f"  Data: {item['current']['data']}")
                    print(f"  Type: {item['current']['type']}")

            if modified:
                print("\n[MODIFIED]")

                for item in modified:
                    print(f"  Name: {item['name']}")
                    print(f"  Old : {item['old']}")
                    print(f"  New : {item['new']}")

            if deleted:
                print("\n[DELETED]")

                for item in deleted:
                    print(f"  Name: {item['name']}")
                    print(f"  Old: {item['old']}")

        total_added += len(added)
        total_modified += len(modified)
        total_deleted += len(deleted)

    print()
    print("=" * 80)
    print("CHANGE DETECTION SUMMARY")
    print("=" * 80)

    print(f"Added values     : {total_added}")
    print(f"Modified values  : {total_modified}")
    print(f"Deleted values   : {total_deleted}")
    print(
        f"Total changes    : "
        f"{total_added + total_modified + total_deleted}"
    )

    print("=" * 80)

    print(
        f"Scan completed: "
        f"{datetime.now().astimezone().isoformat()}"
    )


def run_demo_test():
    """Safely demonstrate change detection without modifying Windows Registry."""

    print()
    print("=" * 80)
    print("SAFE CHANGE DETECTION DEMO")
    print("=" * 80)

    baseline_values = {
        "ExampleApplication": {
            "data": r"C:\Program Files\Example\example.exe",
            "type": "REG_SZ"
        },
        "ExampleSetting": {
            "data": "Enabled",
            "type": "REG_SZ"
        }
    }

    simulated_current_values = {
        "ExampleApplication": {
            "data": r"C:\Program Files\Example\example.exe",
            "type": "REG_SZ"
        },
        "ExampleSetting": {
            "data": "Disabled",
            "type": "REG_SZ"
        },
        "NewApplication": {
            "data": r"C:\Program Files\Example\new.exe",
            "type": "REG_SZ"
        }
    }

    added, modified, deleted = compare_registry_values(
        baseline_values,
        simulated_current_values
    )

    print("\n[ADDED]")

    for item in added:
        print(f"  {item['name']}")
        print(f"  Data: {item['current']['data']}")

    print("\n[MODIFIED]")

    for item in modified:
        print(f"  {item['name']}")
        print(f"  Old: {item['old']['data']}")
        print(f"  New: {item['new']['data']}")

    print("\n[DELETED]")

    if deleted:
        for item in deleted:
            print(f"  {item['name']}")
    else:
        print("  None")

    print()
    print("-" * 80)
    print("SAFE DEMO RESULT")
    print("-" * 80)
    print(f"Added values    : {len(added)}")
    print(f"Modified values : {len(modified)}")
    print(f"Deleted values  : {len(deleted)}")
    print("=" * 80)


if __name__ == "__main__":
    detect_changes()