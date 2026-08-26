import json
import winreg
from datetime import datetime
from pathlib import Path


# Registry locations that our monitoring system will track.
MONITORED_KEYS = [
    {
        "name": "HKCU_Run",
        "root": winreg.HKEY_CURRENT_USER,
        "path": r"Software\Microsoft\Windows\CurrentVersion\Run",
    },
    {
        "name": "HKCU_RunOnce",
        "root": winreg.HKEY_CURRENT_USER,
        "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    },
    {
        "name": "HKLM_Run",
        "root": winreg.HKEY_LOCAL_MACHINE,
        "path": r"Software\Microsoft\Windows\CurrentVersion\Run",
    },
    {
        "name": "HKLM_RunOnce",
        "root": winreg.HKEY_LOCAL_MACHINE,
        "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    },
]


BASELINE_DIR = Path(__file__).resolve().parent.parent / "baseline"
BASELINE_FILE = BASELINE_DIR / "registry_baseline.json"


def get_registry_type_name(value_type):
    """Convert registry type number into a readable name."""

    registry_types = {
        winreg.REG_SZ: "REG_SZ",
        winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
        winreg.REG_BINARY: "REG_BINARY",
        winreg.REG_DWORD: "REG_DWORD",
        winreg.REG_QWORD: "REG_QWORD",
        winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
    }

    return registry_types.get(
        value_type,
        f"UNKNOWN ({value_type})"
    )


def make_json_safe(value):
    """Convert registry data into JSON-compatible data."""

    if isinstance(value, bytes):
        return value.hex()

    if isinstance(value, tuple):
        return list(value)

    return value


def read_registry_values(root_key, sub_key):
    """Read all values from a registry key."""

    values = {}

    try:
        with winreg.OpenKey(
            root_key,
            sub_key,
            0,
            winreg.KEY_READ
        ) as key:

            index = 0

            while True:

                try:
                    value_name, value_data, value_type = winreg.EnumValue(
                        key,
                        index
                    )

                    values[value_name] = {
                        "data": make_json_safe(value_data),
                        "type": get_registry_type_name(value_type),
                    }

                    index += 1

                except OSError:
                    break

    except FileNotFoundError:
        return {}

    except PermissionError:
        return {}

    return values


def create_baseline():
    """Capture the current state of monitored Registry keys."""

    baseline = {
        "metadata": {
            "created_at": datetime.now().astimezone().isoformat(),
            "description": "Windows Registry monitoring baseline",
        },
        "registry": {},
    }

    print()
    print("=" * 80)
    print("CREATING REGISTRY BASELINE")
    print("=" * 80)

    for registry_key in MONITORED_KEYS:

        name = registry_key["name"]
        root = registry_key["root"]
        path = registry_key["path"]

        values = read_registry_values(root, path)

        baseline["registry"][name] = {
            "path": path,
            "values": values,
            "value_count": len(values),
        }

        print(f"{name:<20}: {len(values)} values")

    BASELINE_DIR.mkdir(parents=True, exist_ok=True)

    with open(
        BASELINE_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            baseline,
            file,
            indent=4,
            ensure_ascii=False
        )

    print()
    print("-" * 80)
    print(f"Baseline saved to:")
    print(BASELINE_FILE)
    print("-" * 80)

    total_values = sum(
        item["value_count"]
        for item in baseline["registry"].values()
    )

    print(f"Total values captured: {total_values}")
    print("=" * 80)


if __name__ == "__main__":
    create_baseline()