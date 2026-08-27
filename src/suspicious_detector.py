from baseline import MONITORED_KEYS, read_registry_values


# Patterns that may indicate suspicious registry persistence
# or script-based execution.
SUSPICIOUS_PATTERNS = {
    "HIGH": [
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "encodedcommand",
    ],
    "MEDIUM": [
        "\\temp\\",
        "\\appdata\\roaming\\",
        "\\programdata\\",
        "\\users\\public\\",
    ],
    "LOW": [
        "\\appdata\\local\\",
    ],
}


def analyze_entry(name, data):
    """Analyze one registry entry and return risk and reason."""

    text = f"{name} {data}".lower()

    for pattern in SUSPICIOUS_PATTERNS["HIGH"]:
        if pattern in text:
            return "HIGH", f"Matched '{pattern}'"

    for pattern in SUSPICIOUS_PATTERNS["MEDIUM"]:
        if pattern in text:
            return "MEDIUM", f"Matched '{pattern}'"

    for pattern in SUSPICIOUS_PATTERNS["LOW"]:
        if pattern in text:
            return "LOW", f"Matched '{pattern}'"

    return "SAFE", "No suspicious pattern"


def run_analysis():
    """Analyze the actual monitored Windows Registry locations."""

    print()
    print("=" * 80)
    print("SUSPICIOUS REGISTRY ANALYSIS")
    print("=" * 80)

    summary = {
        "SAFE": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
    }

    for registry_key in MONITORED_KEYS:

        print()
        print("-" * 80)
        print(f"KEY: {registry_key['name']}")
        print(f"PATH: {registry_key['path']}")
        print("-" * 80)

        values = read_registry_values(
            registry_key["root"],
            registry_key["path"]
        )

        if not values:
            print("No entries found.")
            continue

        for value_name, value_info in values.items():

            risk, reason = analyze_entry(
                value_name,
                value_info["data"]
            )

            summary[risk] += 1

            print(f"Name  : {value_name}")
            print(f"Risk  : {risk}")
            print(f"Reason: {reason}")
            print("-" * 40)

    print()
    print("=" * 80)
    print("ANALYSIS SUMMARY")
    print("=" * 80)

    print(f"Safe entries : {summary['SAFE']}")
    print(f"Low risk     : {summary['LOW']}")
    print(f"Medium risk  : {summary['MEDIUM']}")
    print(f"High risk    : {summary['HIGH']}")

    print("=" * 80)


def demo_suspicious_detection():
    """Safely demonstrate the detection logic without modifying the Registry."""

    print()
    print("=" * 80)
    print("SAFE MALWARE DETECTION DEMO")
    print("=" * 80)

    demo_entries = {
        "PowerShellPayload": r"powershell.exe -EncodedCommand ABC123",

        "TempExecutable": (
            r"C:\Users\User\AppData\Local\Temp\malware.exe"
        ),

        "NormalChrome": (
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        ),
    }

    summary = {
        "SAFE": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
    }

    for name, data in demo_entries.items():

        risk, reason = analyze_entry(name, data)

        summary[risk] += 1

        print()
        print(f"Name  : {name}")
        print(f"Data  : {data}")
        print(f"Risk  : {risk}")
        print(f"Reason: {reason}")

    print()
    print("-" * 80)
    print("DEMO SUMMARY")
    print("-" * 80)

    print(f"Safe   : {summary['SAFE']}")
    print(f"Low    : {summary['LOW']}")
    print(f"Medium : {summary['MEDIUM']}")
    print(f"High   : {summary['HIGH']}")

    print("=" * 80)


# IMPORTANT:
# This must be at the VERY BOTTOM of the file.
if __name__ == "__main__":
    run_analysis()
def demo_suspicious_detection():

    print()
    print("=" * 80)
    print("SAFE MALWARE DETECTION DEMO")
    print("=" * 80)

    demo_entries = {
        "PowerShellPayload":
            r"powershell.exe -EncodedCommand ABC123",

        "TempExecutable":
            r"C:\Users\User\AppData\Local\Temp\malware.exe",

        "NormalChrome":
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    }

    summary = {
        "SAFE": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
    }

    for name, data in demo_entries.items():

        risk, reason = analyze_entry(name, data)

        summary[risk] += 1

        print(f"\n{name}")
        print(f"Risk : {risk}")
        print(f"Reason: {reason}")

    print()
    print("-" * 80)
    print("DEMO SUMMARY")
    print("-" * 80)
    print(f"Safe   : {summary['SAFE']}")
    print(f"Low    : {summary['LOW']}")
    print(f"Medium : {summary['MEDIUM']}")
    print(f"High   : {summary['HIGH']}")
    print("=" * 80)
