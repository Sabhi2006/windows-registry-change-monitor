from baseline import MONITORED_KEYS, read_registry_values
from suspicious_detector import analyze_entry


REPORT_FILE = "reports/security_report.txt"


def generate_security_report():
    """Generate a security report from the current Registry analysis."""

    print()
    print("=" * 80)
    print("SECURITY REPORT GENERATOR")
    print("=" * 80)

    summary = {
        "SAFE": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
    }

    findings = []

    for registry_key in MONITORED_KEYS:

        values = read_registry_values(
            registry_key["root"],
            registry_key["path"]
        )

        for value_name, value_info in values.items():

            risk, reason = analyze_entry(
                value_name,
                value_info["data"]
            )

            summary[risk] += 1

            findings.append({
                "key": registry_key["name"],
                "path": registry_key["path"],
                "name": value_name,
                "data": value_info["data"],
                "risk": risk,
                "reason": reason,
            })

    with open(REPORT_FILE, "w", encoding="utf-8") as report:

        report.write("=" * 80 + "\n")
        report.write("WINDOWS REGISTRY SECURITY REPORT\n")
        report.write("=" * 80 + "\n\n")

        for finding in findings:

            report.write("-" * 80 + "\n")
            report.write(f"Registry Key : {finding['key']}\n")
            report.write(f"Path         : {finding['path']}\n")
            report.write(f"Name         : {finding['name']}\n")
            report.write(f"Data         : {finding['data']}\n")
            report.write(f"Risk         : {finding['risk']}\n")
            report.write(f"Reason       : {finding['reason']}\n")

        report.write("\n")
        report.write("=" * 80 + "\n")
        report.write("SECURITY SUMMARY\n")
        report.write("=" * 80 + "\n")

        report.write(f"Safe entries : {summary['SAFE']}\n")
        report.write(f"Low risk     : {summary['LOW']}\n")
        report.write(f"Medium risk  : {summary['MEDIUM']}\n")
        report.write(f"High risk    : {summary['HIGH']}\n")

        report.write("=" * 80 + "\n")

    print()
    print("-" * 80)
    print("SECURITY REPORT SUMMARY")
    print("-" * 80)
    print(f"Safe entries : {summary['SAFE']}")
    print(f"Low risk     : {summary['LOW']}")
    print(f"Medium risk  : {summary['MEDIUM']}")
    print(f"High risk    : {summary['HIGH']}")
    print("-" * 80)
    print(f"Report saved to: {REPORT_FILE}")
    print("=" * 80)


if __name__ == "__main__":
    generate_security_report()