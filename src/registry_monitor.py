import subprocess
import sys


def run_module(module_name):
    print()
    print("=" * 80)
    print(f"RUNNING: {module_name}")
    print("=" * 80)

    result = subprocess.run(
        [sys.executable, module_name],
        capture_output=False
    )

    if result.returncode != 0:
        print(f"\nERROR: {module_name} failed.")
        return False

    print(f"\nCOMPLETED: {module_name}")
    return True


def main():
    print("=" * 80)
    print("WINDOWS REGISTRY SECURITY MONITOR")
    print("=" * 80)

    modules = [
        "src/registry_reader.py",
        "src/change_detector.py",
        "src/suspicious_detector.py",
        "src/integrity_checker.py"
    ]

    for module in modules:
        if not run_module(module):
            print("\nMonitoring stopped because a module failed.")
            return

    print()
    print("=" * 80)
    print("REGISTRY MONITORING COMPLETED")
    print("=" * 80)


if __name__ == "__main__":
    main()