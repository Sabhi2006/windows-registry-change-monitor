import winreg


def get_registry_type_name(value_type):
    """Convert a Windows Registry type number into a readable name."""

    registry_types = {
        winreg.REG_SZ: "REG_SZ",
        winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
        winreg.REG_BINARY: "REG_BINARY",
        winreg.REG_DWORD: "REG_DWORD",
        winreg.REG_QWORD: "REG_QWORD",
        winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
    }

    return registry_types.get(value_type, f"UNKNOWN ({value_type})")


def read_registry_key(root_key, sub_key):
    """Read and display all values from a Windows Registry key."""

    try:
        with winreg.OpenKey(root_key, sub_key, 0, winreg.KEY_READ) as key:

            print()
            print("=" * 80)
            print(f"REGISTRY KEY: {sub_key}")
            print("=" * 80)

            index = 0
            value_count = 0

            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(
                        key, index
                    )

                    type_name = get_registry_type_name(value_type)

                    print(f"Name : {value_name}")
                    print(f"Data : {value_data}")
                    print(f"Type : {type_name}")
                    print("-" * 80)

                    index += 1
                    value_count += 1

                except OSError:
                    break

            print(f"Total values found: {value_count}")
            return value_count
    except FileNotFoundError:
        print(f"Registry key not found: {sub_key}")
        return 0
    except PermissionError:
        print(f"Permission denied: {sub_key}")
        return 0
    except OSError as error:
        print(f"Registry error: {error}")
        return 0

if __name__ == "__main__":

    print("\nWINDOWS REGISTRY READER")
    print("=" * 80)

    results = {}

    results["HKCU Run"] = read_registry_key(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run"
    )

    results["HKCU RunOnce"] = read_registry_key(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    results["HKLM Run"] = read_registry_key(
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows\CurrentVersion\Run"
    )

    results["HKLM RunOnce"] = read_registry_key(
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    print("\n")
    print("=" * 80)
    print("REGISTRY MONITORING SUMMARY")
    print("=" * 80)

    total_values = 0

    for location, count in results.items():
        print(f"{location:<20}: {count} values")
        total_values += count

    print("-" * 80)
    print(f"{'Total Registry Values':<20}: {total_values}")
    print("=" * 80)