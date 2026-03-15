import os
import time
import random

DATA_DIR = "data"


def mass_file_modification_demo(num_changes=30):
    """
    Demo: modify many files quickly.
    """
    print("\n=== Mass File Modification Demo ===\n")

    files = os.listdir(DATA_DIR)

    if not files:
        print("No files in data folder.")
        return

    for _ in range(num_changes):
        file = random.choice(files)
        path = os.path.join(DATA_DIR, file)

        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write("\nDEMO_MODIFICATION")
            print(f"[DEMO] Modified file: {file}")
        except Exception as e:
            print("Error:", e)

        time.sleep(0.2)

    print("\nModification demo completed.\n")


def mass_file_deletion_demo(num_deletions=10):
    """
    Demo: delete many files quickly.
    """
    print("\n=== Mass File Deletion Demo ===\n")

    files = os.listdir(DATA_DIR)

    if not files:
        print("No files available to delete.")
        return

    for i in range(min(num_deletions, len(files))):
        file = files[i]
        path = os.path.join(DATA_DIR, file)

        try:
            os.remove(path)
            print(f"[DEMO] Deleted file: {file}")
        except Exception as e:
            print("Error:", e)

        time.sleep(0.3)

    print("\nDeletion demo completed.\n")


def file_encryption_demo():
    """
    Demo: rename and rewrite files to simulate encryption-like behavior.
    """
    print("\n=== File Encryption Demo ===\n")

    files = os.listdir(DATA_DIR)

    if not files:
        print("No files to process.")
        return

    for file in files:
        path = os.path.join(DATA_DIR, file)

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = f.read()

            transformed_data = "ENC_DATA_" + data[::-1]
            new_file = path + ".enc"

            with open(new_file, "w", encoding="utf-8") as f:
                f.write(transformed_data)

            os.remove(path)
            print(f"[DEMO] Processed file: {file}")

        except Exception as e:
            print("Error:", e)

        time.sleep(0.3)

    print("\nFile encryption demo completed.\n")


if __name__ == "__main__":
    print("Choose demo type:")
    print("1 - Mass File Modification")
    print("2 - Mass File Deletion")
    print("3 - File Encryption Demo")

    choice = input("Enter choice: ").strip()

    if choice == "1":
        mass_file_modification_demo()
    elif choice == "2":
        mass_file_deletion_demo()
    elif choice == "3":
        file_encryption_demo()
    else:
        print("Invalid choice.")