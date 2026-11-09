from getpass import getpass

from backend.services.auth_service import create_user

print("=== PCSIRM Administrator Setup ===")

username = input("Enter administrator username: ").strip()
password = getpass("Enter administrator password: ")
confirm_password = getpass("Confirm administrator password: ")

if password != confirm_password:
    print("Error: Passwords do not match.")
    raise SystemExit(1)

try:
    create_user(username, password, role="admin")
    print(f"Administrator account '{username}' created successfully.")

except ValueError as error:
    print(f"Error: {error}")

except Exception:
    print("Could not create administrator. The username may already exist.")
