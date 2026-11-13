import sqlite3
import os

print("Resetting VETO Demo Data...")

dbs = [
    "audit.db",
    "approvals.db", # Might be inside engine depending on config
    "replay.db"
]

# Often they share the same DB paths, or the user's config specifies them.
# The default DB files are audit.db, test_*.db etc.
# Actually, the Approval engine hardcodes 'approvals.db' or uses self.db_path
# We will just delete all .db files that are not test fixtures.

for f in os.listdir("."):
    if f.endswith(".db") and not f.startswith("test_") and not f.startswith("runner_"):
        try:
            os.remove(f)
            print(f"Deleted {f}")
        except Exception as e:
            print(f"Could not delete {f}: {e}")

print("Demo state reset successfully. Please restart the backend API to re-initialize SQLite tables.")
