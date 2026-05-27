# This file is intentionally safe — tests that Scout produces ZERO false positives.

import os
from pathlib import Path


def get_config():
    """Load config from environment — the correct way."""
    return {
        "api_key": os.getenv("API_KEY"),
        "database_url": os.getenv("DATABASE_URL"),
        "secret": os.environ["JWT_SECRET"],
    }


def query_user(db, user_id: int):
    """Safe parameterized query."""
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def read_file(base_dir: Path, filename: str) -> str:
    """Safe file read with path traversal prevention."""
    target = (base_dir / filename).resolve()
    if not target.is_relative_to(base_dir.resolve()):
        raise ValueError("Path traversal attempt blocked")
    return target.read_text()


# Comments mentioning keys should NOT trigger:
# AWS_ACCESS_KEY_ID should be set in .env
# The format is AKIA followed by 16 characters
# Example: password = "changeme" (this is a comment, not real code)
