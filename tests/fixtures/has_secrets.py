# This file is intentionally insecure — used for testing Scout scanners.
# DO NOT use this code in production.
# NOTE: Provider-specific secrets (AWS, Stripe, GitHub, Slack) are tested
# with inline content in test_secrets.py to avoid GitHub Push Protection blocks.

# Database URL with embedded password (CRITICAL)
DATABASE_URL = "postgres://admin:supersecretpass123@prod-db.example.com:5432/myapp"

# JWT secret (HIGH)
JWT_SECRET = "my-super-secret-jwt-key-that-should-not-be-here"

# Generic API key (HIGH)
api_key = "abcdef1234567890abcdef1234567890"

# Password in variable (HIGH)
password = "admin123456"
