"""Integration-test package — same env-defaults trick as the unit package.
unittest's TestLoader imports this before discovering any test module, so the
env is set before `threatray_mcp.config` is loaded.

Empty values are overwritten (not just absent) because docker-compose passes
`THREATRAY_API_URL: ${THREATRAY_API_URL:-}` which materializes as `''` when
unset — setdefault() would leave the empty string in place.
"""

import os

if not os.environ.get("THREATRAY_API_URL"):
    os.environ["THREATRAY_API_URL"] = "https://api.threatray.test"
if not os.environ.get("THREATRAY_API_KEY"):
    os.environ["THREATRAY_API_KEY"] = "test-key"
