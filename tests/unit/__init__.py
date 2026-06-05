"""Unit-test package — sets the THREATRAY_* env defaults before any test module
imports `threatray_mcp.*`. pydantic-settings reads these once at module import
time when `Settings()` is constructed in `threatray_mcp.config`.

unittest's TestLoader discovers tests by importing this package, so this runs
before any test file. We overwrite empty values too because docker-compose
passes `THREATRAY_API_URL: ${THREATRAY_API_URL:-}` which materializes as an
empty string when the shell var is unset — setdefault() would leave the empty
string in place and break every client-section test.
"""

import os

if not os.environ.get("THREATRAY_API_URL"):
    os.environ["THREATRAY_API_URL"] = "https://api.threatray.test"
if not os.environ.get("THREATRAY_API_KEY"):
    os.environ["THREATRAY_API_KEY"] = "test-key"
