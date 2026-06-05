import os
import sys
import unittest

import coverage

# Compose passes THREATRAY_API_KEY/URL through with `${VAR:-}`, which expands
# to an empty string when unset on the host. The per-test `setdefault` then
# no-ops and respx mocks (registered against API_BASE) miss because requests
# go out with no host. Normalize before any test module imports.
for _var, _default in (
    ("THREATRAY_API_KEY", "test-key"),
    ("THREATRAY_API_URL", "https://api.threatray.test"),
):
    if not os.environ.get(_var):
        os.environ[_var] = _default

cov = coverage.coverage(
    data_file=None,
    branch=True,
    include="./src/threatray_mcp/*",
    omit=[
        "./tests/*",
    ],
)
cov.start()

tests = unittest.TestLoader().discover("tests/unit", top_level_dir=".")
result = unittest.TextTestRunner(verbosity=2).run(tests)

if result.wasSuccessful():
    cov.stop()
    cov.report()
    cov.xml_report(outfile="./tests/coverage/coverage.xml")
else:
    sys.exit(1)
