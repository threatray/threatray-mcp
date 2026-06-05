import os
import sys
import unittest

# Compose passes THREATRAY_API_KEY/URL through with `${VAR:-}`, which expands
# to an empty string when unset on the host. `setdefault` treats empty as
# "already set" and the lifespan check then rejects the empty value — so
# normalize here before any test module imports the server.
for _var, _default in (
    ("THREATRAY_API_KEY", "test-key"),
    ("THREATRAY_API_URL", "https://api.threatray.test"),
):
    if not os.environ.get(_var):
        os.environ[_var] = _default

tests = unittest.TestLoader().discover("tests/integration", top_level_dir=".")
result = unittest.TextTestRunner(verbosity=2).run(tests)

if not result.wasSuccessful():
    sys.exit(1)
