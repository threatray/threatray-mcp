"""CapaClient tests — covers trigger-if-missing and the not-found vs trigger paths."""

import re
import unittest

import httpx
import respx

from threatray_mcp.client import CapaClient
from threatray_mcp.client._http import HttpClient
from threatray_mcp.errors import ThreatrayNotFound
from threatray_mcp.models import CapaInput

API_BASE = "https://api.threatray.test"
SHA = "a" * 64
JOB_ID = "00000000-0000-0000-0000-0000000000aa"

class TestCapaClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.async_client = httpx.AsyncClient()
        self.http = HttpClient(http_client=self.async_client)
        self.client = CapaClient(self.http, poll_interval=0, timeout=10)

    async def asyncTearDown(self):
        await self.async_client.aclose()

    @respx.mock
    async def test_get_existing_results_returns_payload(self):
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(
            return_value=httpx.Response(200, json={"capabilities": {"rules": {}}})
        )
        result = await self.client.get(SHA, trigger_if_missing=False)
        self.assertEqual(result, {"capabilities": {"rules": {}}})

    @respx.mock
    async def test_get_404_without_trigger_states_the_absence_and_names_the_opt_in(self):
        """A file with no CAPA analysis is an ordinary state, not a fault. The
        message is pinned in full: no assertIn/assertNotIn pair catches text
        appended after the asserted phrase, and what must never be appended here
        is a retry instruction.
        """
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(return_value=httpx.Response(404))
        create = respx.post(f"{API_BASE}/v1/capa-analysis/jobs")
        with self.assertRaises(ThreatrayNotFound) as ctx:
            await self.client.get(SHA, trigger_if_missing=False)
        self.assertEqual(
            " ".join(str(ctx.exception).split()),
            "No CAPA analysis exists for this file. This call was made with "
            "trigger_if_missing=false, so none was created. To create one, call "
            "threatray_get_capa with trigger_if_missing=true; a file that already has a "
            "job reuses it rather than starting a second.",
        )
        # The caller opted out, so nothing may be created behind their back.
        self.assertEqual(create.call_count, 0)

    @respx.mock
    async def test_capa_absence_message_only_names_parameters_that_exist(self):
        """The message hard-codes a parameter name. Nothing otherwise ties it to
        the real field, so renaming `trigger_if_missing` would leave the message
        telling agents to pass one that no longer exists — and every other test
        here would still pass. The AI client has this link; CAPA lacked it."""
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(return_value=httpx.Response(404))
        with self.assertRaises(ThreatrayNotFound) as ctx:
            await self.client.get(SHA, trigger_if_missing=False)
        named = {name for name in re.findall(r"\b(\w+)=\w+", str(ctx.exception))}
        self.assertTrue(named, "expected the message to name at least one parameter")
        self.assertTrue(
            named <= set(CapaInput.model_fields),
            f"message names parameters that are not fields of CapaInput: {named - set(CapaInput.model_fields)}",
        )

    @respx.mock
    async def test_opt_out_creates_nothing_even_when_trigger_only_is_set(self):
        """`trigger_if_missing` is read before `trigger_only`, which is what makes
        the message's advice correct. Pin the ordering behaviourally: if the two
        branches were ever swapped, this call would create a job despite the
        caller opting out, and nothing else here would notice."""
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(return_value=httpx.Response(404))
        create = respx.post(f"{API_BASE}/v1/capa-analysis/jobs")
        with self.assertRaises(ThreatrayNotFound):
            await self.client.get(SHA, trigger_if_missing=False, trigger_only=True)
        self.assertEqual(create.call_count, 0)

    @respx.mock
    async def test_capa_opt_out_advice_actually_escapes_the_error(self):
        """Following the advice must reach a different outcome. `trigger_if_missing`
        is read before `trigger_only`, exactly as in the AI client, so advice naming
        only `trigger_only` would return this same message — naming
        `trigger_if_missing=true` is what actually escapes it."""
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(
            side_effect=[
                httpx.Response(404),
                httpx.Response(200, json={"capabilities": {"rules": {}}}),
            ]
        )
        create = respx.post(f"{API_BASE}/v1/capa-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": JOB_ID, "job_status": "DONE"})
        )
        respx.get(f"{API_BASE}/v1/capa-analysis/jobs/{JOB_ID}").mock(
            return_value=httpx.Response(200, json={"job_id": JOB_ID, "job_status": "DONE"})
        )
        result = await self.client.get(SHA, trigger_if_missing=True)
        self.assertEqual(create.call_count, 1)
        self.assertEqual(result, {"capabilities": {"rules": {}}})

    @respx.mock
    async def test_get_404_with_trigger_creates_job_and_fetches(self):
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(
            side_effect=[
                httpx.Response(404),
                httpx.Response(200, json={"capabilities": {"rules": {"r1": {}}}}),
            ]
        )
        respx.post(f"{API_BASE}/v1/capa-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": 99, "job_status": "QUEUED"})
        )
        respx.get(f"{API_BASE}/v1/capa-analysis/jobs/99").mock(
            return_value=httpx.Response(200, json={"job_id": 99, "job_status": "DONE"})
        )
        result = await self.client.get(SHA, trigger_if_missing=True)
        self.assertIn("capabilities", result)

    @respx.mock
    async def test_trigger_only_returns_job_without_polling(self):
        """trigger_only=True: enqueue the job, return immediately, no /jobs/{id} call."""
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(return_value=httpx.Response(404))
        post_route = respx.post(f"{API_BASE}/v1/capa-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": 99, "job_status": "QUEUED"})
        )
        result = await self.client.get(SHA, trigger_if_missing=True, trigger_only=True)
        self.assertEqual(result["pending"], True)
        self.assertEqual(result["job"]["job_id"], 99)
        self.assertEqual(post_route.call_count, 1)

    @respx.mock
    async def test_get_job_returns_status(self):
        """get_job delegates to the poller's job URL and returns the raw payload."""
        route = respx.get(f"{API_BASE}/v1/capa-analysis/jobs/{JOB_ID}").mock(
            return_value=httpx.Response(
                200, json={"job_id": JOB_ID, "file_hash": SHA, "job_status": "PROCESSING"}
            )
        )
        result = await self.client.get_job(JOB_ID)
        self.assertEqual(result["job_status"], "PROCESSING")
        self.assertEqual(route.call_count, 1)

    @respx.mock
    async def test_get_job_404_names_the_id_without_claiming_a_cause(self):
        """A job-route 404 is ambiguous (unknown id vs route absent for this realm),
        so the message names the id but must not assert a cause."""
        respx.get(f"{API_BASE}/v1/capa-analysis/jobs/{JOB_ID}").mock(return_value=httpx.Response(404))
        with self.assertRaises(ThreatrayNotFound) as ctx:
            await self.client.get_job(JOB_ID)
        message = str(ctx.exception)
        self.assertIn(JOB_ID, message)
        self.assertIn("No CAPA job found for id", message)
        # Assert the remap positively, and that the generic mapper's text is
        # fully replaced. The old form checked only for the absence of
        # "Resource not found", which stopped testing its intent the moment that
        # base string changed — the remap could have been dropped entirely and
        # this test would still have passed.
        self.assertNotIn("Not found: GET", message)
