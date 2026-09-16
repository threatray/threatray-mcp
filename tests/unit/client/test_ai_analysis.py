"""AiAnalysisClient tests — covers realm-gating mapping, trigger-if-missing, trigger-only,
get-by-id and get-latest-job."""

import json
import re
import unittest
from itertools import pairwise

import httpx
import respx

from threatray_mcp.client import AiAnalysisClient
from threatray_mcp.client._http import HttpClient
from threatray_mcp.errors import ThreatrayFeatureUnavailable, ThreatrayJobFailed, ThreatrayNotFound
from threatray_mcp.models import AiAnalysisInput

API_BASE = "https://api.threatray.test"
SHA = "f" * 64


class TestAiAnalysisClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.async_client = httpx.AsyncClient()
        self.http = HttpClient(http_client=self.async_client)
        self.client = AiAnalysisClient(self.http, poll_interval=0)

    async def asyncTearDown(self):
        await self.async_client.aclose()

    @respx.mock
    async def test_get_existing_results_returns_first(self):
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(
            return_value=httpx.Response(200, json={"results": [{"id": "abc", "summary": "..."}]})
        )
        result = await self.client.get(SHA, trigger_if_missing=False)
        self.assertEqual(result["id"], "abc")

    @respx.mock
    async def test_get_404_maps_to_feature_unavailable(self):
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(return_value=httpx.Response(404))
        with self.assertRaises(ThreatrayFeatureUnavailable):
            await self.client.get(SHA, trigger_if_missing=False)

    @respx.mock
    async def test_get_empty_results_without_trigger_raises_not_found(self):
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(return_value=httpx.Response(200, json={"results": []}))
        with self.assertRaises(ThreatrayNotFound) as ctx:
            await self.client.get(SHA, trigger_if_missing=False)
        message = str(ctx.exception)
        # The absence is the answer; the creating call is offered but kept
        # optional, because this caller explicitly asked not to create one.
        self.assertIn("No AI analysis results exist for this file", message)
        # Pin the conjunction, not the two tokens: asserting them separately
        # passes an "or", which sends the caller back into this same message.
        self.assertIn("trigger_if_missing=true and trigger_only=true", " ".join(message.split()))

    @respx.mock
    async def test_absence_messages_only_name_parameters_that_exist(self):
        """The messages hard-code tool parameter names. Nothing otherwise ties
        them to the real fields, so renaming one would leave a message telling
        agents to pass a parameter that no longer exists — and every other test
        here would still pass. This is that link."""
        fields = set(AiAnalysisInput.model_fields)
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(return_value=httpx.Response(200, json={"results": []}))
        respx.get(f"{API_BASE}/v1/ai-analysis/jobs/latest").mock(return_value=httpx.Response(404))

        messages = []
        with self.assertRaises(ThreatrayNotFound) as ctx:
            await self.client.get(SHA, trigger_if_missing=False)
        messages.append(str(ctx.exception))
        with self.assertRaises(ThreatrayNotFound) as ctx:
            await self.client.get_latest_job(SHA)
        messages.append(str(ctx.exception))

        named = {name for m in messages for name in re.findall(r"\b(\w+)=\w+", m)}
        self.assertTrue(named, "expected the messages to name at least one parameter")
        self.assertTrue(
            named <= fields,
            f"messages name parameters that are not fields of AiAnalysisInput: {named - fields}",
        )

    @respx.mock
    async def test_no_trigger_advice_actually_escapes_the_error(self):
        """Following the message must reach a different outcome. Adding only
        `trigger_only=True` does not: `trigger_if_missing` is evaluated first, so
        the call returns the identical error and never posts a job."""
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(return_value=httpx.Response(200, json={"results": []}))
        post = respx.post(f"{API_BASE}/v1/ai-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": "j1", "job_status": "QUEUED"})
        )
        with self.assertRaises(ThreatrayNotFound):
            await self.client.get(SHA, trigger_if_missing=False, trigger_only=True)
        self.assertEqual(post.call_count, 0, "trigger_only alone must not create a job")

        # With both flags, as the message instructs, the job is created.
        result = await self.client.get(SHA, trigger_if_missing=True, trigger_only=True)
        self.assertEqual(post.call_count, 1)
        self.assertTrue(result.get("pending"))

    @respx.mock
    async def test_list_results_404_maps_to_feature_unavailable(self):
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(return_value=httpx.Response(404))
        with self.assertRaises(ThreatrayFeatureUnavailable):
            await self.client.list_results(SHA)

    @respx.mock
    async def test_list_results_200_returns_payload(self):
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(
            return_value=httpx.Response(200, json={"results": [{"id": "x"}]})
        )
        result = await self.client.list_results(SHA)
        self.assertEqual(result, {"results": [{"id": "x"}]})

    @respx.mock
    async def test_trigger_flow_fetches_exact_completed_result(self):
        result_id = "00000000-0000-0000-0000-000000000001"
        results_route = respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        respx.post(f"{API_BASE}/v1/ai-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": "j1", "job_status": "QUEUED"})
        )
        respx.get(f"{API_BASE}/v1/ai-analysis/jobs/j1").mock(
            return_value=httpx.Response(
                200,
                json={"job_id": "j1", "job_status": "DONE", "result_id": result_id},
            )
        )
        result_route = respx.get(f"{API_BASE}/v1/ai-analysis/results/{result_id}").mock(
            return_value=httpx.Response(200, json={"id": result_id, "assessment": "fresh"})
        )
        result = await self.client.get(SHA, trigger_if_missing=True, max_wait_seconds=30)
        self.assertEqual(result["id"], result_id)
        self.assertEqual(results_route.call_count, 1)
        self.assertEqual(result_route.call_count, 1)

    @respx.mock
    async def test_completion_without_a_result_id_fails_rather_than_guessing(self):
        """Pins the refusal. A completed job with no result reference fails rather
        than falling back to the listing, whose first entry need not be the analysis
        this call produced. Adding that fallback is what #26 proposed."""
        listing = respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(
            side_effect=[
                httpx.Response(200, json={"results": []}),
                # Present and plausible, so the test fails if anything reaches for it.
                httpx.Response(200, json={"results": [{"id": "some-other-analysis"}]}),
            ]
        )
        respx.post(f"{API_BASE}/v1/ai-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": "j1", "job_status": "QUEUED"})
        )
        respx.get(f"{API_BASE}/v1/ai-analysis/jobs/j1").mock(
            return_value=httpx.Response(200, json={"job_id": "j1", "job_status": "DONE"})
        )

        with self.assertRaises(ThreatrayJobFailed) as ctx:
            await self.client.get(SHA, trigger_if_missing=True, max_wait_seconds=30)

        self.assertIn("no results were returned", str(ctx.exception))
        # Only the initial existence check may have hit the listing — never a
        # second, post-completion read.
        self.assertEqual(listing.call_count, 1)

    @respx.mock
    async def test_trigger_flow_reports_strict_progress_across_stage_lifecycle(self):
        result_id = "00000000-0000-0000-0000-00000000beef"
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        respx.get(f"{API_BASE}/v1/ai-analysis/results/{result_id}").mock(
            return_value=httpx.Response(200, json={"id": result_id, "assessment": "fresh"})
        )
        respx.post(f"{API_BASE}/v1/ai-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": "j1", "job_status": "QUEUED"})
        )
        respx.get(f"{API_BASE}/v1/ai-analysis/jobs/j1").mock(
            side_effect=[
                httpx.Response(
                    200,
                    json={"job_id": "j1", "job_status": "PROCESSING", "stage": "PREPARING"},
                ),
                httpx.Response(
                    200,
                    json={"job_id": "j1", "job_status": "PROCESSING", "stage": "DECOMPILING"},
                ),
                httpx.Response(
                    200,
                    json={
                        "job_id": "j1",
                        "job_status": "PROCESSING",
                        "stage": "ANALYZING",
                        "started_at": "2026-08-17T10:00:00Z",
                        "remaining_time_estimate": {
                            "minimum_seconds": 42,
                            "maximum_seconds": 96,
                        },
                    },
                ),
                httpx.Response(
                    200,
                    json={"job_id": "j1", "job_status": "PROCESSING", "stage": "SYNTHESIZING"},
                ),
                httpx.Response(200, json={"job_id": "j1", "job_status": "DONE", "result_id": result_id}),
            ]
        )
        updates: list[tuple[float, str]] = []

        async def progress_callback(progress: float, message: str) -> None:
            updates.append((progress, message))

        await self.client.get(
            SHA,
            trigger_if_missing=True,
            max_wait_seconds=30,
            progress_callback=progress_callback,
        )

        self.assertEqual(
            [progress for progress, _ in updates],
            [float(value) for value in range(1, 10)],
        )
        messages = [message for _, message in updates]
        self.assertIn("Preparing analysis · Step 1 of 4", messages[3])
        self.assertIn("Decompiling code · Step 2 of 4", messages[4])
        self.assertIn("Analyzing functions · Step 3 of 4 · 40s\N{EN DASH}2m left", messages[5])
        self.assertIn("Finalizing results · Step 4 of 4", messages[6])
        self.assertEqual(messages[7:], ["AI analysis: Complete", "Fetching results..."])

    @respx.mock
    async def test_progress_stays_strict_when_stages_repeat_regress_or_are_unknown(self):
        result_id = "00000000-0000-0000-0000-000000000001"
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(return_value=httpx.Response(200, json={"results": []}))
        respx.post(f"{API_BASE}/v1/ai-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": "j1", "job_status": "QUEUED"})
        )
        respx.get(f"{API_BASE}/v1/ai-analysis/jobs/j1").mock(
            side_effect=[
                httpx.Response(
                    200,
                    json={"job_id": "j1", "job_status": "PROCESSING", "stage": "PREPARING"},
                ),
                httpx.Response(
                    200,
                    json={"job_id": "j1", "job_status": "PROCESSING", "stage": "PREPARING"},
                ),
                httpx.Response(
                    200,
                    json={"job_id": "j1", "job_status": "PROCESSING", "stage": "NEW_STAGE"},
                ),
                httpx.Response(
                    200,
                    json={"job_id": "j1", "job_status": "PROCESSING", "stage": "ANALYZING"},
                ),
                httpx.Response(
                    200,
                    json={"job_id": "j1", "job_status": "PROCESSING", "stage": "PREPARING"},
                ),
                httpx.Response(
                    200,
                    json={"job_id": "j1", "job_status": "DONE", "result_id": result_id},
                ),
            ]
        )
        respx.get(f"{API_BASE}/v1/ai-analysis/results/{result_id}").mock(
            return_value=httpx.Response(200, json={"id": result_id, "assessment": "fresh"})
        )
        updates: list[tuple[float, str]] = []

        async def progress_callback(progress: float, message: str) -> None:
            updates.append((progress, message))

        await self.client.get(
            SHA,
            trigger_if_missing=True,
            max_wait_seconds=30,
            progress_callback=progress_callback,
        )

        progress_values = [progress for progress, _ in updates]
        self.assertEqual(progress_values, [float(value) for value in range(1, len(updates) + 1)])
        self.assertTrue(all(current < following for current, following in pairwise(progress_values)))
        messages = [message for _, message in updates]
        self.assertEqual(sum("Preparing analysis · Step 1 of 4" in message for message in messages), 3)
        self.assertTrue(any(message == "AI analysis: Analyzing" for message in messages))

    @respx.mock
    async def test_trigger_only_returns_job_without_polling(self):
        """trigger_only=True: enqueue the job, return immediately, no /jobs/{id} call."""
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(return_value=httpx.Response(200, json={"results": []}))
        post_route = respx.post(f"{API_BASE}/v1/ai-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": "j1", "job_status": "QUEUED"})
        )
        # If the client polls /jobs/{id} the test should fail — respx-strict by default.
        result = await self.client.get(SHA, trigger_if_missing=True, trigger_only=True)
        self.assertEqual(result["pending"], True)
        self.assertEqual(result["job"]["job_id"], "j1")
        self.assertEqual(post_route.call_count, 1)

    @respx.mock
    async def test_create_job_posts_only_file_hash(self):
        """function_addresses + max_functions are not exposed to agents; the
        client must not leak them onto the POST body either."""
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(return_value=httpx.Response(200, json={"results": []}))
        post_route = respx.post(f"{API_BASE}/v1/ai-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": "j1", "job_status": "QUEUED"})
        )
        await self.client.get(SHA, trigger_if_missing=True, trigger_only=True)
        body = json.loads(post_route.calls[0].request.content)
        self.assertEqual(body, {"file_hash": SHA})

    @respx.mock
    async def test_get_result_by_id(self):
        aid = "00000000-0000-0000-0000-000000000001"
        respx.get(f"{API_BASE}/v1/ai-analysis/results/{aid}").mock(
            return_value=httpx.Response(200, json={"id": aid, "summary": "..."})
        )
        result = await self.client.get_result_by_id(aid)
        self.assertEqual(result["id"], aid)

    @respx.mock
    async def test_get_result_by_id_404_names_the_id_and_the_job_confusion(self):
        """Job ids and result ids are both UUIDs, so a job id sent here 404s
        exactly like a stale result id. The message must name the id and the
        confusion — and must not tell an agent to go checking input it never
        chose, because `get()` and the tool both pass ids they obtained
        themselves."""
        aid = "00000000-0000-0000-0000-0000000000ff"
        respx.get(f"{API_BASE}/v1/ai-analysis/results/{aid}").mock(return_value=httpx.Response(404))
        with self.assertRaises(ThreatrayNotFound) as ctx:
            await self.client.get_result_by_id(aid)
        message = str(ctx.exception)
        self.assertIn(aid, message)
        self.assertIn("threatray_list_ai_analyses", message)
        # Pin the whole closing clause. Matching only "takes the file's SHA256"
        # passes a message that still directs a job id at a file-hash tool.
        self.assertIn(
            "no tool here looks up an AI job by id — threatray_get_latest_ai_job "
            "takes the file's SHA256.",
            " ".join(message.split()),
        )
        self.assertNotIn("Not found: GET", message)

    @respx.mock
    async def test_absence_messages_are_pinned_in_full(self):
        """The AI absence messages are pinned verbatim, deliberately.

        The CAPA one is pinned the same way, in tests/unit/client/test_capa.py.

        No assertIn/assertNotIn pair catches text *appended* after the asserted
        phrase, and appending "retry this call until a job appears." is the exact
        loop this change removes. Editing any of them is meant to fail here —
        update the expected text deliberately, having re-checked that each claim
        is still true and that nothing appended re-instructs a retry.
        """
        aid = "00000000-0000-0000-0000-0000000000ff"
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        respx.get(f"{API_BASE}/v1/ai-analysis/jobs/latest").mock(return_value=httpx.Response(404))
        respx.get(f"{API_BASE}/v1/ai-analysis/results/{aid}").mock(return_value=httpx.Response(404))

        with self.assertRaises(ThreatrayNotFound) as ctx:
            await self.client.get(SHA, trigger_if_missing=False)
        self.assertEqual(
            " ".join(str(ctx.exception).split()),
            "No AI analysis results exist for this file. This call was made with "
            "trigger_if_missing=false, so none was created. To create one — this starts "
            "an analysis job — call threatray_get_ai_analysis with trigger_if_missing=true "
            "and trigger_only=true.",
        )

        with self.assertRaises(ThreatrayNotFound) as ctx:
            await self.client.get_latest_job(SHA)
        self.assertEqual(
            " ".join(str(ctx.exception).split()),
            "No AI analysis job was found for this file. If you only needed to know "
            "whether one exists, that is the answer; where AI analysis is not enabled for "
            "your account this call answers the same way, and threatray_list_ai_analyses "
            "tells the two apart. To create one — this starts an analysis job — call "
            "threatray_get_ai_analysis with trigger_only=true.",
        )

        with self.assertRaises(ThreatrayNotFound) as ctx:
            await self.client.get_result_by_id(aid)
        self.assertEqual(
            " ".join(str(ctx.exception).split()),
            f"No AI analysis result found for id {aid}. Result ids and job ids are both "
            "UUIDs, so a job id sent here fails exactly as a stale result id does. Result "
            "ids are listed by threatray_list_ai_analyses; no tool here looks up an AI job "
            "by id — threatray_get_latest_ai_job takes the file's SHA256.",
        )

    @respx.mock
    async def test_get_latest_job(self):
        respx.get(f"{API_BASE}/v1/ai-analysis/jobs/latest").mock(
            return_value=httpx.Response(200, json={"job_id": "j1", "job_status": "DONE"})
        )
        result = await self.client.get_latest_job(SHA)
        self.assertEqual(result["job_status"], "DONE")

    @respx.mock
    async def test_get_latest_job_404_maps_to_not_found(self):
        # 404 is ambiguous (feature-off vs no-job-yet) and the dominant case is
        # no-job-yet, so it stays ThreatrayNotFound rather than claiming the
        # feature is unavailable.
        respx.get(f"{API_BASE}/v1/ai-analysis/jobs/latest").mock(return_value=httpx.Response(404))
        with self.assertRaises(ThreatrayNotFound) as ctx:
            await self.client.get_latest_job(SHA)
        message = str(ctx.exception)
        # Answers the yes/no question first — most callers of this route wanted
        # only that, and job creation here is not deduplicated, so a retried
        # instruction to create one would create a job per retry.
        self.assertIn("No AI analysis job was found for this file", message)
        self.assertIn("that is the answer", message)
        # The creating call is named but explicitly conditional, and says that it
        # starts a job.
        self.assertIn("trigger_only=true", message)
        self.assertIn("starts an analysis job", message)
        # Ordering is the design: answer first, action second. Substring
        # assertions alone are satisfied by a message that reverses them, which
        # would read as "go create one" to the callers who wanted a yes/no.
        self.assertLess(
            message.index("that is the answer"),
            message.index("starts an analysis job"),
            "the answer must come before the action that creates a job",
        )
        self._assert_carries_the_ambiguity_caveat(message)
        # And never the bare generic text this replaces.
        self.assertNotIn("Not found: GET", message)

    def _assert_carries_the_ambiguity_caveat(self, message: str) -> None:
        """The message must keep saying that a not-found here is ambiguous.

        This is a tripwire, not a proof. Two earlier attempts tried to forbid the
        *claim* that the feature is enabled — first by banning a word, then by
        requiring every "enabled" to be negated. Both were defeated by synonym
        ("not disabled") or by an appended sentence, and the second also rejected
        truthful rewrites like "not, in fact, enabled". A guard that fails a
        correct message is one the next editor deletes, so it is gone.

        What is left is the positive requirement, which is what actually matters:
        the caveat has to survive. The verbatim pin is what catches edits; this
        keeps biting after that pin is deliberately updated.
        """
        self.assertIn("is not enabled", " ".join(message.split()))
