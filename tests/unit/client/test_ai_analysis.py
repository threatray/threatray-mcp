"""AiAnalysisClient tests — covers realm-gating mapping, trigger-if-missing, trigger-only,
get-by-id and get-latest-job."""

import json
import unittest
from itertools import pairwise

import httpx
import respx

from threatray_mcp.client import AiAnalysisClient
from threatray_mcp.client._http import HttpClient
from threatray_mcp.errors import ThreatrayFeatureUnavailable, ThreatrayNotFound

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
        with self.assertRaises(ThreatrayNotFound):
            await self.client.get(SHA, trigger_if_missing=False)

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
    async def test_trigger_flow_falls_back_to_listing_for_legacy_job_shape(self):
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(
            side_effect=[
                httpx.Response(200, json={"results": []}),
                httpx.Response(200, json={"results": [{"id": "fresh"}]}),
            ]
        )
        respx.post(f"{API_BASE}/v1/ai-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": "j1", "job_status": "QUEUED"})
        )
        respx.get(f"{API_BASE}/v1/ai-analysis/jobs/j1").mock(
            return_value=httpx.Response(200, json={"job_id": "j1", "job_status": "DONE"})
        )

        result = await self.client.get(SHA, trigger_if_missing=True, max_wait_seconds=30)

        self.assertEqual(result["id"], "fresh")

    @respx.mock
    async def test_trigger_flow_reports_strict_progress_across_stage_lifecycle(self):
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(
            side_effect=[
                httpx.Response(200, json={"results": []}),
                httpx.Response(200, json={"results": [{"id": "fresh"}]}),
            ]
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
                httpx.Response(200, json={"job_id": "j1", "job_status": "DONE"}),
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
        with self.assertRaises(ThreatrayNotFound):
            await self.client.get_latest_job(SHA)
