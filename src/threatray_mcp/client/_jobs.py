"""Generic async-job poller shared by CAPA and AI analysis clients."""

import asyncio
from typing import Any

from ..errors import ThreatrayJobFailed, ThreatrayJobTimeout
from ..models import JobStatus
from ._http import HttpClient
from ._types import ProgressCallback


class JobPoller:
    """Polls a Threatray async job until it terminates.

    Section clients own the create-job and fetch-results URLs; the poller only owns
    the wait loop, status disambiguation, progress reporting, and timeout. AI
    analysis adds UNSUPPORTED/SKIPPED to the failure terminal set via
    `extra_terminal_failures`.
    """

    def __init__(
        self,
        http: HttpClient,
        job_path_prefix: str,
        job_label: str,
        poll_interval: int = 7,
        timeout: int = 300,
        extra_terminal_failures: tuple[str, ...] = (),
    ):
        self._http = http
        self._job_path_prefix = job_path_prefix
        self._label = job_label
        self.poll_interval = poll_interval
        self.timeout = timeout
        self.extra_terminal_failures = extra_terminal_failures

    async def get_job(self, job_id: str | int) -> dict[str, Any]:
        return await self._http.get(f"{self._job_path_prefix}/jobs/{job_id}")

    async def poll(self, job_id: str | int, progress_callback: ProgressCallback = None) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        start_time = loop.time()
        while True:
            elapsed = loop.time() - start_time
            if elapsed > self.timeout:
                raise ThreatrayJobTimeout(f"{self._label} job {job_id} timed out after {self.timeout}s")

            job = await self.get_job(job_id)
            status = job.get("job_status")

            if progress_callback:
                progress = min(0.9, 0.3 + (elapsed / self.timeout) * 0.6)
                status_msg = f"{self._label} job {status.lower()}..." if status else "Processing..."
                await progress_callback(progress, status_msg)

            if status == JobStatus.DONE.value:
                return job
            if status == JobStatus.FAILED.value or status in self.extra_terminal_failures:
                raise ThreatrayJobFailed(f"{self._label} job {job_id} {str(status).lower()}")

            await asyncio.sleep(self.poll_interval)
