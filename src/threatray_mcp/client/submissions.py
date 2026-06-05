"""Submissions section — list + the submit-* family + task lookups.

Covers the Threatray API endpoints under `/v1/submissions/*` and `/v1/tasks/*`:
  GET  /v1/submissions                       → list (all submission types, mixed)
  POST /v1/submissions/samples               → submit_sample (binary file)
  POST /v1/submissions/urls                  → submit_url
  POST /v1/submissions/endpoint-scan-archive → submit_endpoint_scan_archive
  POST /v1/submissions/minidump              → submit_minidump
  POST /v1/submissions/mans-file             → submit_mans_file (Mandiant ans-file)
  GET  /v1/tasks                             → list_tasks
  GET  /v1/tasks/{task_id}                   → get_task
  GET  /v1/tasks/by-analysis/{analysis_id}   → get_task_by_analysis
"""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any

from ..models import (
    AnalysisMode,
    Priority,
    RawBinaryCpuArchitecture,
    RawBinaryFileFormat,
    SubmissionStatus,
)
from ._http import (
    TIMEOUT_SUBMIT_LONG,
    TIMEOUT_SUBMIT_MEDIUM,
    TIMEOUT_SUBMIT_SHORT,
    HttpClient,
)
from ._types import FileHashAny, SampleAnalysisId, SubmissionId, TaskId


def _read_file(path: str, field_name: str = "file") -> dict[str, tuple[str, bytes, str]]:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {p}")
    content = p.read_bytes()
    content_type = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
    return {field_name: (p.name, content, content_type)}


class SubmissionsClient:
    def __init__(self, http: HttpClient):
        self._http = http

    # ---- read ----

    async def list_submissions(
        self,
        limit: int = 50,
        status_filter: SubmissionStatus = SubmissionStatus.ALL,
        user_submissions_only: bool = False,
    ) -> dict[str, Any]:
        # Use /v1/submissions, not /v1/submissions/page. The /page variant
        # filters server-side to file-only submissions (excluding URL,
        # archive, scan, minidump, and mans submissions), which is too
        # narrow for a general listing tool. /v1/submissions takes no offset
        # (only /page does), so this endpoint has no server-side paging — the
        # formatter renders the returned window as-is.
        params: dict[str, Any] = {
            "limit": limit,
            "status_filter": status_filter,
            "user_submissions": "1" if user_submissions_only else "",
        }
        return await self._http.get("/v1/submissions", params)

    async def get_task(self, task_id: TaskId) -> dict[str, Any]:
        return await self._http.get(f"/v1/tasks/{task_id}")

    async def get_task_by_analysis(self, analysis_id: SampleAnalysisId) -> dict[str, Any]:
        return await self._http.get(f"/v1/tasks/by-analysis/{analysis_id}")

    async def list_tasks(
        self,
        file_hash: FileHashAny | None = None,
        submission_id: SubmissionId | None = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if file_hash:
            params["file_hash"] = file_hash
        if submission_id:
            params["submission_id"] = submission_id
        return await self._http.get("/v1/tasks", params)

    # ---- submit ----

    async def submit_sample(  # noqa: PLR0913 — mirrors the public API request shape
        self,
        file_path: str,
        *,
        label: str | None = None,
        analysis_mode: AnalysisMode = AnalysisMode.DYNAMIC,
        first_seen: int | None = None,
        environments: list[str] | None = None,
        priority: Priority = Priority.NORMAL,
        timeout_seconds: int | None = None,
        enable_network: bool = True,
        is_compound_sample: bool = False,
        entry_point: str | None = None,
        cmd_line_arguments: str | None = None,
        dll_exports: list[str] | None = None,
        dll_arguments: list[str] | None = None,
        raw_binary_file_format: RawBinaryFileFormat | None = None,
        raw_binary_cpu_architecture: RawBinaryCpuArchitecture | None = None,
        raw_binary_function_entry_point_detection_needed: bool | None = None,
        raw_binary_function_file_offset: str | None = None,
        raw_binary_image_base_address: str | None = None,
    ) -> dict[str, Any]:
        files = _read_file(file_path, "file")
        fields: dict[str, Any] = {
            "label": label,
            "analysis_mode": analysis_mode,
            "first_seen": first_seen,
            "environments": environments,
            "priority": priority,
            "timeout": timeout_seconds,
            "enable_network": enable_network,
            "is_compound_sample": is_compound_sample,
            "entry_point": entry_point,
            "cmd_line_arguments": cmd_line_arguments,
            "dll_exports": dll_exports,
            "dll_arguments": dll_arguments,
            "raw_binary_file_format": raw_binary_file_format,
            "raw_binary_cpu_architecture": raw_binary_cpu_architecture,
            "raw_binary_function_entry_point_detection_needed": raw_binary_function_entry_point_detection_needed,
            "raw_binary_function_file_offset": raw_binary_function_file_offset,
            "raw_binary_image_base_address": raw_binary_image_base_address,
        }
        return await self._submit("/v1/submissions/samples", files, fields, TIMEOUT_SUBMIT_LONG)

    async def submit_url(  # noqa: PLR0913 — mirrors the public API request shape
        self,
        url: str,
        *,
        label: str | None = None,
        first_seen: int | None = None,
        environments: list[str] | None = None,
        priority: Priority = Priority.NORMAL,
        timeout_seconds: int | None = None,
        enable_network: bool = True,
    ) -> dict[str, Any]:
        fields = {
            "url": url,
            "label": label,
            "first_seen": first_seen,
            "environments": environments,
            "priority": priority,
            "timeout": timeout_seconds,
            "enable_network": enable_network,
        }
        return await self._submit("/v1/submissions/urls", None, fields, TIMEOUT_SUBMIT_SHORT)

    async def submit_endpoint_scan_archive(
        self,
        archive_path: str,
        *,
        label: str | None = None,
        priority: Priority = Priority.NORMAL,
    ) -> dict[str, Any]:
        files = _read_file(archive_path, "archive")
        fields = {
            "label": label,
            "priority": priority,
        }
        return await self._submit(
            "/v1/submissions/endpoint-scan-archive", files, fields, TIMEOUT_SUBMIT_MEDIUM
        )

    async def submit_minidump(
        self,
        file_path: str,
        *,
        label: str | None = None,
        priority: Priority = Priority.NORMAL,
    ) -> dict[str, Any]:
        files = _read_file(file_path, "file")
        fields = {
            "label": label,
            "priority": priority,
        }
        return await self._submit("/v1/submissions/minidump", files, fields, TIMEOUT_SUBMIT_LONG)

    async def submit_mans_file(
        self,
        file_path: str,
        *,
        label: str | None = None,
        priority: Priority = Priority.NORMAL,
    ) -> dict[str, Any]:
        files = _read_file(file_path, "file")
        fields = {
            "label": label,
            "priority": priority,
        }
        return await self._submit("/v1/submissions/mans-file", files, fields, TIMEOUT_SUBMIT_LONG)

    # ---- shared ----

    async def _submit(
        self,
        path: str,
        files: dict[str, tuple[str, bytes, str]] | None,
        fields: dict[str, Any],
        timeout: Any,
    ) -> dict[str, Any]:
        return await self._http.post_multipart(path, files=files, fields=fields, timeout=timeout)
