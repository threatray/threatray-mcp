"""Submissions section input models."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .common import (
    AnalysisMode,
    HashAny,
    Priority,
    RawBinaryCpuArchitecture,
    RawBinaryFileFormat,
    ResponseFormat,
    SubmissionStatus,
)


class SubmissionsInput(BaseModel):
    """Input for `threatray_list_submissions`."""

    limit: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Maximum submissions to return. Default 50; backend hard ceiling 1000.",
    )
    status_filter: SubmissionStatus = Field(
        default=SubmissionStatus.ALL,
        description="Filter by status: '' (all), 'queued', 'analyzing', 'done', 'failed', 'unsupported'",
    )
    user_submissions_only: bool = Field(
        default=False, description="Only the authenticated user's submissions"
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN, description="Output format"
    )


class TaskIdInput(BaseModel):
    """Input for `threatray_get_task`."""

    task_id: int = Field(..., ge=1, description="Task ID (integer)")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


class TaskByAnalysisInput(BaseModel):
    """Input for `threatray_get_task_by_analysis`."""

    analysis_id: UUID = Field(..., description="Analysis UUID")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


class TasksListInput(BaseModel):
    """Input for `threatray_list_tasks`."""

    file_hash: HashAny | None = Field(default=None, description="Filter by file hash (md5/sha1/sha256)")
    submission_id: UUID | None = Field(default=None, description="Filter by submission UUID")
    limit: int = Field(
        default=200,
        ge=1,
        le=10000,
        description="Maximum tasks to return. Default 200; capped at 10000 (the backend allows higher, "
        "but 10000 is more than enough for any agent use case).",
    )
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


def _validate_file_path(v: str) -> str:
    if not v or not v.strip():
        raise ValueError("file path must not be empty")
    return v.strip()


class SubmitSampleInput(BaseModel):
    """Input for `threatray_submit_sample` — submit a file for static or dynamic analysis."""

    model_config = ConfigDict(str_strip_whitespace=True)

    file_path: str = Field(
        ...,
        description="Absolute or expanded path to the file to submit. Any file type the platform "
        "supports — PE/ELF/Mach-O executables, archives, PDFs, Office documents, scripts, raw binaries.",
    )
    label: str | None = Field(default=None, description="Free-text label attached to the submission")
    analysis_mode: AnalysisMode = Field(
        default=AnalysisMode.DYNAMIC,
        description=(
            "'static' or 'dynamic'. `static` disassembles the file and runs the platform's "
            "classification engines (code-signatures, YARA, AI analysis) on the static binary — no "
            "execution. Fast; works for any supported file type. `dynamic` (default) additionally "
            "runs the file in a sandbox VM and records runtime behaviour (processes, IOCs, memory "
            "regions). The dynamic-only fields below (environments, timeout_seconds, enable_network, "
            "entry_point, cmd_line_arguments, dll_exports, dll_arguments) apply only in dynamic mode."
        ),
    )
    first_seen: int | None = Field(
        default=None,
        description="First-seen Unix-epoch timestamp (seconds). Defaults to submission time when omitted.",
    )
    environments: list[str] | None = Field(
        default=None,
        description=(
            "Sandbox VM image(s) to run the sample in for dynamic analysis. Pass a list; the "
            "platform runs one analysis per environment. Currently `win10_latest_x64` is the "
            "available image. The platform may add new images over time without an MCP update."
        ),
    )
    priority: Priority = Field(
        default=Priority.NORMAL,
        description=(
            "Submission queue priority. `high` jumps the queue, `normal` (default) joins the back, "
            "`low` falls behind everything. Determines when the analysis pipeline picks the "
            "submission up — not how many resources it gets. Use `high` sparingly: it competes with "
            "other users' urgent submissions."
        ),
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=15,
        le=1500,
        description="Sandbox-execution timeout in seconds (how long the file is run in the VM "
        "before the recorder stops). Platform default 180. Bump up for samples that delay "
        "execution (sleep loops, time-bombs).",
    )
    enable_network: bool = Field(
        default=True,
        description=(
            "Allow the sandbox VM to access the internet during dynamic-mode analysis. Default: on. "
            "Keep on for accurate dynamic-behaviour capture — downloaders fetching second-stage "
            "payloads, C2 beacons resolving control servers, droppers querying license servers. "
            "Turn off when contact with the attacker's infrastructure is undesirable (live-campaign "
            "analysis where reaching the C2 would tip off operators, air-gapped policy)."
        ),
    )

    # Compound / DLL execution shape -------------------------------------------------
    is_compound_sample: bool = Field(
        default=False,
        description=(
            "Treat the submission as one compound sample (instead of analysing each contained file "
            "separately). A compound sample is a wrapper — typically an archive or installer — "
            "whose contained payload is what should be executed during dynamic analysis. Requires "
            "`entry_point` to identify the executable inside the wrapper."
        ),
    )
    entry_point: str | None = Field(
        default=None,
        description="Path inside a compound archive to the main executable. Required when "
        "`is_compound_sample` is true.",
    )
    cmd_line_arguments: str | None = Field(
        default=None,
        description="Command-line arguments passed to the sample. Only supported for executables (not DLLs).",
    )
    dll_exports: list[str] | None = Field(
        default=None,
        description="DLL exports to invoke during execution. Each entry pairs positionally with `dll_arguments`.",
    )
    dll_arguments: list[str] | None = Field(
        default=None,
        description="Arguments passed positionally to each `dll_exports` entry. The two lists must "
        "contain the same number of items.",
    )

    # Raw-binary mode --------------------------------------------------------------
    raw_binary_file_format: RawBinaryFileFormat | None = Field(
        default=None,
        description=(
            "Treat the file as a raw binary (shellcode, code dumped from memory, or a PE missing "
            "its headers) instead of asking the platform to autodetect. `raw` = pure bytes, "
            "`pe` = PE without proper headers, `unknown` = let the platform try. Enables the rest "
            "of the raw_binary_* fields below."
        ),
    )
    raw_binary_cpu_architecture: RawBinaryCpuArchitecture | None = Field(
        default=None,
        description="CPU architecture the raw binary was compiled for: '' | 'x86-32' | 'x86-64'. "
        "Tells the disassembler which instruction set to decode. Requires `raw_binary_file_format`.",
    )
    raw_binary_function_entry_point_detection_needed: bool | None = Field(
        default=None,
        description="If true, the platform auto-detects function entry points; if false, the offset "
        "must be supplied via `raw_binary_function_file_offset`. Requires `raw_binary_file_format`.",
    )
    raw_binary_function_file_offset: str | None = Field(
        default=None,
        description="Function entry-point file offset (e.g. '0x1234' or '4660'). Only valid when "
        "`raw_binary_function_entry_point_detection_needed=false`.",
    )
    raw_binary_image_base_address: str | None = Field(
        default=None,
        description="Image base address (e.g. '0x400000' or '4194304'). Requires `raw_binary_file_format`.",
    )

    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")

    _vp = field_validator("file_path")(_validate_file_path)

    @model_validator(mode="after")
    def _check_raw_binary_combo(self) -> SubmitSampleInput:
        raw_fields = (
            self.raw_binary_cpu_architecture,
            self.raw_binary_function_entry_point_detection_needed,
            self.raw_binary_function_file_offset,
            self.raw_binary_image_base_address,
        )
        if self.raw_binary_file_format is None and any(f is not None for f in raw_fields):
            raise ValueError(
                "raw_binary_* fields require raw_binary_file_format to be set ('unknown', 'raw', or 'pe')"
            )
        if (
            self.raw_binary_function_file_offset is not None
            and self.raw_binary_function_entry_point_detection_needed is not False
        ):
            raise ValueError(
                "raw_binary_function_file_offset requires "
                "raw_binary_function_entry_point_detection_needed=false"
            )
        if self.is_compound_sample and not self.entry_point:
            raise ValueError("entry_point is required when is_compound_sample is true")
        if self.dll_exports is not None and self.dll_arguments is not None and len(self.dll_exports) != len(
            self.dll_arguments
        ):
            raise ValueError("dll_exports and dll_arguments must have the same length")
        return self


class SubmitUrlInput(BaseModel):
    """Input for `threatray_submit_url`.

    Submit a URL. The platform fetches the URL in a browser, downloads the file
    it points at, and runs dynamic analysis on **that file** — the URL itself
    is not the subject of analysis."""

    model_config = ConfigDict(str_strip_whitespace=True)

    url: str = Field(..., min_length=1, description="URL to fetch (http, https, or ftp).")
    label: str | None = Field(default=None)
    first_seen: int | None = Field(
        default=None,
        description="First-seen Unix-epoch timestamp (seconds). Defaults to submission time when omitted.",
    )
    environments: list[str] | None = Field(
        default=None,
        description=(
            "Sandbox VM image(s) to run the downloaded file in. Currently `win10_latest_x64` "
            "is the available image. The platform may add new images over time without an MCP "
            "update."
        ),
    )
    priority: Priority = Field(
        default=Priority.NORMAL,
        description=(
            "Submission queue priority. `high` jumps the queue, `normal` (default) joins the back, "
            "`low` falls behind everything. Determines when the analysis pipeline picks the "
            "submission up. Use `high` sparingly."
        ),
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=15,
        le=1500,
        description="Sandbox-execution timeout in seconds. Platform default 180.",
    )
    enable_network: bool = Field(
        default=True,
        description=(
            "Allow the sandbox VM to access the internet during dynamic-mode analysis. Default: on. "
            "Keep on for accurate dynamic-behaviour capture (downloaders, C2 beacons, multi-stage "
            "payloads). Turn off when contact with attacker infrastructure is undesirable."
        ),
    )
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")

    @field_validator("url")
    @classmethod
    def _vurl(cls, v: str) -> str:
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://") or v.startswith("ftp://")):
            raise ValueError("url must start with http://, https://, or ftp://")
        return v


class _FileSubmitInput(BaseModel):
    """Shared base for the file-only multipart submissions."""

    model_config = ConfigDict(str_strip_whitespace=True)

    file_path: str = Field(..., description="Absolute or expanded path to the file to submit")
    label: str | None = Field(default=None)
    priority: Priority = Field(default=Priority.NORMAL, description="'low', 'normal', or 'high'")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")

    _vp = field_validator("file_path")(_validate_file_path)


class SubmitEndpointScanArchiveInput(_FileSubmitInput):
    """Input for `threatray_submit_endpoint_scan_archive` — submit an archive of endpoint scans."""


class SubmitMinidumpInput(_FileSubmitInput):
    """Input for `threatray_submit_minidump` — submit a Windows minidump (.dmp) file."""


class SubmitMansFileInput(_FileSubmitInput):
    """Input for `threatray_submit_mans_file` — submit a Mandiant `.mans` memory triage file."""
