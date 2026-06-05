"""Files section input models."""

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .common import HashAny, ResponseFormat


class FileMetadataInput(BaseModel):
    """Input for file metadata retrieval (PE headers, sections, imports,
    exports, resources, version info). Strings are excluded — use
    `threatray_get_strings` to fetch them separately."""

    model_config = ConfigDict(str_strip_whitespace=True)

    file_hash: HashAny = Field(..., description="MD5, SHA1, or SHA256 hash of the file")
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )


class StringsInput(BaseModel):
    """Input for the extracted-strings list of a file."""

    model_config = ConfigDict(str_strip_whitespace=True)

    file_hash: HashAny = Field(..., description="MD5, SHA1, or SHA256 hash of the file")
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description=(
            "Output format. 'markdown' caps the rendered list at the first 200 strings "
            "to keep the response compact; 'json' returns every string the platform "
            "extracted."
        ),
    )


class FileDownloadInput(BaseModel):
    """Input for malware sample download."""

    model_config = ConfigDict(str_strip_whitespace=True)

    file_hash: HashAny = Field(..., description="MD5, SHA1, or SHA256 hash of the file to download")
    output_path: str = Field(
        ...,
        min_length=1,
        description="Local file path where the password-protected ZIP file will be saved.",
    )

    @field_validator("output_path")
    @classmethod
    def validate_output_path(cls, v: str) -> str:
        # OS file-system permissions are the source of truth for where the
        # MCP process is allowed to write — we don't impose a directory
        # allowlist on top. The README's security note covers operator
        # responsibility (run under least-privilege, watch tool calls).
        path = Path(v).resolve()
        if path.is_dir():
            raise ValueError("output_path must be a file path, not a directory")
        return str(path)


