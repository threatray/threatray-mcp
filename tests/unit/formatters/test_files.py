"""Tests for formatters/files.py."""

import unittest

from hamcrest import assert_that, contains_string

from tests.dummies import DUMMY_MD5, DUMMY_SHA1, DUMMY_SHA256
from threatray_mcp.formatters import format_file_metadata, format_strings_list


def _metadata_payload():
    """Trimmed copy of the /v1/files/{hash}/metadata?include_strings=false
    response. The `header` has FileHeader + OptionalHeader; sections / imports
    / exports / resources / rich_header / version_info round out the PE
    surface. No `strings` key — that lives on /v1/files/{hash}/strings."""
    return {
        "hash_sha256": DUMMY_SHA256,
        "hash_sha1": DUMMY_SHA1,
        "hash_md5": DUMMY_MD5,
        "first_seen": 1777556349,
        "magic": "PE32+ executable (DLL) (GUI) x86-64",
        "size": 241153,
        "scope": "private",
        "header": {
            "FileHeader": {
                "Machine": 332,
                "NumberOfSections": 4,
                "TimeDateStamp": "2024-03-16T06:02:19",
                "PointerToSymbolTable": 0,
                "NumberOfSymbols": 0,
                "SizeOfOptionalHeader": 224,
                "Characteristics": 259,
                "Flags": [
                    "IMAGE_FILE_RELOCS_STRIPPED",
                    "IMAGE_FILE_EXECUTABLE_IMAGE",
                    "IMAGE_FILE_32BIT_MACHINE",
                ],
            },
            "OptionalHeader": {
                "Magic": 0x10B,
                "ImageBase": 0x400000,
                "AddressOfEntryPoint": 0x1080,
                "SizeOfCode": 0x1000,
                "SizeOfImage": 0x10000,
                "Subsystem": 3,
                "DllCharacteristics": ["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"],
                "MajorLinkerVersion": 14,
                "MinorLinkerVersion": 30,
            },
        },
        "sections": [
            {"Name": ".text", "VirtualAddress": 0x1000, "VirtualSize": 0x800, "SizeOfRawData": 0x1000},
            {"Name": ".rdata", "VirtualAddress": 0x2000, "VirtualSize": 0x400, "SizeOfRawData": 0x1000},
        ],
        "imports": [{"DLL": "kernel32.dll"}, {"DLL": "user32.dll"}],
        "exports": [{"name": "DllEntry"}],
        "resources": [{"name": "MUI", "magic": "MS Windows Compiled Help index"}],
        "rich_header": {"checksum": 0x12345678, "checksum_valid": True},
        "version_info": [[{"CompanyName": "Acme Corp", "LangID": 1033}]],
    }


class TestFormatFileMetadata(unittest.TestCase):
    def test_renders_identification(self):
        result = format_file_metadata(_metadata_payload())
        assert_that(result, contains_string(DUMMY_SHA256))
        assert_that(result, contains_string("PE32+"))
        assert_that(result, contains_string("241153 bytes"))

    def test_renders_file_header_with_flags(self):
        result = format_file_metadata(_metadata_payload())
        assert_that(result, contains_string("FileHeader"))
        assert_that(result, contains_string("Machine"))
        assert_that(result, contains_string("NumberOfSections"))
        assert_that(result, contains_string("SizeOfOptionalHeader"))
        assert_that(result, contains_string("IMAGE_FILE_EXECUTABLE_IMAGE"))

    def test_renders_optional_header_addresses_in_hex(self):
        result = format_file_metadata(_metadata_payload())
        assert_that(result, contains_string("OptionalHeader"))
        assert_that(result, contains_string("0x00400000"))  # ImageBase
        assert_that(result, contains_string("0x00001080"))  # AddressOfEntryPoint
        assert_that(result, contains_string("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"))

    def test_renders_sections_table(self):
        result = format_file_metadata(_metadata_payload())
        assert_that(result, contains_string("Sections (2)"))
        assert_that(result, contains_string(".text"))
        assert_that(result, contains_string("0x00001000"))

    def test_renders_resources(self):
        result = format_file_metadata(_metadata_payload())
        assert_that(result, contains_string("Resources (1)"))
        assert_that(result, contains_string("MUI"))

    def test_renders_rich_header(self):
        result = format_file_metadata(_metadata_payload())
        assert_that(result, contains_string("Rich header"))
        assert_that(result, contains_string("valid"))

    def test_renders_version_info(self):
        result = format_file_metadata(_metadata_payload())
        assert_that(result, contains_string("Version info"))
        assert_that(result, contains_string("Acme Corp"))

    def test_no_strings_section_even_if_payload_carries_some(self):
        """Defensive — older backends may still include `strings`. The
        formatter must not render them; that's the dedicated
        `threatray_get_strings` tool's job."""
        data = {**_metadata_payload(), "strings": ["evil.com", "CreateFileW"]}
        result = format_file_metadata(data)
        self.assertNotIn("### Strings", result)
        self.assertNotIn("evil.com", result)


class TestFormatStringsList(unittest.TestCase):
    """`format_strings_list` is paired with a tool layer that asks the upstream
    for at most 201 strings — so the formatter sees ≤201 entries and uses the
    201th as the "there's more" signal."""

    def test_renders_exact_count_when_under_cap(self):
        result = format_strings_list({"strings": ["evil.com", "CreateFileW", "Mutex42"]})
        assert_that(result, contains_string("Strings (3)"))
        assert_that(result, contains_string("evil.com"))
        assert_that(result, contains_string("CreateFileW"))
        assert_that(result, contains_string("Mutex42"))
        self.assertNotIn("more than", result)

    def test_renders_full_list_when_exactly_at_cap(self):
        """Receiving exactly 200 strings means the probe (201) did NOT trip —
        the upstream returned ≤200. The formatter renders all 200 with the
        exact count and no truncation note."""
        result = format_strings_list({"strings": [f"s_{i}" for i in range(200)]})
        assert_that(result, contains_string("Strings (200)"))
        assert_that(result, contains_string("s_0"))
        assert_that(result, contains_string("s_199"))
        self.assertNotIn("more than", result)
        self.assertNotIn("response_format='json'", result)

    def test_caps_render_and_notes_truncation_when_probe_trips(self):
        """Receiving 201 strings means the probe tripped — actual count is
        unknown but > 200. Render the first 200 + a truncation note pointing
        at the spill file and the JSON escape hatch."""
        result = format_strings_list({"strings": [f"s_{i}" for i in range(201)]})
        assert_that(result, contains_string("more than 200"))
        assert_that(result, contains_string("showing first 200"))
        assert_that(result, contains_string("s_0"))
        assert_that(result, contains_string("s_199"))
        self.assertNotIn("s_200", result)
        # Footer mentions both escape hatches: the spill file (added by the
        # tool layer) and the JSON re-call.
        assert_that(result, contains_string("Full markdown saved to disk"))
        assert_that(result, contains_string("response_format='json'"))

    def test_max_strings_none_renders_every_entry_no_footer(self):
        """`max_strings=None` is the spill-to-disk path's contract — every
        string in the response renders, no truncation footer, regardless of
        how many were extracted."""
        result = format_strings_list(
            {"strings": [f"s_{i:04d}" for i in range(500)]},
            max_strings=None,
        )
        assert_that(result, contains_string("Strings (500)"))
        assert_that(result, contains_string("s_0000"))
        assert_that(result, contains_string("s_0499"))
        self.assertNotIn("more than", result)
        self.assertNotIn("Full markdown saved to disk", result)

    def test_empty_strings(self):
        result = format_strings_list({"strings": []})
        assert_that(result, contains_string("Strings (0)"))

    def test_missing_strings_key(self):
        """Defensive — payload without a `strings` key renders as empty."""
        result = format_strings_list({})
        assert_that(result, contains_string("Strings (0)"))


class TestZeroByteFile(unittest.TestCase):
    def test_zero_byte_file_renders_size_not_hidden(self):
        # size=0 is a legitimate value (0-byte file); it must render, not be
        # dropped by a falsy check.
        out = format_file_metadata({"hash_sha256": DUMMY_SHA256, "size": 0})
        assert_that(out, contains_string("0 bytes"))
