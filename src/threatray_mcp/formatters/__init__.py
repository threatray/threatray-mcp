"""Per-section response formatters. Re-exports the public format_* functions."""

from .ai_analysis import format_ai_analysis, format_ai_analysis_list
from .analyses import (
    format_analyses_list,
    format_analysis_details,
    format_endpoint_scan_analyses,
    format_osint_report,
)
from .capa import format_capa_results
from .files import format_file_metadata, format_strings_list
from .functions import (
    format_code_detections,
    format_function_diff,
    format_function_retrohunt,
    format_functions_list,
)
from .samples import format_sample_details
from .search import format_retrohunt_results, format_search_results
from .submissions import (
    format_submission_response,
    format_submissions_list,
    format_task,
    format_tasks_list,
)

__all__ = [
    "format_ai_analysis",
    "format_ai_analysis_list",
    "format_analyses_list",
    "format_analysis_details",
    "format_capa_results",
    "format_code_detections",
    "format_endpoint_scan_analyses",
    "format_file_metadata",
    "format_function_diff",
    "format_function_retrohunt",
    "format_functions_list",
    "format_osint_report",
    "format_retrohunt_results",
    "format_sample_details",
    "format_search_results",
    "format_strings_list",
    "format_submission_response",
    "format_submissions_list",
    "format_task",
    "format_tasks_list",
]
