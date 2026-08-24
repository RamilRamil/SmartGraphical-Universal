"""Single-shot analyzer CLI: one target in, one JSON document on stdout.

Contract (see docs/contracts/analyzer-cli-v1.schema.json):

- stdout carries exactly one JSON document and nothing else. Every diagnostic,
  including anything the engine prints, is redirected to stderr.
- The document is versioned by ``schema_version``. Additive changes keep the
  major; removals or renames do not.
- Failures are data too: an error envelope goes to stderr and the process exits
  with a code that says which kind of failure it was.
- Same input, same build, byte-identical stdout. Nothing that varies run to run
  (wall-clock timing, absolute temp paths) is allowed into the document; timing
  is reported on stderr instead.

This is the surface batch consumers are meant to build against. ``sg_cli.py``
remains the interactive, human-facing entry point and is unaffected.
"""
import argparse
import contextlib
import io
import json
import os
import sys
import time

from smartgraphical.services import provenance
from smartgraphical.services.analyze_facade import analyze as facade_analyze
from smartgraphical.services.analyze_facade import analyze_all as facade_analyze_all
from smartgraphical.services.analyze_facade import graph as facade_graph
from smartgraphical.services.task_catalog import META_TASK_ALL_ID, is_run_all_task
from smartgraphical.services.web_support import (
    ERROR_INTERNAL,
    ERROR_INVALID_LANGUAGE,
    ERROR_INVALID_MODE,
    ERROR_INVALID_PATH,
    ERROR_INVALID_TASK,
    WebApiError,
)


# Major version of the stdout envelope. Bumped only on a breaking shape change.
SCHEMA_VERSION = 1

# Exit codes are part of the contract: a consumer must be able to tell "analysis
# ran and found nothing" (0, findings_count 0) from "analysis never ran".
EXIT_OK = 0
EXIT_UNEXPECTED = 1
EXIT_USAGE = 2
EXIT_INVALID_TARGET = 3
EXIT_ANALYSIS_FAILED = 4

_EXIT_FOR_ERROR_CODE = {
    ERROR_INVALID_PATH: EXIT_INVALID_TARGET,
    ERROR_INVALID_LANGUAGE: EXIT_USAGE,
    ERROR_INVALID_MODE: EXIT_USAGE,
    ERROR_INVALID_TASK: EXIT_USAGE,
    ERROR_INTERNAL: EXIT_ANALYSIS_FAILED,
}

SUPPORTED_LANGUAGES = ("solidity", "c", "rust", "go")
SUPPORTED_MODES = ("legacy", "auditor", "explore")


# --------------------------------------------------------------------------
# deterministic ordering
# --------------------------------------------------------------------------

def _finding_sort_key(finding):
    """Total order over findings that depends only on their content.

    Rule-registry iteration order is already stable, but ordering findings by
    what they say (rather than by when they were produced) keeps run-to-run
    diffs meaningful even if a rule's internals are reshuffled later.
    """
    evidences = finding.get("evidences") or []
    first = evidences[0] if evidences else {}
    raw_task = str(finding.get("task_id", ""))
    # Numeric task ids sort numerically; named ones (e.g. "taint") sort after.
    numeric_task = (0, int(raw_task)) if raw_task.isdigit() else (1, 0)
    return (
        str(finding.get("source_file", "")),
        numeric_task,
        raw_task,
        str(finding.get("rule_id", "")),
        str(first.get("type_name", "")),
        str(first.get("function_name", "")),
        int(first.get("line_number", 0) or 0),
        str(first.get("source_statement", "") or first.get("statement", "")),
        str(finding.get("message", "")),
    )


def _sorted_findings(findings):
    return sorted(findings or [], key=_finding_sort_key)


def _sorted_graph(graph_dict):
    """Sort nodes and edges by identity, leaving each object's fields untouched."""
    nodes = sorted(graph_dict.get("nodes") or [], key=lambda node: str(node.get("id", "")))
    edges = sorted(
        graph_dict.get("edges") or [],
        key=lambda edge: (
            str(edge.get("source", "")),
            str(edge.get("target", "")),
            str(edge.get("kind", "")),
            str(edge.get("label", "")),
            str(edge.get("id", "")),
        ),
    )
    return nodes, edges


# --------------------------------------------------------------------------
# envelopes
# --------------------------------------------------------------------------

def _tool_block():
    return {
        "name": provenance.TOOL_NAME,
        "version": provenance.tool_version(),
        "rules_catalog_hash": provenance.rules_catalog_hash(),
    }


def error_envelope(code, message):
    """The stderr document for a run that did not produce an analysis."""
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "error",
        "code": code,
        "message": message,
        "tool": _tool_block(),
    }


def _ok_envelope(report, graph_block):
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "ok",
        "tool": _tool_block(),
        "artifact": report["artifact"],
        "language": report["language"],
        "mode": report["mode"],
        "task": report["task"],
        "rules_run": list(report["rules_run"]),
        "findings": _sorted_findings(report["findings"]),
        "findings_count": len(report["findings"]),
        "graph": graph_block,
    }


def dumps(document, pretty=False):
    """Serialize deterministically: sorted keys, ASCII-only, trailing newline."""
    if pretty:
        text = json.dumps(document, sort_keys=True, ensure_ascii=True, indent=2)
    else:
        text = json.dumps(document, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return text + "\n"


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------

def _build_graph_block(path, language):
    result = facade_graph(path, language=language)
    summary = result.get("model_summary") or {}
    raw = summary.get("graph") or {}
    nodes, edges = _sorted_graph(raw)
    return {
        # Promoted to a documented top level: consumers must not have to walk
        # model_summary -> graph to reach the nodes.
        "graph_schema_version": raw.get("graph_schema_version", ""),
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "types_count": summary.get("types_count", 0),
            "functions_count": summary.get("functions_count", 0),
            "state_entities_count": summary.get("state_entities_count", 0),
            "guards_count": summary.get("guards_count", 0),
            "call_edges_count": summary.get("call_edges_count", 0),
        },
    }


def run_analysis(path, task=None, language=None, mode="auditor", include_graph=False):
    """Run the analysis and return the stdout envelope.

    Raises WebApiError for every anticipated failure; the caller turns that into
    the error envelope. All engine chatter is captured, so this never writes to
    the real stdout.
    """
    if mode not in SUPPORTED_MODES:
        raise WebApiError(
            ERROR_INVALID_MODE,
            f"mode must be one of {', '.join(SUPPORTED_MODES)}",
        )
    if language is not None and language not in SUPPORTED_LANGUAGES:
        raise WebApiError(
            ERROR_INVALID_LANGUAGE,
            f"language must be one of {', '.join(SUPPORTED_LANGUAGES)}",
        )

    if task is None or is_run_all_task(task):
        report = facade_analyze_all(path, language=language, mode=mode)
        report["task"] = META_TASK_ALL_ID
    else:
        report = facade_analyze(path, task, language=language, mode=mode)

    graph_block = None
    if include_graph:
        graph_block = _build_graph_block(path, report["language"])
    return _ok_envelope(report, graph_block)


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------

class _ArgumentError(Exception):
    """argparse wanted to exit(2) with a usage message; carry it as data."""


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse would print to stderr and sys.exit
        raise _ArgumentError(message)


def build_parser():
    parser = _Parser(
        prog="python -m smartgraphical",
        description="SmartGraphical single-shot analyzer: one target in, one JSON document out.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="analyze one file or bundle directory and print a JSON report to stdout",
    )
    analyze_parser.add_argument(
        "path",
        help="source file, or a bundle directory containing a bundle manifest",
    )
    analyze_parser.add_argument(
        "--mode",
        default="auditor",
        help=f"finding presentation mode ({', '.join(SUPPORTED_MODES)}); default auditor",
    )
    analyze_parser.add_argument(
        "--language",
        default=None,
        help=f"override language detection ({', '.join(SUPPORTED_LANGUAGES)})",
    )
    analyze_parser.add_argument(
        "--task",
        default=None,
        help="run a single rule id instead of every rule; default runs all",
    )
    analyze_parser.add_argument(
        "--graph",
        action="store_true",
        help="include the code graph (nodes/edges) in the report",
    )
    analyze_parser.add_argument(
        "--pretty",
        action="store_true",
        help="indent the JSON; output stays deterministic either way",
    )
    return parser


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def main(argv=None, stdout=None, stderr=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr

    try:
        args = build_parser().parse_args(argv)
    except _ArgumentError as exc:
        stderr.write(dumps(error_envelope("invalid_arguments", str(exc))))
        return EXIT_USAGE
    except SystemExit as exc:  # --help / -h, which argparse prints itself
        return int(exc.code or EXIT_OK)

    started_at = time.perf_counter()
    # Any print() inside the engine belongs on stderr, not in the JSON stream.
    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured):
            document = run_analysis(
                args.path,
                task=args.task,
                language=args.language,
                mode=args.mode,
                include_graph=args.graph,
            )
    except WebApiError as exc:
        _flush_captured(captured, stderr)
        stderr.write(dumps(exc.to_dict() | {"schema_version": SCHEMA_VERSION, "tool": _tool_block()}))
        return _EXIT_FOR_ERROR_CODE.get(exc.code, EXIT_UNEXPECTED)
    except Exception as exc:  # never let a traceback reach stdout
        _flush_captured(captured, stderr)
        stderr.write(dumps(error_envelope(ERROR_INTERNAL, f"unexpected failure: {exc}")))
        return EXIT_UNEXPECTED

    _flush_captured(captured, stderr)
    # Timing is real but not reproducible, so it is a diagnostic, not a field.
    duration_ms = int((time.perf_counter() - started_at) * 1000)
    stderr.write(f"smartgraphical: analysis completed in {duration_ms} ms\n")
    stdout.write(dumps(document, pretty=args.pretty))
    return EXIT_OK


def _flush_captured(captured, stderr):
    text = captured.getvalue()
    if text:
        stderr.write(text)


if __name__ == "__main__":
    sys.exit(main())
