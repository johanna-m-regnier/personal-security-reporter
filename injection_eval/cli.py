from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from config import TriageConfigError, load_triage_config
from paths import OUTPUT_DIR
from triage import ClientFactory, create_openai_client

from .corpus import CorpusError, DEFAULT_CORPUS_PATH, load_injection_corpus
from .reporting import print_summary, write_evaluation_artifacts
from .runner import EvaluationError, offline_client_factory, run_injection_testbed

_DEFAULT_REPEAT = 5


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate PSR triage against a prompt-injection corpus. "
            "Offline fixture mode is the default."
        )
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use OpenAI. Requires an explicit --max-calls value.",
    )
    parser.add_argument(
        "--max-calls",
        type=int,
        help="Maximum calls across controls and attack trials.",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=_DEFAULT_REPEAT,
        help=f"Repeat every attack with a fresh control (default: {_DEFAULT_REPEAT}).",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS_PATH,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=OUTPUT_DIR,
    )
    args = parser.parse_args(argv)
    if args.live and args.max_calls is None:
        parser.error("--live requires an explicit --max-calls value.")
    if args.max_calls is not None and args.max_calls < 2:
        parser.error("--max-calls must be at least 2.")
    if args.repeat < 1:
        parser.error("--repeat must be at least 1.")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        cases = load_injection_corpus(args.corpus)
        config = load_triage_config()
    except (CorpusError, TriageConfigError) as error:
        print(f"ERROR: {error}")
        return 2

    full_plan = args.repeat * (1 + len(cases))
    if args.live:
        if not config.api_key:
            print("ERROR: OPENAI_API_KEY is required for --live.")
            return 2
        assert args.max_calls is not None
        requested_limit = args.max_calls
        run_config = config
        mode = "live_openai"
        client_factory: ClientFactory = create_openai_client
    else:
        requested_limit = args.max_calls or full_plan
        run_config = replace(
            config,
            max_findings_per_run=max(
                config.max_findings_per_run,
                requested_limit,
            ),
        )
        mode = "offline_fixture"
        client_factory = offline_client_factory

    effective_limit = min(requested_limit, run_config.max_findings_per_run)
    planned_calls = min(full_plan, effective_limit)
    print(
        f"Planned {mode} client calls: {planned_calls} "
        f"(effective cap: {effective_limit}, repeat: {args.repeat})"
    )
    if args.live and planned_calls < full_plan:
        print(
            "WARNING: The live call cap will truncate the requested repetitions. "
            "Per-case denominators will be reported explicitly."
        )

    try:
        evaluation = run_injection_testbed(
            cases,
            corpus_path=args.corpus,
            config=run_config,
            client_factory=client_factory,
            max_calls=requested_limit,
            mode=mode,
            repeat=args.repeat,
        )
        json_path, markdown_path = write_evaluation_artifacts(
            evaluation,
            output_dir=args.output_dir,
        )
    except (EvaluationError, OSError) as error:
        print(f"ERROR: {error}")
        return 2

    print_summary(evaluation)
    print(f"\nJSON: {json_path}\nMarkdown: {markdown_path}")
    if mode == "offline_fixture":
        print(
            "Offline fixture results validate the harness only; they are "
            "not live-model security evidence."
        )
    return 0
