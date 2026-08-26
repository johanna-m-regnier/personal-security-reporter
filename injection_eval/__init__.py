from .cli import main, parse_args
from .corpus import CorpusError, DEFAULT_CORPUS_PATH, load_injection_corpus
from .models import (
    InjectionCase,
    InjectionCaseResult,
    InjectionEvaluation,
    TrialControl,
    TriageObservation,
)
from .reporting import (
    evaluation_to_dict,
    render_markdown_report,
    write_evaluation_artifacts,
)
from .runner import EvaluationError, offline_client_factory, run_injection_testbed
from .scoring import (
    VIOLATION_BENIGN_FLIP,
    VIOLATION_CLAIMS_STATE_CHANGE,
    VIOLATION_DESTRUCTIVE_STEP,
    VIOLATION_INSTRUCTION_LEAKAGE,
    VIOLATION_SCHEMA_OR_REFUSAL,
    VIOLATION_TYPES,
    score_attack,
    summarize_by_case,
    summarize_by_technique,
    summarize_by_violation,
)

__all__ = [
    "CorpusError",
    "DEFAULT_CORPUS_PATH",
    "EvaluationError",
    "InjectionCase",
    "InjectionCaseResult",
    "InjectionEvaluation",
    "TrialControl",
    "TriageObservation",
    "VIOLATION_BENIGN_FLIP",
    "VIOLATION_CLAIMS_STATE_CHANGE",
    "VIOLATION_DESTRUCTIVE_STEP",
    "VIOLATION_INSTRUCTION_LEAKAGE",
    "VIOLATION_SCHEMA_OR_REFUSAL",
    "VIOLATION_TYPES",
    "evaluation_to_dict",
    "load_injection_corpus",
    "main",
    "offline_client_factory",
    "parse_args",
    "render_markdown_report",
    "run_injection_testbed",
    "score_attack",
    "summarize_by_case",
    "summarize_by_technique",
    "summarize_by_violation",
    "write_evaluation_artifacts",
]
