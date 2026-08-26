from __future__ import annotations

import hmac
import secrets
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import select_autoescape
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from baseline import BaselineError, acknowledge_findings
from ledger import (
    LedgerError,
    get_triage_annotation,
    record_triage_verdict,
)
from paths import BASELINE_PATH, LEDGER_PATH, OUTPUT_DIR
from web.data import DashboardData, DashboardDataError

_WEB_DIR = Path(__file__).resolve().parent
_TEMPLATE_DIR = _WEB_DIR / "templates"
_STATIC_DIR = _WEB_DIR / "static"
_ALLOWED_VERDICTS = frozenset({"accurate", "wrong", "unsure"})
_CSRF_SESSION_KEY = "csrf_token"


def _display_timestamp(value: Any) -> str:
    if value is None:
        return "Not completed"

    text = str(value).strip()

    if not text:
        return "Unknown"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return text

    return parsed.astimezone().strftime("%b %d, %Y · %I:%M:%S %p")


def _csrf_context(request: Request) -> dict[str, str]:
    token = request.session.get(_CSRF_SESSION_KEY)

    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(32)
        request.session[_CSRF_SESSION_KEY] = token

    return {"csrf_token": token}


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")

    if origin is None:
        return True

    parsed = urlsplit(origin)
    request_host = request.headers.get("host", "")

    return (
        parsed.scheme == request.url.scheme
        and parsed.netloc == request_host
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
    )


def _require_csrf(
    request: Request,
    submitted_token: str,
) -> None:
    session_token = request.session.get(_CSRF_SESSION_KEY)

    if (
        not isinstance(session_token, str)
        or not submitted_token
        or not hmac.compare_digest(session_token, submitted_token)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token.",
        )

    if not _same_origin(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-origin form submission rejected.",
        )


def create_app(
    *,
    ledger_path: Path = LEDGER_PATH,
    output_dir: Path = OUTPUT_DIR,
    baseline_path: Path = BASELINE_PATH,
    session_secret: str | None = None,
    allowed_hosts: Sequence[str] = ("127.0.0.1", "localhost"),
) -> FastAPI:
    resolved_secret = session_secret or secrets.token_urlsafe(48)

    middleware = [
        Middleware(
            TrustedHostMiddleware,
            allowed_hosts=list(allowed_hosts),
            www_redirect=False,
        ),
        Middleware(
            SessionMiddleware,
            secret_key=resolved_secret,
            session_cookie="psr_session",
            same_site="strict",
            https_only=False,
            max_age=8 * 60 * 60,
        ),
    ]

    app = FastAPI(
        title="Personal Security Reporter",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        middleware=middleware,
    )

    app.state.dashboard_data = DashboardData(
        ledger_path=ledger_path.expanduser().resolve(),
        output_dir=output_dir.expanduser().resolve(),
        baseline_path=baseline_path.expanduser().resolve(),
    )

    templates = Jinja2Templates(
        directory=str(_TEMPLATE_DIR),
        context_processors=[_csrf_context],
    )
    templates.env.autoescape = select_autoescape(
        enabled_extensions=("html", "htm", "xml"),
        default_for_string=True,
        default=True,
    )
    templates.env.filters["display_time"] = _display_timestamp
    app.state.templates = templates

    app.mount(
        "/static",
        StaticFiles(directory=str(_STATIC_DIR)),
        name="static",
    )

    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "script-src 'none'; "
            "style-src 'self'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    def data_for(request: Request) -> DashboardData:
        return request.app.state.dashboard_data

    def render(
        request: Request,
        template_name: str,
        context: dict[str, Any],
        *,
        status_code: int = 200,
    ) -> Response:
        return request.app.state.templates.TemplateResponse(
            request,
            template_name,
            context,
            status_code=status_code,
        )

    @app.get("/", name="index")
    def index(request: Request) -> Response:
        try:
            latest = data_for(request).latest_run_view()
        except DashboardDataError as error:
            return render(
                request,
                "index.html",
                {
                    "page_title": "Latest run",
                    "latest": None,
                    "data_error": str(error),
                },
                status_code=500,
            )

        return render(
            request,
            "index.html",
            {
                "page_title": "Latest run",
                "latest": latest,
                "data_error": None,
            },
        )

    @app.get("/runs", name="runs")
    def runs(request: Request) -> Response:
        try:
            rows = data_for(request).list_runs()
        except DashboardDataError as error:
            return render(
                request,
                "runs.html",
                {
                    "page_title": "Run history",
                    "runs": [],
                    "data_error": str(error),
                },
                status_code=500,
            )

        return render(
            request,
            "runs.html",
            {
                "page_title": "Run history",
                "runs": rows,
                "data_error": None,
            },
        )

    @app.get("/runs/{run_id}", name="run_detail")
    def run_detail(request: Request, run_id: str) -> Response:
        try:
            view = data_for(request).get_run_view(run_id)
        except DashboardDataError as error:
            raise HTTPException(
                status_code=500,
                detail=str(error),
            ) from error

        if view is None:
            raise HTTPException(
                status_code=404,
                detail="Run not found.",
            )

        return render(
            request,
            "run_detail.html",
            {
                "page_title": f"Run {run_id}",
                "view": view,
            },
        )

    @app.get(
        "/findings/{finding_id}",
        name="finding_detail",
    )
    def finding_detail(
        request: Request,
        finding_id: str,
    ) -> Response:
        try:
            view = data_for(request).get_finding_view(finding_id)
        except DashboardDataError as error:
            raise HTTPException(
                status_code=500,
                detail=str(error),
            ) from error

        if view is None:
            raise HTTPException(
                status_code=404,
                detail="Finding not found.",
            )

        return render(
            request,
            "finding.html",
            {
                "page_title": f"Finding {finding_id}",
                "view": view,
            },
        )

    @app.post(
        "/findings/{finding_id}/acknowledge",
        name="acknowledge_finding",
    )
    def acknowledge_finding(
        request: Request,
        finding_id: str,
        csrf_token: Annotated[str, Form()] = "",
    ) -> RedirectResponse:
        _require_csrf(request, csrf_token)

        try:
            view = data_for(request).get_finding_view(finding_id)
        except DashboardDataError as error:
            raise HTTPException(
                status_code=500,
                detail=str(error),
            ) from error

        if view is None:
            raise HTTPException(
                status_code=404,
                detail="Finding not found.",
            )

        try:
            acknowledge_findings(
                finding_ids=[finding_id],
                path=data_for(request).baseline_path,
            )
        except BaselineError as error:
            raise HTTPException(
                status_code=409,
                detail=str(error),
            ) from error

        return RedirectResponse(
            url=request.url_for(
                "finding_detail",
                finding_id=finding_id,
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post(
        "/triage/{finding_id}/verdict",
        name="record_verdict",
    )
    def record_verdict(
        request: Request,
        finding_id: str,
        prompt_hash: Annotated[str, Form()],
        verdict: Annotated[str, Form()],
        csrf_token: Annotated[str, Form()] = "",
    ) -> RedirectResponse:
        _require_csrf(request, csrf_token)

        normalized_verdict = verdict.strip().lower()

        if normalized_verdict not in _ALLOWED_VERDICTS:
            raise HTTPException(
                status_code=422,
                detail="Verdict must be accurate, wrong, or unsure.",
            )

        ledger_path = data_for(request).ledger_path

        try:
            target = get_triage_annotation(
                path=ledger_path,
                finding_id=finding_id,
                prompt_hash=prompt_hash,
            )
        except LedgerError as error:
            raise HTTPException(
                status_code=500,
                detail=str(error),
            ) from error

        if target is None:
            raise HTTPException(
                status_code=404,
                detail="Triage annotation not found.",
            )

        try:
            annotation = record_triage_verdict(
                path=ledger_path,
                finding_id=finding_id,
                prompt_hash=prompt_hash,
                verdict=normalized_verdict,
                verdict_at=(
                    datetime.now()
                    .astimezone()
                    .isoformat()
                ),
            )
        except LedgerError as error:
            raise HTTPException(
                status_code=500,
                detail=str(error),
            ) from error

        target = request.url_for(
            "finding_detail",
            finding_id=finding_id,
        )

        return RedirectResponse(
            url=f"{target}#annotation-{annotation.prompt_hash[:12]}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return app
