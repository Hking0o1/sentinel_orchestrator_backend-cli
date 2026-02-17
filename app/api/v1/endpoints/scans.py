from uuid import uuid4
from typing import Dict, List, Any
import os
import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.models.scan import ScanCreate, ScanJob, ScanJobSummary, ScanFinding, ScanStatus, ScanProfile
from app.models.security import ActivityOutcome, DomainStatus, TrustTier
from app.core.security import get_current_user
from app.models.user import User
from app.db import crud
from app.services.security_controls import (
    is_abuse_guard_enabled,
    is_domain_verification_enabled,
    is_rate_limiting_enabled,
)

from engine.services.scan_submitter import ScanSubmitter, ScanSubmissionError
from engine.security import AbuseDecision, AbuseGuard, RateLimiter
from engine.scheduler.runtime import get_scheduler
from config.settings import settings
import logging

logger = logging.getLogger(__name__)
router = APIRouter()
abuse_guard = AbuseGuard()
rate_limiter = RateLimiter()
_SHARED_PLATFORM_SUFFIXES = (".vercel.app", ".netlify.app")


def _resolve_scan_pdf_path(scan_id: str, report_url: str | None) -> str | None:
    candidates: list[str] = []
    if report_url:
        candidates.append(report_url)

    scan_base = os.path.join(settings.SCAN_RESULTS_DIR, scan_id)
    candidates.extend(
        [
            os.path.join(scan_base, "report", "report.pdf"),
            os.path.join(scan_base, "Sentrion_Security_Report.pdf"),
            os.path.join(scan_base, "Gemini_Security_Report.pdf"),
            os.path.join(scan_base, "Report.pdf"),
        ]
    )

    seen: set[str] = set()
    for path in candidates:
        normalized = os.path.normpath(path)
        if normalized in seen:
            continue
        seen.add(normalized)
        if os.path.exists(normalized):
            return normalized

    return None


def _scan_base_dir(scan_id: str) -> Path:
    return Path(settings.SCAN_RESULTS_DIR) / scan_id


def _extract_client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def _target_domain(scan_in: ScanCreate) -> str | None:
    if not scan_in.target_url:
        return None
    return crud.normalize_domain(str(scan_in.target_url))


def _is_shared_platform_domain(domain: str) -> bool:
    return domain.endswith(_SHARED_PLATFORM_SUFFIXES)


def _resolve_trust_tier(raw_tier) -> TrustTier:
    if isinstance(raw_tier, TrustTier):
        return raw_tier
    try:
        return TrustTier(str(raw_tier))
    except Exception:
        return TrustTier.NEW


def _read_jsonl_tail(path: Path, limit: int) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    if not path.exists():
        return []

    items: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    items.append(parsed)
            except Exception:
                continue
    if len(items) <= limit:
        return items
    return items[-limit:]


@router.post("/start", status_code=status.HTTP_202_ACCEPTED)
async def start_scan(
    request: Request,
    scan_in: ScanCreate,
    db: AsyncSession = Depends(get_db_session),
    current_user=Depends(get_current_user),
):
    targets: Dict[str, str] = {}

    if scan_in.target_url:
        targets["target_url"] = str(scan_in.target_url)

    if scan_in.source_code_path:
        targets["source_code_path"] = scan_in.source_code_path

    if not targets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid scan target provided",
        )

    scan_id = str(uuid4())
    target_domain = _target_domain(scan_in)
    client_ip = _extract_client_ip(request)
    trust_tier = _resolve_trust_tier(getattr(current_user, "trust_tier", TrustTier.NEW))

    if trust_tier == TrustTier.SUSPENDED:
        await crud.create_scan_activity(
            db=db,
            user_id=current_user.id,
            domain=target_domain,
            scan_type=scan_in.profile.value,
            ip_address=client_ip,
            risk_score=100,
            outcome=ActivityOutcome.BLOCKED,
            reason="USER_SUSPENDED",
        )
        raise HTTPException(status_code=403, detail="Your account is suspended from scanning.")

    if scan_in.profile == ScanProfile.FULL and trust_tier != TrustTier.TRUSTED:
        await crud.create_scan_activity(
            db=db,
            user_id=current_user.id,
            domain=target_domain,
            scan_type=scan_in.profile.value,
            ip_address=client_ip,
            risk_score=0,
            outcome=ActivityOutcome.BLOCKED,
            reason="TRUST_TIER_RESTRICTED_SCAN_DEPTH",
        )
        raise HTTPException(status_code=403, detail="Your trust tier does not allow full-depth scans.")

    if target_domain and _is_shared_platform_domain(target_domain) and scan_in.profile == ScanProfile.FULL:
        await crud.create_scan_activity(
            db=db,
            user_id=current_user.id,
            domain=target_domain,
            scan_type=scan_in.profile.value,
            ip_address=client_ip,
            risk_score=0,
            outcome=ActivityOutcome.BLOCKED,
            reason="SHARED_PLATFORM_DOMAIN_RESTRICTED",
        )
        raise HTTPException(
            status_code=403,
            detail="Shared platform domains are restricted to lightweight scans.",
        )

    if target_domain and is_domain_verification_enabled():
        domain_record = await crud.get_domain_record(
            db,
            user_id=current_user.id,
            domain=target_domain,
        )
        if not domain_record or domain_record.status != DomainStatus.VERIFIED:
            await crud.create_scan_activity(
                db=db,
                user_id=current_user.id,
                domain=target_domain,
                scan_type=scan_in.profile.value,
                ip_address=client_ip,
                risk_score=0,
                outcome=ActivityOutcome.BLOCKED,
                reason="DOMAIN_NOT_VERIFIED",
            )
            raise HTTPException(
                status_code=403,
                detail="Domain ownership is not verified for this target.",
            )

    if is_abuse_guard_enabled():
        abuse_decision = await abuse_guard.evaluate(
            db=db,
            user_id=current_user.id,
            domain=target_domain,
            ip_address=client_ip,
            target_url=str(scan_in.target_url) if scan_in.target_url else None,
        )
        if abuse_decision.action == "BLOCK":
            await crud.create_scan_activity(
                db=db,
                user_id=current_user.id,
                domain=target_domain,
                scan_type=scan_in.profile.value,
                ip_address=client_ip,
                risk_score=abuse_decision.risk_score,
                outcome=ActivityOutcome.BLOCKED,
                reason="ABUSE_RISK_BLOCK",
                metadata_json={"reasons": abuse_decision.reasons},
            )
            raise HTTPException(
                status_code=403,
                detail="Scan blocked by abuse protection controls.",
            )
        if abuse_decision.action == "THROTTLE":
            await crud.create_scan_activity(
                db=db,
                user_id=current_user.id,
                domain=target_domain,
                scan_type=scan_in.profile.value,
                ip_address=client_ip,
                risk_score=abuse_decision.risk_score,
                outcome=ActivityOutcome.THROTTLED,
                reason="ABUSE_RISK_THROTTLE",
                metadata_json={"reasons": abuse_decision.reasons},
            )
            raise HTTPException(
                status_code=429,
                detail="Scan request throttled by abuse protection controls.",
            )
    else:
        abuse_decision = AbuseDecision(risk_score=0, action="ALLOW", reasons=[])

    if is_rate_limiting_enabled():
        rate_decision = await rate_limiter.evaluate(
            db=db,
            user_id=current_user.id,
            trust_tier=trust_tier,
            domain=target_domain,
            profile=scan_in.profile,
        )
        if not rate_decision.allowed:
            await crud.create_scan_activity(
                db=db,
                user_id=current_user.id,
                domain=target_domain,
                scan_type=scan_in.profile.value,
                ip_address=client_ip,
                risk_score=abuse_decision.risk_score,
                outcome=ActivityOutcome.THROTTLED,
                reason=rate_decision.reason,
            )
            raise HTTPException(
                status_code=429,
                detail=f"Scan request throttled: {rate_decision.reason}",
            )

    scheduler = get_scheduler()
    submitter = ScanSubmitter(scheduler)

    scan_request = {
        "scan_id": scan_id,
        "profile": scan_in.profile,
        "targets": targets,
        "auth_cookie": scan_in.auth_cookie,
        "enable_ai": scan_in.enable_ai,
    }

    try:
        submitter.validate_scan_request(scan_request)
    except ScanSubmissionError as exc:
        logger.warning(
            "Scan validation rejected | user_id=%s | reason=%s",
            current_user.id,
            exc.public_message,
        )
        raise HTTPException(
            status_code=exc.status_code,
            detail={
                "message": exc.public_message,
                "code": exc.code,
            },
        )

    try:
        db_scan = await crud.create_scan_job(
            db=db,
            job_id=scan_id,
            scan_in=scan_in,
            owner_id=current_user.id,
        )
    except Exception:
        logger.exception("Failed to create scan job row")
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Unable to create scan record right now. Please try again.",
                "code": "SCAN_RECORD_CREATE_FAILED",
            },
        )

    try:
        submitter.submit_scan(scan_request)
    except ScanSubmissionError as exc:
        logger.warning(
            "Scan submission rejected | user_id=%s | code=%s | reason=%s",
            current_user.id,
            exc.code,
            exc.public_message,
        )
        db_scan.status = ScanStatus.FAILED
        await db.commit()
        await crud.create_scan_activity(
            db=db,
            user_id=current_user.id,
            domain=target_domain,
            scan_type=scan_in.profile.value,
            ip_address=client_ip,
            risk_score=abuse_decision.risk_score,
            outcome=ActivityOutcome.BLOCKED,
            reason=f"SUBMISSION_REJECTED:{exc.code}",
        )
        raise HTTPException(
            status_code=exc.status_code,
            detail={
                "message": exc.public_message,
                "code": exc.code,
            },
        )
    except Exception:
        logger.exception("Scan submission failed")
        db_scan.status = ScanStatus.FAILED
        await db.commit()
        await crud.create_scan_activity(
            db=db,
            user_id=current_user.id,
            domain=target_domain,
            scan_type=scan_in.profile.value,
            ip_address=client_ip,
            risk_score=abuse_decision.risk_score,
            outcome=ActivityOutcome.BLOCKED,
            reason="SUBMISSION_INTERNAL_ERROR",
        )
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Unable to queue scan right now. Please try again.",
                "code": "SCAN_SUBMISSION_INTERNAL_ERROR",
            },
        )
    await crud.create_scan_activity(
        db=db,
        user_id=current_user.id,
        domain=target_domain,
        scan_type=scan_in.profile.value,
        ip_address=client_ip,
        risk_score=abuse_decision.risk_score,
        outcome=ActivityOutcome.ALLOWED,
        reason="SCAN_ACCEPTED",
    )
    return {
        "scan_id": db_scan.id,
        "job_id": db_scan.id,
        "target": db_scan.target_url or db_scan.source_code_path,
        "profile": db_scan.profile,
        "status": db_scan.status,
    }


@router.get("/", response_model=List[ScanJobSummary])
async def get_scan_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
    skip: int = 0,
    limit: int = 100,
):
    scans = await crud.get_scan_history(
        db,
        owner_id=current_user.id,
        skip=skip,
        limit=limit,
    )
    return [
        ScanJobSummary(
            id=scan.id,
            status=scan.status,
            profile=scan.profile,
            target=scan.target_url or scan.source_code_path or "N/A",
            highest_severity=scan.highest_severity,
            created_at=scan.created_at,
        )
        for scan in scans
    ]


@router.get("/{scan_id}", response_model=ScanJob)
async def get_scan_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    db_scan = await crud.get_scan_job(db, job_id=scan_id)
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if db_scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    return db_scan


@router.get("/{scan_id}/download")
async def download_scan_pdf(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    db_scan = await crud.get_scan_job(db, job_id=scan_id)
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if db_scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    file_path = _resolve_scan_pdf_path(scan_id=scan_id, report_url=db_scan.report_url)
    if not file_path:
        raise HTTPException(status_code=404, detail="PDF report file not found on server.")

    if db_scan.report_url != file_path:
        db_scan.report_url = file_path
        await db.commit()

    return FileResponse(
        path=file_path,
        filename=f"Sentinel_Report_{scan_id}.pdf",
        media_type="application/pdf",
    )


@router.get("/findings/all", response_model=List[ScanFinding])
async def get_all_vulnerabilities(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
    limit: int = 500,
):
    scans = await crud.get_scan_history(db, owner_id=current_user.id, limit=50)

    all_findings = []
    for scan in scans:
        if scan.status == "COMPLETED" and scan.findings:
            for finding_dict in scan.findings:
                target_name = scan.target_url or scan.source_code_path or "Unknown"
                finding = finding_dict.copy()
                original_loc = finding.get("location") or ""
                finding["location"] = f"[{target_name}] {original_loc}"
                all_findings.append(finding)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: sev_order.get(x.get("severity", "INFO"), 5))
    return all_findings[:limit]


@router.get("/{scan_id}/observability")
async def get_scan_observability_overview(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    db_scan = await crud.get_scan_job(db, job_id=scan_id)
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if db_scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    base = _scan_base_dir(scan_id)
    events_path = base / "scheduler_events.jsonl"
    alerts_path = base / "alerts.jsonl"
    timeline_path = base / "timeline.json"

    events_tail = _read_jsonl_tail(events_path, 10)
    alerts_tail = _read_jsonl_tail(alerts_path, 10)

    timeline = None
    if timeline_path.exists():
        try:
            timeline = json.loads(timeline_path.read_text(encoding="utf-8"))
        except Exception:
            timeline = None

    return {
        "scan_id": scan_id,
        "status": db_scan.status,
        "files": {
            "scheduler_events": str(events_path),
            "alerts": str(alerts_path),
            "timeline": str(timeline_path),
        },
        "counts": {
            "events_tail_count": len(events_tail),
            "alerts_tail_count": len(alerts_tail),
            "timeline_task_count": len((timeline or {}).get("tasks", {})),
        },
        "latest_events": events_tail,
        "latest_alerts": alerts_tail,
        "timeline_available": timeline is not None,
    }


@router.get("/{scan_id}/observability/events")
async def get_scan_scheduler_events(
    scan_id: str,
    limit: int = 200,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    db_scan = await crud.get_scan_job(db, job_id=scan_id)
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if db_scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    safe_limit = max(1, min(limit, 2000))
    path = _scan_base_dir(scan_id) / "scheduler_events.jsonl"
    items = _read_jsonl_tail(path, safe_limit)
    return {
        "scan_id": scan_id,
        "count": len(items),
        "items": items,
    }


@router.get("/{scan_id}/observability/alerts")
async def get_scan_scheduler_alerts(
    scan_id: str,
    limit: int = 200,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    db_scan = await crud.get_scan_job(db, job_id=scan_id)
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if db_scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    safe_limit = max(1, min(limit, 2000))
    path = _scan_base_dir(scan_id) / "alerts.jsonl"
    items = _read_jsonl_tail(path, safe_limit)
    return {
        "scan_id": scan_id,
        "count": len(items),
        "items": items,
    }


@router.get("/{scan_id}/observability/timeline")
async def get_scan_scheduler_timeline(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    db_scan = await crud.get_scan_job(db, job_id=scan_id)
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if db_scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    path = _scan_base_dir(scan_id) / "timeline.json"
    if not path.exists():
        return {"scan_id": scan_id, "available": False, "timeline": None}

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise HTTPException(status_code=500, detail="Timeline file is malformed")

    return {
        "scan_id": scan_id,
        "available": True,
        "timeline": payload,
    }



