from datetime import datetime
from typing import Dict

from croniter import croniter
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.crud import get_due_schedules
from engine.services.scan_submitter import ScanSubmitter


class ScheduleLoader:
    """
    Loads due schedules from DB and converts them
    into normal scan submissions.

    DOES NOT touch scheduler internals.
    """

    def __init__(self, submitter: ScanSubmitter):
        self.submitter = submitter

    async def dispatch_due_schedules(self, db: AsyncSession) -> int:
        due = await get_due_schedules(db)
        dispatched = 0

        for schedule in due:
            scan_request = self._schedule_to_scan_request(schedule)

            try:
                self.submitter.submit_scan(scan_request)
                self._update_next_run(schedule)
                dispatched += 1
            except Exception:
                # Scheduler failure must not corrupt DB
                continue

        return dispatched

    def _schedule_to_scan_request(self, schedule) -> Dict:
        targets = {}

        if schedule.target_url:
            targets["target_url"] = schedule.target_url

        if schedule.source_code_path:
            targets["source_code_path"] = schedule.source_code_path

        return {
            "profile": schedule.profile,
            "targets": targets,
            "auth_cookie": schedule.auth_cookie,
            "scheduled": True,  # metadata only
        }

    def _update_next_run(self, schedule):
        base = schedule.next_run_at or datetime.utcnow()
        itr = croniter(schedule.crontab, base)
        schedule.last_run_at = datetime.utcnow()
        schedule.next_run_at = itr.get_next(datetime)
