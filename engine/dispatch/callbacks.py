from engine.scheduler.scheduler import ScanScheduler

_scheduler: ScanScheduler | None = None


def init_scheduler(scheduler: ScanScheduler):
    global _scheduler
    _scheduler = scheduler


def notify_task_success(task_id: str, output: dict):
    assert _scheduler is not None
    _scheduler.on_task_complete(
        task_id=task_id,
        success=True,
        output=output,
    )


def notify_task_failure(task_id: str, error: str):
    assert _scheduler is not None
    _scheduler.on_task_complete(
        task_id=task_id,
        success=False,
        error=error,
    )
