from engine.scheduler.dag import TaskDescriptor

def build_scan_dag(scan_config) -> list[TaskDescriptor]:
    """
    PURE FUNCTION

    Input: scan_config (from CLI/API)
    Output: list of TaskDescriptor with dependencies

    - No Celery
    - No retries
    - No execution
    """

