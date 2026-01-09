# engine/planner/exceptions.py

class PlannerError(Exception):
    """Base class for planning errors"""


class InvalidScanRequest(PlannerError):
    pass


class UnsupportedProfile(PlannerError):
    pass


class ToolResolutionError(PlannerError):
    pass
