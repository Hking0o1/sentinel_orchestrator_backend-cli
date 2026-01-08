class ResourceBudget:
    """
    Bounded execution resource controller.

    Represents abstract execution pressure
    (CPU, memory, IO combined).
    """

    __slots__ = ("_total", "_available")

    def __init__(self, total_units: int):
        assert total_units > 0
        self._total: int = total_units
        self._available: int = total_units

    @property
    def total(self) -> int:
        return self._total

    @property
    def available(self) -> int:
        return self._available

    def can_allocate(self, units: int) -> bool:
        return units <= self._available

    def allocate(self, units: int) -> None:
        if units > self._available:
            raise RuntimeError("Resource budget exceeded")
        self._available -= units

    def release(self, units: int) -> None:
        self._available += units
        if self._available > self._total:
            raise RuntimeError("Resource budget over-release")
        
    #test
    def test_resource_budget():
        rb = ResourceBudget(4)
        rb.allocate(3)
        assert rb.available == 1
        rb.release(3)
        assert rb.available == 4

