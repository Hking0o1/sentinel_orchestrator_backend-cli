import inspect
from typing import Dict, Any, Callable


class ToolRunnerAdapter:
    """
    Adapts heterogeneous tool runner signatures
    to a uniform execution interface.
    """

    def __init__(self, runner: Callable[..., Dict[str, Any]]):
        self.runner = runner
        self._params = inspect.signature(runner).parameters

    def run(
        self,
        *,
        target: str | None = None,
        src_path: str | None = None,
        output_dir: str,
        **kwargs,
    ) -> Dict[str, Any]:
        try:
            call_kwargs = {"output_dir": output_dir}

            if "src_path" in self._params and src_path is not None:
                call_kwargs["src_path"] = src_path
            elif "target" in self._params and target is not None:
                call_kwargs["target"] = target
            else:
                raise ValueError(
                    f"Tool {self.runner.__name__} does not accept "
                    f"src_path or target"
                )

            return self.runner(**call_kwargs)

        except TypeError as exc:
            raise RuntimeError(
                f"Tool runner signature mismatch: {self.runner.__name__}"
            ) from exc
