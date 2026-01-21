import inspect
from typing import Dict, Any, Callable


class ToolRunnerAdapter:
    """
    Normalizes heterogeneous tool runner signatures into a single call contract.

    Supported input parameters (one required):
    - target_url
    - target
    - src_path

    Required:
    - output_dir
    """

    def __init__(self, runner: Callable[..., Dict[str, Any]]):
        self.runner = runner
        self.sig = inspect.signature(runner)
        self.params = self.sig.parameters

    def __call__(
        self,
        *,
        target_url: str | None = None,
        src_path: str | None = None,
        output_dir: str,
        **extra,
    ) -> Dict[str, Any]:

        call_kwargs: Dict[str, Any] = {"output_dir": output_dir}

        # --- URL-based tools ---
        if "target_url" in self.params:
            if not target_url:
                raise RuntimeError(
                    f"{self.runner.__name__} requires target_url"
                )
            call_kwargs["target_url"] = target_url

        elif "target" in self.params:
            if not target_url:
                raise RuntimeError(
                    f"{self.runner.__name__} requires target"
                )
            call_kwargs["target"] = target_url

        # --- Source-based tools ---
        elif "src_path" in self.params:
            if not src_path:
                raise RuntimeError(
                    f"{self.runner.__name__} requires src_path"
                )
            call_kwargs["src_path"] = src_path

        else:
            raise RuntimeError(
                f"Unsupported tool signature: {self.runner.__name__}{self.sig}"
            )

        try:
            return self.runner(**call_kwargs)

        except TypeError as exc:
            raise RuntimeError(
                f"Tool runner invocation failed: {self.runner.__name__}{self.sig}"
            ) from exc
