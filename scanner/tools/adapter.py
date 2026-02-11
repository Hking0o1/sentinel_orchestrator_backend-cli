import inspect
import logging
from typing import Dict, Any, Callable

logger = logging.getLogger(__name__)
class ToolRunnerAdapter:
    def __init__(self, runner: Callable[..., Dict[str, Any]]):
        self.runner = runner
        self._params = inspect.signature(runner).parameters

    def __call__(
        self,
        *,
        target_url: str | None = None,
        src_path: str | None = None,
        auth_cookie: str | None = None,
        output_dir: str,
        **_,
    ) -> Dict[str, Any]:
        return self.run(
            target_url=target_url,
            src_path=src_path,
            auth_cookie=auth_cookie,
            output_dir=output_dir,
        )

    def run(
        self,
        *,
        target_url: str | None = None,
        src_path: str | None = None,
        auth_cookie: str | None = None,
        output_dir: str,
    ) -> Dict[str, Any]:
        call_kwargs = {"output_dir": output_dir}

        if "src_path" in self._params and src_path is not None:
            call_kwargs["src_path"] = src_path

        elif "target_url" in self._params and target_url is not None:
            call_kwargs["target_url"] = target_url

        elif "target" in self._params and target_url is not None:
            call_kwargs["target"] = target_url

        else:
            raise RuntimeError(
                f"{self.runner.__name__} requires target_url or src_path"
            )

        if "auth_cookie" in self._params and auth_cookie is not None:
            call_kwargs["auth_cookie"] = auth_cookie

        try:
            logger.info(
                "Running tool | runner=%s | kwargs=%s",
                self.runner.__name__,
                call_kwargs,
            )
            return self.runner(**call_kwargs)
        except TypeError as exc:
            raise RuntimeError(
                f"Tool runner signature mismatch: {self.runner.__name__}"
            ) from exc
