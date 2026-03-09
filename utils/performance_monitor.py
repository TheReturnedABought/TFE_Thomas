"""
utils/performance_monitor.py — Simple wall-clock timer.

Used by analyzers to measure and report analysis duration.
"""

import time
from typing import Optional


class PerformanceMonitor:
    """Lightweight start/stop timer that tracks elapsed wall-clock time."""

    def __init__(self) -> None:
        self._start: Optional[float] = None
        self._end: Optional[float] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_timer(self) -> None:
        """Start (or restart) the timer."""
        self._start = time.perf_counter()
        self._end = None

    def stop_timer(self) -> None:
        """
        Stop the timer.

        Raises:
            RuntimeError: If start_timer() was never called.
        """
        if self._start is None:
            raise RuntimeError(
                "PerformanceMonitor: stop_timer() called before start_timer()."
            )
        self._end = time.perf_counter()

    def get_duration(self) -> Optional[float]:
        """
        Return elapsed time in seconds.

        - If the timer has been stopped, returns the fixed duration.
        - If the timer is still running, returns the current elapsed time.
        - If the timer was never started, returns None.
        """
        if self._start is None:
            return None
        end = self._end if self._end is not None else time.perf_counter()
        return round(end - self._start, 4)

    def reset(self) -> None:
        """Reset the timer to its initial state."""
        self._start = None
        self._end = None

    def __repr__(self) -> str:  # pragma: no cover
        duration = self.get_duration()
        return f"PerformanceMonitor(duration={duration}s)"
