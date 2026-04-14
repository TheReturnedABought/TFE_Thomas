import time

from utils.performance_monitor import PerformanceMonitor


class Test_PerformanceMonitor___init__:
    def test_init(self):
        """Test init."""
        pm = PerformanceMonitor()
        assert pm._start is None


class Test_PerformanceMonitor_start_timer:
    def test_start_sets_time(self):
        """Test start sets time."""
        pm = PerformanceMonitor()
        pm.start_timer()
        assert pm._start is not None


class Test_PerformanceMonitor_stop_timer:
    def test_stop_sets_end(self):
        """Test stop sets end."""
        pm = PerformanceMonitor()
        pm.start_timer()
        pm.stop_timer()
        assert pm._end is not None


class Test_PerformanceMonitor_get_duration:
    def test_returns_float(self):
        """Test returns float."""
        pm = PerformanceMonitor()
        pm.start_timer()
        time.sleep(0.01)
        pm.stop_timer()
        d = pm.get_duration()
        assert isinstance(d, float)
        assert d >= 0.01

    def test_returns_none_before_start(self):
        """Test returns none before start."""
        pm = PerformanceMonitor()
        assert pm.get_duration() is None


class Test_PerformanceMonitor_start_stop:
    def test_timing(self):
        """Test timing."""
        pm = PerformanceMonitor()
        pm.start_timer()
        time.sleep(0.01)
        pm.stop_timer()
        assert pm.get_duration() >= 0.01


class Test_PerformanceMonitor_reset:
    def test_reset(self):
        """Test reset."""
        pm = PerformanceMonitor()
        pm.start_timer()
        pm.stop_timer()
        pm.reset()
        assert pm.get_duration() is None
        assert pm._start is None
