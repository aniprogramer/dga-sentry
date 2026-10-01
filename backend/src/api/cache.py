"""
Thread-safe in-memory prediction cache for DGA domain detection.

Provides bounded LRU caching to eliminate redundant feature extraction
and model inference on recurrent domains.
"""

from collections import OrderedDict
import threading
from typing import Any


class PredictionCache:
    """
    Thread-safe, bounded Least Recently Used (LRU) prediction cache.
    """

    def __init__(self, max_size: int = 10000, enabled: bool = True):
        self.max_size = max_size
        self.enabled = enabled
        self._cache: OrderedDict[str, Any] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get(self, key: str) -> Any | None:
        """
        Retrieve a prediction result from cache by key.
        Returns a defensive deep copy if the value has model_copy, or None on miss.
        """
        if not self.enabled:
            return None
        with self._lock:
            if key in self._cache:
                self.hits += 1
                self._cache.move_to_end(key)
                val = self._cache[key]
                if hasattr(val, "model_copy"):
                    return val.model_copy(deep=True)
                return val
            self.misses += 1
            return None

    def set(self, key: str, value: Any) -> None:
        """
        Store a prediction result in cache, evicting the oldest entry if at capacity.
        """
        if not self.enabled or self.max_size <= 0:
            return
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                self._cache[key] = value
            else:
                if len(self._cache) >= self.max_size:
                    self._cache.popitem(last=False)
                    self.evictions += 1
                self._cache[key] = value

    def clear(self) -> None:
        """
        Reset cache entries and performance counters.
        """
        with self._lock:
            self._cache.clear()
            self.hits = 0
            self.misses = 0
            self.evictions = 0

    def stats(self) -> dict:
        """
        Return snapshot of cache metrics.
        """
        with self._lock:
            total = self.hits + self.misses
            return {
                "enabled": self.enabled,
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "hit_ratio": round(self.hits / total, 4) if total > 0 else 0.0,
            }
