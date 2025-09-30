from abc import ABC, abstractmethod
from typing import Any

class ScopeProvider(ABC):
    @abstractmethod
    def verify(self, **kwargs) -> Any:
        """ Verify trust based on the provided arguments."""
        pass
