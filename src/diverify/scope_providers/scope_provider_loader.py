import importlib
from typing import Any

def load_scope_provider(verifier_name: str) -> Any:
    """Loads a trust verifier and returns its instance."""
    module_name = f"diverify.scope_providers.{verifier_name}"
    module = importlib.import_module(module_name)
    
    class_name_parts = verifier_name.split('_')
    class_name = ''.join(part.capitalize() for part in class_name_parts) + "ScopeProvider"
    verifier_class = getattr(module, class_name)
    
    return verifier_class()
