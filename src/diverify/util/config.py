import tomli
from pathlib import Path
from typing import Dict, Any


class Config:
    """
    Represents a DiVerify configuration object.
    """
    
    def __init__(self, file_path: str) -> None:
        """ Parses a TOML-formatted config file
            and populates the underlying config dict.
        """
        self.file_path = file_path
        self.config_dict = self._load_config()
        
        # Initialize service URLs
        self.fulcio_service_url = ""
        self.rekor_service_url = ""
        self.oauth_issuer_url = ""
        self.diverify_url = ""
        self.tuf_url = ""
        self.kms_service_url = ""
        self.sigstore_trusted_root = ""
        
        # Parse configuration
        self._parse_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load and parse the TOML configuration file."""
        try:
            with open(self.file_path, "rb") as f:
                return tomli.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.file_path}")
        except tomli.TOMLDecodeError as e:
            raise ValueError(f"Invalid TOML format in {self.file_path}: {e}")

    def _parse_config(self) -> None:
        """Parse the configuration dictionary and set instance variables."""
        # Get settings section
        settings = self.config_dict.get("settings", {})
        
        # Parse URLs from settings
        self.fulcio_service_url = settings.get("fulcio_url", "")
        self.rekor_service_url = settings.get("rekor_url", "")
        self.oauth_issuer_url = settings.get("oauth_issuer_url", "")
        self.diverify_url = settings.get("diverify_url", "")
        self.tuf_url = settings.get("tuf_url", "")
        self.sigstore_trusted_root = settings.get("sigstore_trusted_root", "")

    def get_fulcio_service_url(self) -> str:
        """ Returns the Fulcio service URL, if specified."""
        return self.fulcio_service_url

    def get_rekor_service_url(self) -> str:
        """ Returns the Rekor service URL, if specified."""
        return self.rekor_service_url

    def get_oauth_issuer_url(self) -> str:
        """ Returns the OAuth issuer URL, if specified."""
        return self.oauth_issuer_url

    def get_diverify_url(self) -> str:
        """ Returns the DiVerify service URL, if specified."""
        return self.diverify_url

    def get_tuf_url(self) -> str:
        """ Returns the TUF service URL, if specified."""
        return self.tuf_url

    def get_sigstore_trusted_root_path(self) -> Path:
        """ Returns the Sigstore trusted root as a Path object, if specified."""
        path = Path(self.sigstore_trusted_root).resolve()
        return path
    
    def get_sigstore_trusted_root(self) -> str:
        """ Returns the Sigstore trusted root path, if specified."""
        return self.sigstore_trusted_root
    