from diverify.util.config import Config

config = Config('config/stack_config.conf')
DEFAULT_FULCIO_URL = config.get_fulcio_service_url()
DEFAULT_REKOR_URL = config.get_rekor_service_url()
DEFAULT_OAUTH_ISSUER_URL = config.get_oauth_issuer_url()

__all__ = [
    "DEFAULT_REKOR_URL", 
    "DEFAULT_FULCIO_URL", 
    "DEFAULT_OAUTH_ISSUER_URL"
]
