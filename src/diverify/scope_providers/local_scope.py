import requests
from diverify.scope_providers.base_verifier import ScopeProvider

class LocalScopeScopeProvider(ScopeProvider):
    def verify(self, **kwargs) -> dict:
        """Get the local scope of a user in a repository."""
        required_keys = ["identity_token", "repo_full_name", "username"]
        missing = [key for key in required_keys if key not in kwargs]
        if missing:
            raise ValueError(f"Missing required parameters: {', '.join(missing)}")

        url = f"https://api.github.com/repos/{kwargs['repo_full_name']}/collaborators/{kwargs['username']}/permission"
        headers = {'Authorization': f'token {kwargs["identity_token"]}', 'Accept': 'application/vnd.github.v3+json'}
        
        response = requests.get(url, headers=headers)
        response.raise_for_status() 
        return response.json()
