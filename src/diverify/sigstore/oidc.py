import base64
import hashlib
import http.server
import os
import socketserver
import uuid
import webbrowser
from threading import Event, Thread
from typing import Tuple
from urllib import parse
import jwt
import requests
from diverify.sigstore import DEFAULT_OAUTH_ISSUER_URL


class OIDCAuthenticator:
    """Handles OIDC authentication flows for DiVerify."""
    
    def __init__(self, oauth_issuer_url: str = DEFAULT_OAUTH_ISSUER_URL):
        self.oauth_issuer_url = oauth_issuer_url
    
    def get_identity_token(self, nonce, limit_scope: bool = False) -> Tuple[str, dict]:
        """Retrieve an identity token using OAuth2 with Dex.
        
        Args:
            limit_scope: Whether to limit scope to specific repositories
            
        Returns:
            Tuple of (raw_token, decoded_token)
        """
        client_id = "sigstore"
        client_secret = ""

        auth_code, redirect_uri, code_verifier = self._get_authorization_code(
            nonce, client_id, client_secret, limit_scope=limit_scope
        )

        response = requests.post(
            f"{self.oauth_issuer_url}/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            }
        )

        response.raise_for_status() 
        response_json = response.json()
        
        raw_token = response_json.get("id_token")
        if not raw_token:
            raise KeyError("Response does not contain 'id_token'")

        decoded_token = jwt.decode(raw_token, options={"verify_signature": False})
        return raw_token, decoded_token

    def _get_authorization_code(self, nonce, client_id: str, client_secret: str, limit_scope: bool = False) -> Tuple[str, str, str]:
        class AuthHandler(http.server.BaseHTTPRequestHandler):
            """Handles the OAuth2 redirect and extracts the auth code."""
            def do_GET(self):
                parsed_path = parse.urlparse(self.path)
                query_params = parse.parse_qs(parsed_path.query)
                if "code" in query_params:
                    self.server.auth_code = query_params["code"][0]
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Authentication successful. You can close this window.")
                    self.server.auth_event.set()
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Authentication failed.")

        # Start local server
        server = socketserver.TCPServer(("localhost", 0), AuthHandler, bind_and_activate=False)
        server.allow_reuse_address = True
        server.server_bind()
        server.server_activate()
        port = server.server_address[1]
        redirect_uri = f"http://localhost:{port}/callback"
        
        # Generate PKCE parameters
        code_verifier, code_challenge = self._generate_pkce_challenge()
        state = str(uuid.uuid4())

        scope = "openid+email"
        # TODO: Add repo scope when Dex supports it
        # if limit_scope:
        #     scope += "+repo" 

        auth_url = (
            f"{self.oauth_issuer_url}/auth?"
            f"response_type=code&client_id={client_id}&client_secret={client_secret}&"
            f"scope={scope}&redirect_uri={redirect_uri}&"
            f"code_challenge={code_challenge}&code_challenge_method=S256&"
            f"state={state}&nonce={nonce}"
        )

        print(f"Opening browser for login: {auth_url}")
        webbrowser.open(auth_url)
        
        server.auth_event = Event()
        server_thread = Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        print("Waiting for authentication...")
        server.auth_event.wait()  

        auth_code = server.auth_code
        server.shutdown()
        return auth_code, redirect_uri, code_verifier

    @staticmethod
    def _generate_pkce_challenge() -> Tuple[str, str]:
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()
        return code_verifier, code_challenge
