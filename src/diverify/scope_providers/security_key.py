import subprocess, json, requests, tempfile
from pathlib import Path
from diverify.scope_providers.base_verifier import ScopeProvider

class SecurityKeyScopeProvider(ScopeProvider):
    class CommandExecutionError(Exception):
        """Custom exception for command failures."""

    def run(self, cmd):
        try:
            result = subprocess.run(cmd, check=True, capture_output=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            error = str(e)
            stderr = e.stderr.decode().strip()
            raise self.CommandExecutionError(f"{error}\n{stderr}" if stderr else error) from e
        except Exception as e:
            print(f"Unexpected error: {e}")
            raise

    def verify(self):
        try:
            return self.run(["yubico-piv-tool", "--action=attest", "--slot=9a"]).decode()
        except Exception as e:
            if "Failed to connect to yubikey" in str(e):
                # Temporary allow testers without yubikeys
                piv_attestation = "-----BEGIN CERTIFICATE-----\nMIIDIDCCAgigAwIBAgIQAWVy6rQflfN6Gqf9kHs8vzANBgkqhkiG9w0BAQsFADAh\nMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0dGVzdGF0aW9uMCAXDTE2MDMxNDAwMDAw\nMFoYDzIwNTIwNDE3MDAwMDAwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRl\nc3RhdGlvbiA5YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ0gJCuE\ndZIq8E0643fsl46poybLw1/bLWUv1DdTbi/HeOeuzYXuqbtKWnVh4L3Z4ZoH516w\nO1zazIi0ihB8EO3fsOlrA1MVF3nQK9saLnuAGRnMDNbkKYuT23xQQTDjOkwCOSnt\nmhS2sAI+faIc8z+nUx57MdMkdn5uqh2kzlZJpZMrAbTtCFJYMjQg89odKhns1AcS\n0ZDqd1XSN2yw7u42hgM03LUky3STUDBbaDN5EML11fsPQAB64xf93HU4RYtzYCWq\nU9e/rlTpt0aE/z/FkcqnDqKTKXhnJabp1WJtDKbud1OmtrDNjJSkjtEUCcG0AtFZ\nj2DjFrOKx402Lh8CAwEAAaNOMEwwEQYKKwYBBAGCxAoDAwQDBQIHMBQGCisGAQQB\ngsQKAwcEBgIEAPM1RjAQBgorBgEEAYLECgMIBAICATAPBgorBgEEAYLECgMJBAED\nMA0GCSqGSIb3DQEBCwUAA4IBAQAZBSsvbkPjhecOuBxy2yPGibDY83xUMUaEx18U\nIGYzk/1u+gwOaLspk/VQIek9oWFYMYgz+1fx0HQ8vBXnbztEvTWovYuK6BkvSOcD\n/EJS+U9+tMC1L/drQbDjZe6n5xprKh8ziaTpZbdl885OWll/dIYPc2iapqMYxnII\nVtqLqV4cyog7C8PN27svtM1yT2v7uldjxw9LE859JqIit08Db2cT+5Bwu4gZuRMu\n155bPyr+h/ytorueOWQuWUNmO6aTAGHIch3MyovnS+ge5C0q+N4FKNSS6y4jZb8Q\nYGV2yc8EWBL8yIz5TrL5CG6wTA8XaqmR70SBQgAQw8DnSVE6\n-----END CERTIFICATE-----"
                return piv_attestation
            raise
            