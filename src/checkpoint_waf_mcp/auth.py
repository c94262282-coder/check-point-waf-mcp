"""Authentication for Check Point Infinity Portal."""

import time

import httpx

# Region is still validated for config sanity, but this tenant flow uses the
# global Infinity Portal hostname for both auth and GraphQL.
VALID_REGIONS = {"us", "eu", "ap", "au", "in"}

# Auth uses the global Infinity Portal endpoint for external users.
AUTH_BASE_URL = "https://cloudinfra-gw.portal.checkpoint.com"
AUTH_PATH = "/auth/external/user"


class AuthClient:
    """Handles JWT token acquisition and caching for Check Point API."""

    def __init__(self, client_id: str, access_key: str, region: str = "us"):
        self.client_id = client_id
        self.access_key = access_key
        if region.lower() not in VALID_REGIONS:
            raise ValueError(f"Unknown region '{region}'. Valid: {sorted(VALID_REGIONS)}")
        self.base_url = AUTH_BASE_URL
        self.auth_url = f"{AUTH_BASE_URL}{AUTH_PATH}"
        self._token: str | None = None
        self._token_expiry: float = 0

    async def get_token(self) -> str:
        """Get a valid JWT token, refreshing if needed."""
        # Refresh if token expires in less than 60 seconds
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        return await self._refresh_token()

    async def _refresh_token(self) -> str:
        """Acquire a new JWT token from Infinity Portal."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.auth_url,
                json={
                    "clientId": self.client_id,
                    "accessKey": self.access_key,
                },
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            resp.raise_for_status()
            try:
                data = resp.json()
            except ValueError as exc:
                raise RuntimeError(
                    "Authentication endpoint returned a non-JSON response. "
                    "Check the configured region and API credentials."
                ) from exc

        token = data.get("data", {}).get("token")
        if not token:
            raise RuntimeError(f"No token in auth response: {data}")
        
        self._token = token
        # Tokens typically last 3600s; assume 3600 if not provided
        expires_in = data.get("data", {}).get("expiresIn", 3600)
        self._token_expiry = time.time() + expires_in
        return self._token
