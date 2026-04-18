"""GraphQL client for Check Point WAF API."""

from typing import Any
import httpx
from .auth import AuthClient

GRAPHQL_V1_PATH = "/app/waf/graphql/v1"
GRAPHQL_V2_PATH = "/app/waf/graphql/v2"


class GraphQLClient:
    """Executes GraphQL queries against Check Point WAF API."""

    def __init__(self, auth: AuthClient):
        self.auth = auth

    async def execute(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        use_v2: bool = False,
    ) -> dict[str, Any]:
        """Execute a GraphQL query/mutation.

        Args:
            query: GraphQL query or mutation string.
            variables: Optional variables dict.
            use_v2: Use v2 endpoint (needed for tuning queries).

        Returns:
            The 'data' portion of the GraphQL response.

        Raises:
            RuntimeError: On GraphQL errors.
        """
        token = await self.auth.get_token()
        path = GRAPHQL_V2_PATH if use_v2 else GRAPHQL_V1_PATH
        url = f"{self.auth.base_url}{path}"

        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                },
                timeout=60,
            )
            resp.raise_for_status()
            result = resp.json()

        if "errors" in result:
            raise RuntimeError(f"GraphQL errors: {result['errors']}")

        return result.get("data", {})
