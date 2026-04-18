"""Check Point WAF MCP Server."""

import json
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from .auth import AuthClient
from .graphql_client import GraphQLClient

mcp = FastMCP(
    "Check Point WAF",
    description="MCP server for Check Point CloudGuard WAF management via GraphQL API",
)

# Lazy-init globals
_auth: AuthClient | None = None
_gql: GraphQLClient | None = None


def _get_clients() -> tuple[AuthClient, GraphQLClient]:
    """Initialize and return auth + GraphQL clients."""
    global _auth, _gql
    if _auth is None:
        client_id = os.environ.get("CHECKPOINT_CLIENT_ID", "")
        access_key = os.environ.get("CHECKPOINT_ACCESS_KEY", "")
        region = os.environ.get("CHECKPOINT_REGION", "us")
        if not client_id or not access_key:
            raise RuntimeError(
                "Set CHECKPOINT_CLIENT_ID and CHECKPOINT_ACCESS_KEY environment variables"
            )
        _auth = AuthClient(client_id, access_key, region)
        _gql = GraphQLClient(_auth)
    return _auth, _gql


def _fmt(data: Any) -> str:
    """Format response data as JSON string."""
    return json.dumps(data, indent=2, default=str)


# ──────────────────────────────────────────────
# QUERY TOOLS
# ──────────────────────────────────────────────


@mcp.tool()
async def list_assets(
    match_search: str = "",
    user_defined: bool = True,
) -> str:
    """List all WAF assets (web applications, APIs, etc.).

    Args:
        match_search: Optional search filter string.
        user_defined: If true, filter to user-defined assets only (excludes system defaults).
    """
    _, gql = _get_clients()
    # Build args
    args = []
    if user_defined:
        args.append("userDefined: true")
    if match_search:
        args.append(f'matchSearch: "{match_search}"')
    arg_str = f"({', '.join(args)})" if args else ""
    query = f"""
    query {{
        getAssets{arg_str} {{
            assets {{
                id
                name
                assetType
                status
                state
                mainAttributes
                family
                category
                class
                kind
                group
            }}
        }}
    }}
    """
    data = await gql.execute(query)
    return _fmt(data.get("getAssets", {}))


@mcp.tool()
async def get_asset(asset_id: str) -> str:
    """Get detailed information about a specific asset by ID.

    Args:
        asset_id: The unique identifier of the asset.
    """
    _, gql = _get_clients()
    query = """
    query getAsset($id: String!) {
        getAsset(id: $id) {
            id
            name
            assetType
            status
            state
            mainAttributes
            family
            category
            class
            kind
            group
            tags { id name }
            profiles { id name }
            practices { 
                practiceId
                mainMode
                subPracticeModes { mode subPractice }
            }
        }
    }
    """
    data = await gql.execute(query, {"id": asset_id})
    return _fmt(data.get("getAsset", {}))


@mcp.tool()
async def get_web_application_asset(asset_id: str) -> str:
    """Get full details of a Web Application asset including URLs and proxy settings.

    Args:
        asset_id: The unique identifier of the web application asset.
    """
    _, gql = _get_clients()
    query = """
    query getWebApplicationAsset($id: ID!) {
        getWebApplicationAsset(id: $id) {
            id
            name
            assetType
            status
            state
            stage
            upstreamURL
            deployCertificateManually
            URLs { id URL }
            proxySetting { id key value }
            sourceIdentifiers { id sourceIdentifier values { id value } }
            practices {
                practiceId
                mainMode
                subPracticeModes { mode subPractice }
            }
            profiles { id name }
            tags { id name }
        }
    }
    """
    data = await gql.execute(query, {"id": asset_id})
    return _fmt(data.get("getWebApplicationAsset", {}))


@mcp.tool()
async def get_asset_tuning(asset_id: str) -> str:
    """Get tuning suggestions for an asset. Shows detected events that may need tuning.

    Args:
        asset_id: The unique identifier of the asset to get tuning for.
    """
    _, gql = _get_clients()
    query = """
    query getAssetTuning($id: String!) {
        getAssetTuning(id: $id) {
            attackTypes
            decision
            eventTitle
            eventType
            logQuery
            policyVersion
            severity
        }
    }
    """
    data = await gql.execute(query, {"id": asset_id}, use_v2=True)
    return _fmt(data.get("getAssetTuning", []))


@mcp.tool()
async def get_asset_tuning_review(asset_id: str) -> str:
    """Get tuning review decisions for an asset (decisions taken regarding tuning events).

    Args:
        asset_id: The unique identifier of the asset.
    """
    _, gql = _get_clients()
    query = """
    query getAssetTuningReview($id: String!) {
        getAssetTuningReview(id: $id) {
            decision
            eventType
            eventTitle
            severity
            logQuery
            attackTypes
            policyVersion
        }
    }
    """
    data = await gql.execute(query, {"id": asset_id}, use_v2=True)
    return _fmt(data.get("getAssetTuningReview", []))


@mcp.tool()
async def get_asset_statistics(asset_id: str) -> str:
    """Get traffic and security statistics for an asset.

    Args:
        asset_id: The unique identifier of the asset.
    """
    _, gql = _get_clients()
    query = """
    query getAssetStatistics($id: String!) {
        getAssetStatistics(id: $id) {
            totalRequests
            maliciousRequests
            legitimateRequests
            criticalRequests
            highRequests
            uniqueSources
            uniqueUrls
            elapsedTime
            status
            readiness
            readinessDisplayName
            readinessToolTip
            recommendation
            recommendationDisplayName
            recommendationToolTip
            startupTime
        }
    }
    """
    data = await gql.execute(query, {"id": asset_id})
    return _fmt(data.get("getAssetStatistics", {}))


@mcp.tool()
async def list_profiles(match_search: str = "") -> str:
    """List all agent profiles (gateways, Docker, Kubernetes, etc.).

    Args:
        match_search: Optional search filter string.
    """
    _, gql = _get_clients()
    args = f'(matchSearch: "{match_search}")' if match_search else ""
    query = f"""
    query {{
        getProfiles{args} {{
            id
            name
        }}
    }}
    """
    data = await gql.execute(query)
    return _fmt(data.get("getProfiles", []))


@mcp.tool()
async def get_profile(profile_id: str) -> str:
    """Get detailed information about a specific profile.

    Args:
        profile_id: The unique identifier of the profile.
    """
    _, gql = _get_clients()
    query = """
    query getProfile($id: ID!) {
        getProfile(id: $id) {
            id
            name
        }
    }
    """
    data = await gql.execute(query, {"id": profile_id})
    return _fmt(data.get("getProfile", {}))


@mcp.tool()
async def list_agents(match_search: str = "") -> str:
    """List all connected agents/gateways.

    Args:
        match_search: Optional search filter string.
    """
    _, gql = _get_clients()
    args = f'(matchSearch: "{match_search}")' if match_search else ""
    query = f"""
    query {{
        getAgents{args} {{
            id
            name
        }}
    }}
    """
    data = await gql.execute(query)
    return _fmt(data.get("getAgents", []))


@mcp.tool()
async def list_practices(
    match_search: str = "",
    practice_type: str = "",
    include_private: bool = False,
) -> str:
    """List all security practices (WAF, API Security, etc.).

    Args:
        match_search: Optional search filter string.
        practice_type: Optional type filter (e.g. 'WebApplication', 'WebAPI').
        include_private: Include privately-owned (local) practices.
    """
    _, gql = _get_clients()
    args = []
    if match_search:
        args.append(f'matchSearch: "{match_search}"')
    if practice_type:
        args.append(f"practiceType: {practice_type}")
    if include_private:
        args.append("includePrivatePractices: true")
    arg_str = f"({', '.join(args)})" if args else ""
    query = f"""
    query {{
        getPractices{arg_str} {{
            id
            name
            practiceType
            visibility
            category
            default
        }}
    }}
    """
    data = await gql.execute(query)
    return _fmt(data.get("getPractices", []))


@mcp.tool()
async def get_web_application_practice(practice_id: str) -> str:
    """Get detailed Web Application Practice (WAF) configuration.

    Args:
        practice_id: The unique identifier of the practice.
    """
    _, gql = _get_clients()
    query = """
    query getWebApplicationPractice($id: ID!) {
        getWebApplicationPractice(id: $id) {
            id
            name
            practiceType
            visibility
            category
            default
            IPS {
                performanceImpact
                severityLevel
                protectionsFromYear
                highConfidence
                mediumConfidence
                lowConfidence
            }
            WebAttacks {
                minimumSeverity
                advancedSetting {
                    CSRFProtection
                    openRedirect
                    errorDisclosure
                    bodySize
                    urlSize
                    headerSize
                    maxObjectDepth
                    illegalHttpMethods
                }
            }
            WebBot {
                injectURIs
                validURIs
            }
        }
    }
    """
    data = await gql.execute(query, {"id": practice_id})
    return _fmt(data.get("getWebApplicationPractice", {}))


@mcp.tool()
async def get_overview() -> str:
    """Get a high-level overview of configured objects (assets, practices, profiles, etc.)."""
    _, gql = _get_clients()
    query = """
    query {
        getOverview {
            assets
            practices
            profiles
            triggers
            zones
        }
    }
    """
    data = await gql.execute(query)
    return _fmt(data.get("getOverview", {}))


@mcp.tool()
async def list_log_triggers(match_search: str = "") -> str:
    """List all log trigger configurations.

    Args:
        match_search: Optional search filter.
    """
    _, gql = _get_clients()
    args = f'(matchSearch: "{match_search}")' if match_search else ""
    query = f"""
    query {{
        getTriggers{args} {{
            id
            name
            triggerType
        }}
    }}
    """
    data = await gql.execute(query)
    return _fmt(data.get("getTriggers", []))


# ──────────────────────────────────────────────
# MUTATION TOOLS
# ──────────────────────────────────────────────


@mcp.tool()
async def publish_changes() -> str:
    """Publish all pending configuration changes. Required after any create/update/delete operations."""
    _, gql = _get_clients()
    mutation = """
    mutation {
        publishChanges {
            isValid
            errors { type message }
        }
    }
    """
    data = await gql.execute(mutation)
    return _fmt(data.get("publishChanges", {}))


@mcp.tool()
async def discard_changes() -> str:
    """Discard all pending (unpublished) configuration changes."""
    _, gql = _get_clients()
    mutation = """
    mutation {
        discardChanges
    }
    """
    data = await gql.execute(mutation)
    return _fmt(data)


@mcp.tool()
async def enforce_policy() -> str:
    """Enforce the latest published policy on all connected agents."""
    _, gql = _get_clients()
    mutation = """
    mutation {
        enforcePolicy {
            id
            status
        }
    }
    """
    data = await gql.execute(mutation)
    return _fmt(data.get("enforcePolicy", {}))


@mcp.tool()
async def new_web_application_asset(
    name: str,
    upstream_url: str,
    urls: list[str],
    profile_ids: list[str] | None = None,
    practice_ids: list[str] | None = None,
) -> str:
    """Create a new Web Application asset.

    Args:
        name: Name for the new asset.
        upstream_url: The backend/upstream URL to protect.
        urls: List of public-facing URLs for the asset.
        profile_ids: Optional list of profile IDs to attach.
        practice_ids: Optional list of practice IDs to attach.
    """
    _, gql = _get_clients()
    variables: dict[str, Any] = {
        "input": {
            "name": name,
            "upstreamURL": upstream_url,
            "URLs": urls,
        }
    }
    if profile_ids:
        variables["input"]["profiles"] = profile_ids
    if practice_ids:
        variables["input"]["practices"] = [
            {"practiceId": pid} for pid in practice_ids
        ]

    mutation = """
    mutation newWebApplicationAsset($input: WebApplicationAssetInput!) {
        newWebApplicationAsset(assetInput: $input) {
            id
            name
            upstreamURL
            URLs { id URL }
        }
    }
    """
    data = await gql.execute(mutation, variables)
    return _fmt(data.get("newWebApplicationAsset", {}))


@mcp.tool()
async def update_web_application_asset(
    asset_id: str,
    update_input: dict[str, Any],
) -> str:
    """Update an existing Web Application asset.

    Args:
        asset_id: ID of the asset to update.
        update_input: Dictionary of fields to update. Supports: name, upstreamURL, addURLs, removeURLs, 
                       addProfiles, removeProfiles, addPractices, removePractices, state, stage, etc.
    """
    _, gql = _get_clients()
    mutation = """
    mutation updateWebApplicationAsset($id: ID!, $input: WebApplicationAssetUpdateInput!) {
        updateWebApplicationAsset(id: $id, assetInput: $input)
    }
    """
    data = await gql.execute(mutation, {"id": asset_id, "input": update_input})
    return _fmt(data)


@mcp.tool()
async def delete_asset(asset_id: str) -> str:
    """Delete an asset by ID. Remember to publish changes after deletion.

    Args:
        asset_id: The unique identifier of the asset to delete.
    """
    _, gql = _get_clients()
    mutation = """
    mutation deleteAsset($id: String!) {
        deleteAsset(id: $id)
    }
    """
    data = await gql.execute(mutation, {"id": asset_id})
    return _fmt(data)


@mcp.tool()
async def new_web_application_practice(
    name: str,
    owner_id: str = "",
    modes: list[dict[str, str]] | None = None,
    practice_input: dict[str, Any] | None = None,
) -> str:
    """Create a new Web Application (WAF) practice.

    Args:
        name: Name for the new practice.
        owner_id: Optional owner asset/zone ID (for local visibility practices).
        modes: Optional list of mode configs, e.g. [{"mode": "Prevent", "subPractice": "IPS"}].
        practice_input: Optional advanced configuration dict with keys like IPS, WebAttacks, WebBot, Snort.
    """
    _, gql = _get_clients()
    variables: dict[str, Any] = {}
    pi = practice_input or {}
    pi["name"] = name
    variables["practiceInput"] = pi
    if owner_id:
        variables["ownerId"] = owner_id
    if modes:
        variables["modes"] = modes

    mutation = """
    mutation newWebApplicationPractice(
        $ownerId: ID,
        $modes: [PracticeModeInput],
        $practiceInput: WebApplicationPracticeInput
    ) {
        newWebApplicationPractice(
            ownerId: $ownerId,
            modes: $modes,
            practiceInput: $practiceInput
        ) {
            id
            name
            practiceType
            visibility
        }
    }
    """
    data = await gql.execute(mutation, variables)
    return _fmt(data.get("newWebApplicationPractice", {}))


@mcp.tool()
async def update_web_application_practice(
    practice_id: str,
    update_input: dict[str, Any],
    owner_id: str = "",
) -> str:
    """Update a Web Application (WAF) practice.

    Args:
        practice_id: ID of the practice to update.
        update_input: Dictionary of fields to update (name, visibility, IPS, WebAttacks, WebBot, Snort).
        owner_id: Optional owner ID for local-visibility practices.
    """
    _, gql = _get_clients()
    variables: dict[str, Any] = {
        "id": practice_id,
        "practiceInput": update_input,
    }
    if owner_id:
        variables["ownerId"] = owner_id

    mutation = """
    mutation updateWebApplicationPractice(
        $id: ID!,
        $practiceInput: WebApplicationPracticeUpdateInput,
        $ownerId: ID
    ) {
        updateWebApplicationPractice(
            id: $id,
            practiceInput: $practiceInput,
            ownerId: $ownerId
        )
    }
    """
    data = await gql.execute(mutation, variables)
    return _fmt(data)


# ──────────────────────────────────────────────
# RAW GRAPHQL TOOL
# ──────────────────────────────────────────────


@mcp.tool()
async def raw_graphql_query(
    query: str,
    variables: dict[str, Any] | None = None,
    use_v2: bool = False,
) -> str:
    """Execute a raw GraphQL query or mutation against the Check Point WAF API.
    Use this for operations not covered by other tools.

    Args:
        query: The full GraphQL query or mutation string.
        variables: Optional variables dictionary.
        use_v2: Use the v2 GraphQL endpoint (needed for tuning-related queries).
    """
    _, gql = _get_clients()
    data = await gql.execute(query, variables, use_v2=use_v2)
    return _fmt(data)


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
