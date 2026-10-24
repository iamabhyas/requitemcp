import asyncio
import json
import os
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row
from psycopg.types.json import set_json_loads

from fastmcp import FastMCP

load_dotenv(Path(__file__).resolve().parent / ".env")


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


# Values come from the process environment, or from .env for local runs.
# A variable already set on the server is left unchanged.
ENGAGEMENT_DB__HOST = _required_env("ENGAGEMENT_DB__HOST")
ENGAGEMENT_DB__PORT = int(_required_env("ENGAGEMENT_DB__PORT"))
ENGAGEMENT_DB__NAME = _required_env("ENGAGEMENT_DB__NAME")
ENGAGEMENT_DB__USER = _required_env("ENGAGEMENT_DB__USER")
ENGAGEMENT_DB__PASSWORD = _required_env("ENGAGEMENT_DB__PASSWORD")

MAX_LIMIT = 100

mcp = FastMCP("RequiteMCP")


def _connect():
    conn = psycopg.connect(
        host=ENGAGEMENT_DB__HOST,
        port=ENGAGEMENT_DB__PORT,
        dbname=ENGAGEMENT_DB__NAME,
        user=ENGAGEMENT_DB__USER,
        password=ENGAGEMENT_DB__PASSWORD,
        connect_timeout=15,
        row_factory=dict_row,
    )
    set_json_loads(json.loads, conn)
    return conn


def _jsonable(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    return value


def _parse_uuid(value: str, field_name: str) -> str:
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a UUID") from exc


def fetch_engagement_events(
    engagement_event_id: str | None = None,
    community_id: str | None = None,
    event_type: str | None = None,
    limit: int = 20,
) -> list[dict]:
    if limit < 1:
        raise ValueError("limit must be at least 1")
    limit = min(limit, MAX_LIMIT)

    conditions: list[str] = []
    params: list[object] = []

    if engagement_event_id:
        conditions.append("engagement_event_id = %s")
        params.append(_parse_uuid(engagement_event_id, "engagement_event_id"))
    if community_id:
        conditions.append("community_id = %s")
        params.append(_parse_uuid(community_id, "community_id"))
    if event_type:
        conditions.append("event_type = %s")
        params.append(event_type)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"""
        SELECT
            engagement_event_id,
            event_category,
            event_type,
            event_sub_type,
            payload,
            metadata,
            event_source,
            event_metadata_contact_id,
            event_metadata_pass_instance_id,
            create_ts,
            community_id,
            event_node_device_id,
            event_node_session_id,
            primary_id,
            primary_name,
            community_patrons_id,
            community_passes_id,
            header
        FROM "EngagementEvents"
        {where}
        ORDER BY create_ts DESC
        LIMIT %s
    """
    params.append(limit)

    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()

    return [_jsonable(row) for row in rows]


@mcp.tool
async def get_engagement_events(
    engagement_event_id: str | None = None,
    community_id: str | None = None,
    event_type: str | None = None,
    limit: int = 20,
) -> list[dict]:
    """Get rows from the EngagementEvents table.

    Filter by engagement_event_id, community_id, and/or event_type.
    With no filters, returns the most recent events. limit is capped at 100.
    """
    return await asyncio.to_thread(
        fetch_engagement_events,
        engagement_event_id,
        community_id,
        event_type,
        limit,
    )


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000)
