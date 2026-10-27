import json
import os
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID, uuid4

import psycopg
from dotenv import load_dotenv
from mcp_types import ToolAnnotations
from psycopg.rows import dict_row
from psycopg.types.json import Json, set_json_loads
from pydantic import BaseModel, Field

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
TRANSACTION_DB__NAME = _required_env("TRANSACTION_DB__NAME")
WALLET_DB__NAME = _required_env("WALLET_DB__NAME")
USER_DB__NAME = _required_env("USER_DB__NAME")

MAX_LIMIT = 100
DETAIL_FIELDS = ("payload", "metadata", "header")
SENSITIVE_KEYS = {
    "authorization",
    "push_token",
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "x-api-key",
}

mcp = FastMCP("RequiteMCP")


class EngagementEventsPage(BaseModel):
    """One page of EngagementEvents rows."""

    returned: int
    limit: int
    offset: int
    has_more: bool
    filters: dict[str, str]
    events: list[dict[str, Any]]


def _connect(dbname: str):
    conn = psycopg.connect(
        host=ENGAGEMENT_DB__HOST,
        port=ENGAGEMENT_DB__PORT,
        dbname=dbname,
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


def _blank_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


def _parse_uuid(value: str, field_name: str) -> str:
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a UUID") from exc


def _parse_timestamp(value: str, field_name: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                "[redacted]"
                if str(key).lower() in SENSITIVE_KEYS
                else _redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def fetch_engagement_events(
    engagement_event_id: str | None = None,
    community_id: str | None = None,
    event_type: str | None = None,
    event_category: str | None = None,
    event_sub_type: str | None = None,
    event_source: str | None = None,
    pass_instance_id: str | None = None,
    primary_id: str | None = None,
    created_after: str | None = None,
    created_before: str | None = None,
    include_details: bool | None = None,
    limit: int = 20,
    offset: int = 0,
) -> EngagementEventsPage:
    if limit < 1:
        raise ValueError("limit must be at least 1")
    if offset < 0:
        raise ValueError("offset must be 0 or greater")
    limit = min(limit, MAX_LIMIT)

    filters: dict[str, str] = {}
    conditions: list[str] = []
    params: list[object] = []

    def add_uuid(column: str, field_name: str, value: str | None) -> None:
        text = _blank_to_none(value)
        if not text:
            return
        parsed = _parse_uuid(text, field_name)
        conditions.append(f"{column} = %s")
        params.append(parsed)
        filters[field_name] = parsed

    def add_text(column: str, field_name: str, value: str | None) -> None:
        text = _blank_to_none(value)
        if not text:
            return
        conditions.append(f"{column} = %s")
        params.append(text)
        filters[field_name] = text

    add_uuid("engagement_event_id", "engagement_event_id", engagement_event_id)
    add_uuid("community_id", "community_id", community_id)
    add_text("event_type", "event_type", event_type)
    add_text("event_category", "event_category", event_category)
    add_text("event_sub_type", "event_sub_type", event_sub_type)
    add_text("event_source", "event_source", event_source)
    add_uuid(
        "event_metadata_pass_instance_id",
        "pass_instance_id",
        pass_instance_id,
    )
    add_text("primary_id", "primary_id", primary_id)

    created_after_text = _blank_to_none(created_after)
    if created_after_text:
        parsed_after = _parse_timestamp(created_after_text, "created_after")
        conditions.append("create_ts >= %s")
        params.append(parsed_after)
        filters["created_after"] = parsed_after.isoformat()

    created_before_text = _blank_to_none(created_before)
    if created_before_text:
        parsed_before = _parse_timestamp(created_before_text, "created_before")
        conditions.append("create_ts < %s")
        params.append(parsed_before)
        filters["created_before"] = parsed_before.isoformat()

    if (
        "created_after" in filters
        and "created_before" in filters
        and filters["created_after"] >= filters["created_before"]
    ):
        raise ValueError("created_after must be earlier than created_before")

    show_details = (
        "engagement_event_id" in filters
        if include_details is None
        else include_details
    )

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
        ORDER BY create_ts DESC, engagement_event_id DESC
        LIMIT %s
        OFFSET %s
    """
    params.extend([limit + 1, offset])

    with _connect(dbname=ENGAGEMENT_DB__NAME) as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()

    has_more = len(rows) > limit
    events = [_jsonable(row) for row in rows[:limit]]
    if show_details:
        events = [_redact(event) for event in events]
    else:
        for event in events:
            for field_name in DETAIL_FIELDS:
                event.pop(field_name, None)

    return EngagementEventsPage(
        returned=len(events),
        limit=limit,
        offset=offset,
        has_more=has_more,
        filters=filters,
        events=events,
    )


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get engagement events",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    )
)
def get_engagement_events(
    engagement_event_id: Annotated[
        str | None,
        Field(description="Primary key of one EngagementEvents row. UUID."),
    ] = None,
    community_id: Annotated[
        str | None,
        Field(description="Community that owns the events. UUID."),
    ] = None,
    event_type: Annotated[
        str | None,
        Field(description="Exact event_type, such as SVC_PASS_EXPIRED."),
    ] = None,
    event_category: Annotated[
        str | None,
        Field(description="Exact event_category, such as System."),
    ] = None,
    event_sub_type: Annotated[
        str | None,
        Field(description="Exact event_sub_type, such as apple_wallet_pass_expired."),
    ] = None,
    event_source: Annotated[
        str | None,
        Field(description="Exact event_source, such as Wallet Service."),
    ] = None,
    pass_instance_id: Annotated[
        str | None,
        Field(description="Pass instance id stored on the event. UUID."),
    ] = None,
    primary_id: Annotated[
        str | None,
        Field(description="primary_id value. Often a pass instance id."),
    ] = None,
    created_after: Annotated[
        str | None,
        Field(description="Include events created at or after this ISO-8601 time."),
    ] = None,
    created_before: Annotated[
        str | None,
        Field(description="Include events created before this ISO-8601 time."),
    ] = None,
    include_details: Annotated[
        bool | None,
        Field(
            description=(
                "Include payload, metadata, and header. "
                "Defaults to true for a single engagement_event_id lookup "
                "and false for lists. Credential fields are redacted."
            )
        ),
    ] = None,
    limit: Annotated[
        int,
        Field(description="Maximum rows to return. Capped at 100.", ge=1, le=MAX_LIMIT),
    ] = 20,
    offset: Annotated[
        int,
        Field(description="Number of matching rows to skip. Use with has_more.", ge=0),
    ] = 0,
) -> EngagementEventsPage:
    """Read EngagementEvents, newest first.

    Combine any filters. With none, returns the most recent events.
    Use has_more and offset to page. A single engagement_event_id lookup
    includes payload, metadata, and header unless include_details is false.
    """
    return fetch_engagement_events(
        engagement_event_id=engagement_event_id,
        community_id=community_id,
        event_type=event_type,
        event_category=event_category,
        event_sub_type=event_sub_type,
        event_source=event_source,
        pass_instance_id=pass_instance_id,
        primary_id=primary_id,
        created_after=created_after,
        created_before=created_before,
        include_details=include_details,
        limit=limit,
        offset=offset,
    )


def fetch_pass_templates() -> list[dict[str, Any]]:
    """Return active rows from MasterPasstemplates."""
    with _connect(dbname=WALLET_DB__NAME) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM public."MasterPasstemplates"
                WHERE is_deleted IS FALSE
                ORDER BY master_pass_template_id ASC
                """
            )
            rows = cur.fetchall()
    return [_jsonable(row) for row in rows]


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get pass templates",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    )
)
def get_pass_templates() -> list[dict[str, Any]]:
    """Get all active pass templates."""
    return fetch_pass_templates()


PASS_TYPES = ("event_ticket", "coupon", "store_card", "boarding_pass", "generic")
TEMPLATE_STATUSES = ("active", "draft", "inactive")
TEMPLATE_PURPOSES = (
    "general_pass",
    "paylink_pass",
    "dynamic_paylink_pass",
    "payment_profile_pass",
    "checkin_loyalty",
    "QR_CHECKIN",
    "QR_COMMUNITY",
    "QR_KUDOS",
    "QR_MEMBER",
    "QR_PAYMENT_PROFILE",
)
TEMPLATE_TYPES = (
    "classic_voucher",
    "classic_paylink",
    "classic_payment_profile",
    "qr_pass",
    "loyalty_with_checkin",
)


class WalletTemplateCreated(BaseModel):
    """A CommunityPasses row created as a wallet template."""

    detail: str
    community_passes_id: str
    community_id: str
    member_id: str | None
    name: str
    type: str
    template_status: str
    template_purpose: str
    template_type: str
    receipt_enabled: bool
    mystery_box_enabled: bool
    created_date: str


def _require_choice(value: str, field_name: str, allowed: tuple[str, ...]) -> str:
    text = _blank_to_none(value)
    if text not in allowed:
        choices = ", ".join(allowed)
        raise ValueError(f"{field_name} must be one of: {choices}")
    return text


def create_wallet_template_record(
    community_id: str,
    name: str,
    type: str,
    template_status: str,
    template_purpose: str,
    template_type: str,
    wallet_pass_data: dict[str, Any] | None = None,
    member_id: str | None = None,
    receipt_enabled: bool = False,
    mystery_box_enabled: bool = False,
) -> WalletTemplateCreated:
    """Insert one active CommunityPasses wallet template."""
    community_uuid = _parse_uuid(community_id, "community_id")
    template_name = _blank_to_none(name)
    if not template_name:
        raise ValueError("name is required")

    pass_type = _require_choice(type, "type", PASS_TYPES)
    status = _require_choice(template_status, "template_status", TEMPLATE_STATUSES)
    purpose = _require_choice(template_purpose, "template_purpose", TEMPLATE_PURPOSES)
    kind = _require_choice(template_type, "template_type", TEMPLATE_TYPES)

    member_text = _blank_to_none(member_id)
    member_uuid = _parse_uuid(member_text, "member_id") if member_text else None
    if wallet_pass_data is not None and not isinstance(wallet_pass_data, dict):
        raise ValueError("wallet_pass_data must be a JSON object")

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    community_passes_id = str(uuid4())
    pass_data = Json(wallet_pass_data) if wallet_pass_data else None

    with _connect(dbname=WALLET_DB__NAME) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO public."CommunityPasses" (
                    community_passes_id,
                    community_id,
                    member_id,
                    name,
                    type,
                    wallet_pass_data,
                    template_status,
                    template_purpose,
                    template_type,
                    receipt_enabled,
                    mystery_box_enabled,
                    created_date,
                    modified_date,
                    deleted_date,
                    is_deleted,
                    notification_workflow_filters
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                RETURNING
                    community_passes_id,
                    community_id,
                    member_id,
                    name,
                    type,
                    template_status,
                    template_purpose,
                    template_type,
                    receipt_enabled,
                    mystery_box_enabled,
                    created_date
                """,
                (
                    community_passes_id,
                    community_uuid,
                    member_uuid,
                    template_name,
                    pass_type,
                    pass_data,
                    status,
                    purpose,
                    kind,
                    receipt_enabled,
                    mystery_box_enabled,
                    now,
                    now,
                    None,
                    False,
                    Json({}),
                ),
            )
            row = cur.fetchone()

    if not row:
        raise RuntimeError("Wallet template creation failed")

    created = _jsonable(row)
    return WalletTemplateCreated(
        detail="Wallet template created successfully",
        community_passes_id=created["community_passes_id"],
        community_id=created["community_id"],
        member_id=created["member_id"],
        name=created["name"],
        type=created["type"],
        template_status=created["template_status"],
        template_purpose=created["template_purpose"],
        template_type=created["template_type"],
        receipt_enabled=created["receipt_enabled"],
        mystery_box_enabled=created["mystery_box_enabled"],
        created_date=created["created_date"],
    )


@mcp.tool(
    annotations=ToolAnnotations(
        title="Create wallet template",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    )
)
def create_wallet_template(
    community_id: Annotated[
        str,
        Field(description="Community that owns the template. UUID."),
    ],
    name: Annotated[str, Field(description="Display name of the wallet template.")],
    type: Annotated[
        str,
        Field(
            description=(
                "Wallet pass type: event_ticket, coupon, store_card, "
                "boarding_pass, or generic."
            )
        ),
    ],
    template_status: Annotated[
        str,
        Field(description="Template status: active, draft, or inactive."),
    ],
    template_purpose: Annotated[
        str,
        Field(
            description=(
                "Template purpose, such as general_pass, paylink_pass, "
                "dynamic_paylink_pass, payment_profile_pass, checkin_loyalty, "
                "QR_CHECKIN, QR_COMMUNITY, QR_KUDOS, QR_MEMBER, or "
                "QR_PAYMENT_PROFILE."
            )
        ),
    ],
    template_type: Annotated[
        str,
        Field(
            description=(
                "Template type: classic_voucher, classic_paylink, "
                "classic_payment_profile, qr_pass, or loyalty_with_checkin."
            )
        ),
    ],
    wallet_pass_data: Annotated[
        dict[str, Any] | None,
        Field(
            description=(
                "Pass design JSON stored on the template. "
                "Omit it to store no pass data."
            )
        ),
    ] = None,
    member_id: Annotated[
        str | None,
        Field(description="Member who created the template. UUID. Optional."),
    ] = None,
    receipt_enabled: Annotated[
        bool,
        Field(description="Whether receipts are enabled for this template."),
    ] = False,
    mystery_box_enabled: Annotated[
        bool,
        Field(description="Whether the mystery box is enabled for this template."),
    ] = False,
) -> WalletTemplateCreated:
    """Create a community wallet pass template.

    Inserts a CommunityPasses row with is_deleted false and an empty
    notification_workflow_filters object. This does not change MasterPasstemplates.
    """
    return create_wallet_template_record(
        community_id=community_id,
        name=name,
        type=type,
        template_status=template_status,
        template_purpose=template_purpose,
        template_type=template_type,
        wallet_pass_data=wallet_pass_data,
        member_id=member_id,
        receipt_enabled=receipt_enabled,
        mystery_box_enabled=mystery_box_enabled,
    )


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8001)
