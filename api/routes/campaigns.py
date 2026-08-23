"""Campaign endpoints — attackers grouped by behaviour rather than by address.

Stored clusterings are served by default. Clustering is O(n²) and this is a
synchronous endpoint, so recomputing per request is opt-in rather than the
default: at 500 sources that is a quarter of a second, at 1500 it is over two.
An endpoint that blocks for seconds is a denial of service you shipped
yourself.

``python -m pipeline.analysis.campaigns --store`` writes the rows this serves.
When nothing is stored for the requested threshold the response says so rather
than silently computing — a slow surprise is worse than an empty list with an
explanation.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session as OrmSession

from api.schemas import CampaignOut, CampaignPage
from pipeline.analysis.campaigns import DEFAULT_THRESHOLD, find_campaigns
from storage import queries
from storage.db import get_db

router = APIRouter(prefix="/campaigns", tags=["campaigns"])


def _from_row(row) -> CampaignOut:
    return CampaignOut(
        size=row.size,
        members=row.members or [],
        event_count=row.event_count,
        cohesion=row.cohesion,
        shared_credentials=row.shared_credentials or [],
        shared_payloads=row.shared_payloads or [],
        shared_paths=row.shared_paths or [],
        asns=row.asns or [],
        countries=row.countries or [],
        classifications=row.classifications or [],
        first_seen=row.first_seen,
        last_seen=row.last_seen,
    )


@router.get("", response_model=CampaignPage, summary="Attackers grouped into campaigns")
def list_campaigns(
    db: OrmSession = Depends(get_db),
    threshold: float = Query(
        DEFAULT_THRESHOLD,
        ge=0.0,
        le=1.0,
        description="Similarity floor. Higher means tighter, fewer, more confident groups.",
    ),
    min_size: int = Query(2, ge=2, le=100, description="Smallest group worth calling a campaign"),
    recompute: bool = Query(
        False,
        description=(
            "Cluster now instead of reading stored rows. O(n²) and synchronous: "
            "roughly 0.24s at 500 sources, over 2s at 1500."
        ),
    ),
    limit: int = Query(
        500,
        ge=2,
        le=2000,
        description="Attackers to consider when recomputing, most active first",
    ),
) -> CampaignPage:
    """Group sources by shared credentials, paths, artefacts and tooling.

    Answers the question an IP-keyed view structurally cannot: *is this the same
    operator from a new address?* Botnet operators rotate through compromised
    hosts, so a count of unique source IPs measures the size of somebody's
    botnet rather than the number of adversaries.
    """
    if recompute:
        found = find_campaigns(db, threshold=threshold, limit=limit, min_size=min_size)
        return CampaignPage(
            items=[CampaignOut(**c.as_dict()) for c in found],
            threshold=threshold,
            source="computed",
            computed_at=None,
        )

    rows = queries.list_campaigns(db, threshold=threshold, min_size=min_size)
    return CampaignPage(
        items=[_from_row(r) for r in rows],
        threshold=threshold,
        source="stored",
        computed_at=rows[0].computed_at if rows else None,
        available_thresholds=queries.stored_campaign_thresholds(db),
    )


__all__ = ["router"]
