"""Campaign endpoints — attackers grouped by behaviour rather than by address.

Clustering is computed on request rather than stored. That is a deliberate
choice for now: the grouping depends on a threshold the caller picks, so a
cached table would only ever be right for one setting.

The cost is real and worth knowing before raising ``limit``. Comparison is
pairwise, so doubling the sources roughly quadruples the work — measured at
0.24s for 500 and 2.3s for 1500. The default is set low for that reason: a
synchronous endpoint that blocks for seconds is a denial of service you shipped
yourself. If this becomes a hot path it wants the treatment ``payloads`` got —
a derived table plus a rebuild command.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session as OrmSession

from api.schemas import CampaignOut
from pipeline.analysis.campaigns import DEFAULT_THRESHOLD, find_campaigns
from storage.db import get_db

router = APIRouter(prefix="/campaigns", tags=["campaigns"])


@router.get("", response_model=list[CampaignOut], summary="Attackers grouped into campaigns")
def list_campaigns(
    db: OrmSession = Depends(get_db),
    threshold: float = Query(
        DEFAULT_THRESHOLD,
        ge=0.0,
        le=1.0,
        description="Similarity floor. Higher means tighter, fewer, more confident groups.",
    ),
    limit: int = Query(
        500,
        ge=2,
        le=2000,
        description=(
            "Attackers to consider, most active first. Clustering is O(n²): "
            "500 costs roughly a quarter of a second, 2000 several seconds."
        ),
    ),
    min_size: int = Query(2, ge=2, le=100, description="Smallest group worth calling a campaign"),
) -> list[CampaignOut]:
    """Group sources by shared credentials, paths, artefacts and tooling.

    Answers the question an IP-keyed view structurally cannot: *is this the same
    operator from a new address?* Botnet operators rotate through compromised
    hosts, so a count of unique source IPs measures the size of somebody's
    botnet rather than the number of adversaries.
    """
    campaigns = find_campaigns(db, threshold=threshold, limit=limit, min_size=min_size)
    return [CampaignOut(**c.as_dict()) for c in campaigns]


__all__ = ["router"]
