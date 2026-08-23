import { useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtNumber, fmtRelative } from "../api.js";
import { useApi } from "../useApi.js";
import { ErrorBox, Loading, StatTile } from "../components/common.jsx";

/**
 * Sources grouped by behaviour rather than by address.
 *
 * A count of unique attacker IPs measures the size of somebody's botnet, not
 * the number of adversaries — operators rotate through compromised hosts
 * constantly. This page answers the question the attacker list structurally
 * cannot: is this the same operator from a new address?
 *
 * Every campaign shows the credentials, paths and artefacts its members
 * actually share. That is the point rather than decoration: a grouping an
 * analyst cannot inspect is one they cannot disagree with, which makes it
 * useless as evidence.
 */
export default function Campaigns() {
  const [threshold, setThreshold] = useState(0.35);
  const [expanded, setExpanded] = useState(null);

  const { data, error, loading } = useApi(() => api.campaigns({ threshold }), [threshold]);

  const items = data?.items || [];
  const grouped = items.reduce((n, c) => n + c.size, 0);
  const isStale = data?.source === "stored" && data?.computed_at;

  return (
    <div>
      <div className="topbar">
        <div>
          <h1 className="page-title">Campaigns</h1>
          <div className="page-sub">
            {data
              ? `${items.length} campaign(s) covering ${grouped} sources`
              : "…"}
          </div>
        </div>
        <div className="controls">
          <select
            value={threshold}
            onChange={(e) => setThreshold(Number(e.target.value))}
            aria-label="Similarity threshold"
          >
            <option value={0.25}>Loose (0.25)</option>
            <option value={0.35}>Balanced (0.35)</option>
            <option value={0.5}>Tight (0.50)</option>
            <option value={0.7}>Very tight (0.70)</option>
          </select>
        </div>
      </div>

      {error && <ErrorBox error={error} />}

      {loading && !data ? (
        <Loading />
      ) : (
        <>
          <div className="grid stats">
            <StatTile label="Campaigns" value={items.length} />
            <StatTile label="Sources grouped" value={grouped} />
            <StatTile label="Largest campaign" value={items[0]?.size ?? 0} />
            <StatTile
              label="Events attributed"
              value={items.reduce((n, c) => n + (c.event_count || 0), 0)}
            />
          </div>

          {/* Provenance, stated plainly: a stored grouping can be hours old,
              and a reader who assumes it is live will conclude an operator has
              gone quiet when the table is simply stale. */}
          <div className="muted" style={{ fontSize: 12, margin: "12px 2px" }}>
            {data?.source === "computed" ? (
              <>Computed just now at threshold {data.threshold}.</>
            ) : isStale ? (
              <>
                Stored clustering from {fmtRelative(data.computed_at)}, threshold{" "}
                {data.threshold}. Refresh with{" "}
                <code>python -m pipeline.analysis.campaigns --store</code>.
              </>
            ) : (
              <>
                No stored clustering at threshold {threshold}. Run{" "}
                <code>python -m pipeline.analysis.campaigns --store</code> to build one.
              </>
            )}
          </div>

          {items.length === 0 ? (
            <div className="card">
              <div className="empty">
                No campaigns at this threshold. Try a looser setting, or check that a
                clustering has been stored.
              </div>
            </div>
          ) : (
            items.map((campaign, i) => (
              <CampaignCard
                key={campaign.members.join(",")}
                index={i + 1}
                campaign={campaign}
                open={expanded === i}
                onToggle={() => setExpanded(expanded === i ? null : i)}
              />
            ))
          )}
        </>
      )}
    </div>
  );
}

function CampaignCard({ index, campaign, open, onToggle }) {
  const evidence = [
    ["Shared credentials", campaign.shared_credentials],
    ["Shared paths", campaign.shared_paths],
    ["Shared payloads", campaign.shared_payloads],
  ].filter(([, values]) => values?.length);

  return (
    <div className="card" style={{ marginBottom: 12 }} data-testid="campaign-card">
      <div className="row spread">
        <div>
          <h3 style={{ margin: 0 }}>
            Campaign {index}
            <span className="muted" style={{ fontWeight: 400, marginLeft: 10, fontSize: 13 }}>
              {campaign.size} sources · {fmtNumber(campaign.event_count)} events · cohesion{" "}
              {campaign.cohesion?.toFixed(2)}
            </span>
          </h3>
          <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
            {campaign.classifications?.join(", ") || "unclassified"}
            {campaign.countries?.length ? ` · ${campaign.countries.join(", ")}` : ""}
            {campaign.asns?.length ? ` · AS${campaign.asns.slice(0, 4).join(", AS")}` : ""}
          </div>
        </div>
        <button onClick={onToggle} aria-expanded={open}>
          {open ? "Hide" : "Evidence"}
        </button>
      </div>

      <div style={{ marginTop: 10 }}>
        {campaign.members.slice(0, open ? campaign.members.length : 8).map((ip) => (
          <Link key={ip} to={`/attackers/${ip}`} className="chip mono" style={{ marginRight: 6 }}>
            {ip}
          </Link>
        ))}
        {!open && campaign.members.length > 8 && (
          <span className="muted" style={{ fontSize: 12 }}>
            +{campaign.members.length - 8} more
          </span>
        )}
      </div>

      {open && (
        <div style={{ marginTop: 14 }}>
          {evidence.length === 0 ? (
            <div className="muted" style={{ fontSize: 12 }}>
              Grouped on partial overlap — no facet is common to every member.
            </div>
          ) : (
            evidence.map(([label, values]) => (
              <div key={label} style={{ marginBottom: 10 }}>
                <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}>
                  {label} — common to all {campaign.size} members
                </div>
                {values.map((v) => (
                  <span key={v} className="chip mono">
                    {v.length > 40 ? `${v.slice(0, 40)}…` : v}
                  </span>
                ))}
              </div>
            ))
          )}
          <div className="muted" style={{ fontSize: 11, marginTop: 8 }}>
            Active {fmtRelative(campaign.first_seen)} → {fmtRelative(campaign.last_seen)}
          </div>
        </div>
      )}
    </div>
  );
}
