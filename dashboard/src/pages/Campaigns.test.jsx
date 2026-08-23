/*
 * Tests for the Campaigns page.
 *
 * Two things get the most attention. The evidence must be reachable — a
 * grouping an analyst cannot inspect is one they cannot disagree with — and the
 * provenance must be visible, because a stored clustering can be hours old and
 * a reader who assumes it is live will conclude an operator went quiet when the
 * table is merely stale.
 */

import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import Campaigns from "./Campaigns.jsx";
import { apiError, mockApi, renderRoute } from "../test/helpers.jsx";

function campaign(overrides = {}) {
  return {
    size: 3,
    members: ["45.33.32.1", "45.33.32.2", "45.33.32.3"],
    event_count: 120,
    cohesion: 0.82,
    shared_credentials: ["root:hunter2"],
    shared_payloads: [],
    shared_paths: ["/shell.php"],
    asns: [63949],
    countries: ["NL"],
    classifications: ["credential-bruteforce"],
    first_seen: "2026-08-18T10:00:00Z",
    last_seen: "2026-08-21T09:00:00Z",
    ...overrides,
  };
}

const page = (items, extra = {}) => ({
  items,
  threshold: 0.35,
  source: "stored",
  computed_at: "2026-08-21T08:00:00Z",
  available_thresholds: [0.35],
  ...extra,
});

function setup(body = page([campaign()])) {
  mockApi({ "/campaigns": body });
  return renderRoute(<Campaigns />, { path: "/campaigns", route: "/campaigns" });
}

describe("Campaigns list", () => {
  it("renders a campaign with its headline numbers", async () => {
    setup();
    expect(await screen.findByText("Campaign 1")).toBeInTheDocument();
    expect(screen.getByText(/3 sources · 120 events · cohesion 0.82/)).toBeInTheDocument();
  });

  it("links each member to its attacker profile", async () => {
    setup();
    const link = await screen.findByRole("link", { name: "45.33.32.1" });
    expect(link).toHaveAttribute("href", "/attackers/45.33.32.1");
  });

  it("summarises classification, country and ASN", async () => {
    setup();
    expect(await screen.findByText(/credential-bruteforce · NL · AS63949/)).toBeInTheDocument();
  });

  it("counts sources across campaigns", async () => {
    setup(page([campaign(), campaign({ members: ["8.8.8.8", "8.8.4.4"], size: 2 })]));
    await screen.findByText("Campaign 1");
    const tile = screen.getByText("Sources grouped").closest(".stat");
    expect(tile).toHaveTextContent("5");
  });

  it("truncates a large member list until expanded", async () => {
    const members = Array.from({ length: 20 }, (_, i) => `45.33.32.${i + 1}`);
    setup(page([campaign({ members, size: 20 })]));
    expect(await screen.findByText("+12 more")).toBeInTheDocument();
  });

  it("explains an empty result rather than showing a blank page", async () => {
    setup(page([]));
    expect(await screen.findByText(/No campaigns at this threshold/)).toBeInTheDocument();
  });

  it("surfaces an API failure", async () => {
    mockApi({ "/campaigns": apiError(500, "database is locked") });
    renderRoute(<Campaigns />, { path: "/campaigns", route: "/campaigns" });
    expect(await screen.findByText(/Request failed/)).toBeInTheDocument();
  });
});

describe("evidence is reachable", () => {
  it("hides evidence behind a toggle by default", async () => {
    setup();
    await screen.findByText("Campaign 1");
    expect(screen.queryByText(/common to all/)).not.toBeInTheDocument();
  });

  it("shows shared credentials when expanded", async () => {
    setup();
    await userEvent.click(await screen.findByRole("button", { name: /evidence/i }));
    expect(screen.getByText("root:hunter2")).toBeInTheDocument();
    expect(screen.getByText(/Shared credentials — common to all 3 members/)).toBeInTheDocument();
  });

  it("shows shared paths when expanded", async () => {
    setup();
    await userEvent.click(await screen.findByRole("button", { name: /evidence/i }));
    expect(screen.getByText("/shell.php")).toBeInTheDocument();
  });

  it("omits facets with nothing in common", async () => {
    setup();
    await userEvent.click(await screen.findByRole("button", { name: /evidence/i }));
    expect(screen.queryByText(/Shared payloads/)).not.toBeInTheDocument();
  });

  it("says so when no facet is common to every member", async () => {
    // Transitive grouping: A~B and B~C with no shared facet across all three.
    setup(page([campaign({ shared_credentials: [], shared_paths: [], shared_payloads: [] })]));
    await userEvent.click(await screen.findByRole("button", { name: /evidence/i }));
    expect(screen.getByText(/no facet is common to every member/)).toBeInTheDocument();
  });

  it("reveals every member when expanded", async () => {
    const members = Array.from({ length: 20 }, (_, i) => `45.33.32.${i + 1}`);
    setup(page([campaign({ members, size: 20 })]));
    await userEvent.click(await screen.findByRole("button", { name: /evidence/i }));
    expect(screen.queryByText("+12 more")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "45.33.32.20" })).toBeInTheDocument();
  });

  it("collapses again", async () => {
    setup();
    const toggle = await screen.findByRole("button", { name: /evidence/i });
    await userEvent.click(toggle);
    await userEvent.click(screen.getByRole("button", { name: /hide/i }));
    expect(screen.queryByText(/common to all/)).not.toBeInTheDocument();
  });
});

describe("provenance is visible", () => {
  it("says when a stored clustering was computed", async () => {
    setup();
    expect(await screen.findByText(/Stored clustering from/)).toBeInTheDocument();
  });

  it("distinguishes a freshly computed grouping", async () => {
    setup(page([campaign()], { source: "computed", computed_at: null }));
    expect(await screen.findByText(/Computed just now/)).toBeInTheDocument();
  });

  it("tells the reader how to build a missing clustering", async () => {
    setup(page([], { computed_at: null }));
    expect(await screen.findByText(/No stored clustering at threshold/)).toBeInTheDocument();
    expect(
      screen.getByText("python -m pipeline.analysis.campaigns --store")
    ).toBeInTheDocument();
  });
});

describe("threshold control", () => {
  it("requests the chosen threshold", async () => {
    const fetchMock = mockApi({ "/campaigns": page([campaign()]) });
    renderRoute(<Campaigns />, { path: "/campaigns", route: "/campaigns" });
    await screen.findByText("Campaign 1");

    await userEvent.selectOptions(screen.getByLabelText("Similarity threshold"), "0.5");

    const urls = fetchMock.mock.calls.map((c) => String(c[0]));
    expect(urls.some((u) => u.includes("threshold=0.5"))).toBe(true);
  });

  it("defaults to the balanced setting", async () => {
    const fetchMock = mockApi({ "/campaigns": page([campaign()]) });
    renderRoute(<Campaigns />, { path: "/campaigns", route: "/campaigns" });
    await screen.findByText("Campaign 1");
    expect(String(fetchMock.mock.calls[0][0])).toContain("threshold=0.35");
  });
});
