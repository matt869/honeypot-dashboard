# Field report — 2026-08-24

Thirty days of capture from the live Azure sensor, read straight from the
production database at commit `415e96c`. Every figure below came from running
the code against real data, not from a fixture.

The point of this document is not that the sensor collected a lot. It is that
the analysis built on top of it says something an event table cannot, and that
the parts which are *not* yet backed by real traffic are named as such.

## Headline

| | |
|---|---|
| Events | **98,522** across 22,610 sessions |
| Source addresses | **1,316** from 81 countries |
| Auth attempts | **15,213**, 515 distinct credential pairs |
| Commands run in the fake shell | **30,081** |
| Artefacts captured and analysed | **24** |
| Campaigns identified | **9**, covering 390 sources |

## Where the traffic went

| Service | Events | Sources |
|---|---:|---:|
| telnet | 58,859 | 547 |
| mysql | 23,544 | 99 |
| ssh | 7,399 | 400 |
| http | 3,582 | 259 |
| docker | 2,572 | 63 |
| redis | 2,267 | 83 |
| ftp | 284 | 67 |
| elasticsearch | 15 | 1 |

Telnet takes roughly eight times the volume of SSH. That is the IoT botnet
story in one row — port 23 is where Mirai and its descendants live, and they
sweep it constantly with a short hardcoded credential list.

## The number that unique-IP counting would have hidden

| Origin | Events | Sources | Events per source |
|---|---:|---:|---:|
| United States | 22,959 | 348 | 66 |
| **Indonesia** | 21,126 | **14** | **1,509** |
| Germany | 20,905 | 68 | 307 |
| China | 10,062 | 169 | 60 |
| Pakistan | 5,725 | 40 | 143 |
| Sweden | 2,519 | 7 | 360 |
| Andorra | 1,737 | 12 | 145 |
| South Korea | 1,207 | 23 | 52 |

Indonesia and the United States sent almost identical volume. Indonesia used
14 addresses to do it; the US used 348. Those are two completely different
things — a concentrated operator versus background noise from a large address
space — and a table of unique source counts shows them as roughly equal.

## What they left behind

```
$ python -m pipeline.analysis.store
seen 24, analysed 3, skipped 21, errors 0

02cae78321  script  113B  H=4.70   seen 12x
    tags: downloader:curl, downloader:wget
    url : hxxps://217[.]60[.]195[.]113/sh
72561b01f7  script  121B  H=4.72   seen 2x
    tags: downloader:curl, downloader:wget
    url : hxxps://217[.]60[.]195[.]113/sh
```

That URL is a real second-stage dropper, captured fourteen times across two
distinct artefacts. It is defanged here because it is defanged everywhere: the
analyser renders indicators inert on the way out and nothing re-fangs them.
There is a test asserting that at every layer the value crosses — the function,
the stored row, the JSON the browser receives, and the rendered DOM.

## Who is actually behind them

1,316 source addresses is not 1,316 adversaries. Operators rotate through
compromised hosts, so sources are grouped by behaviour — credentials genuinely
tried, paths requested, artefacts delivered — rather than by address.

| Sources | Events | Cohesion | Shared evidence | Origins |
|---:|---:|---:|---|---|
| 195 | 44,561 | 0.70 | *none common to all* | AE AR AU BE CN CO DE EC … |
| 170 | 1,800 | 0.64 | *none common to all* | AD AM AU BE BR CA CN DE … |
| 7 | 325 | 0.67 | shared payload `39fb1ae987` | GB ID IR KR SG SO US |
| 4 | 71 | 0.50 | `enable:system` | CN HK KR |
| 2 | 14 | 0.40 | `hikvision:hikvision` | RU UA |

Two of these are worth reading closely.

**Seven addresses across seven countries delivered identical bytes.** They are
grouped on a shared payload hash, nothing about the networks they came from.
The same file arriving from GB, ID, IR, KR, SG, SO and US is one operator with
a botnet, and no address-keyed view can express that.

**Two addresses, two countries, one camera.** `hikvision:hikvision` is the
factory default on Hikvision IP cameras. A source in Russia and one in Ukraine
both tried exactly it. Same toolkit, different hosts.

## What the sensor will not keep forever

```
$ python -m pipeline.retention --older-than 90
retention cutoff 2026-05-26T16:54:26Z — would remove:
  events                   0
  sessions                 0
  alerts                   0
  payload rows             0
  payload files            0  (0 bytes)
  stored campaigns         0
  kept 24 payload(s) still referenced by live events

Dry run. Nothing was deleted — pass --apply to act.
```

The last line is the safety property working on production data. All 24 samples
survive because live events still point at them: a payload attached to an
observation is evidence, not litter, and is never deleted however old it is.

Before this existed, pruning deleted the record of an intrusion and left the
working malware on disk indefinitely. See [FINDINGS.md](../FINDINGS.md) for the
handling policy.

## Verification

| | |
|---|---|
| Tests | 832 Python, 42 frontend |
| Coverage | 80% across pipeline, sensor, storage, API |
| Lint | `ruff check` and `ruff format` clean, 107 files |
| Query performance | timeseries 162.1 → 37.4 ms p50; summary 67.3 → 30.2 ms p50 |
| PostgreSQL bucketing | 4.68× faster on 57,621 real events, output identical to the Python path |

## What this evidence does not show

Three things a careful reader should discount, recorded here rather than left
to be discovered.

**The Elasticsearch bait has caught nothing real.** All 15 of its events came
from `172.18.0.2` — a container on the sensor's own bridge network, which is to
say a test probe rather than the internet. Port 9200 still needs an inbound NSG
rule before organic traffic can reach it. The severity ladder is proven to
work; it simply has not been exercised by a stranger yet.

**The two largest campaigns share no evidence at all.** 195 and 170 sources,
held together by transitive chaining — A resembles B, B resembles C, across
hundreds of hops — with no credential, path or payload common to every member.
The dashboard says so rather than hiding it, and it is still weak as a claim.
Tightening it means deciding what a campaign should *mean*, which is a
judgement call rather than a bug fix. See the note in
[ROADMAP.md](ROADMAP.md#campaign-clustering--done).

**Some captured credentials are artefacts of a fixed bug.** Scanners speaking
HTTP at port 23 had their request lines recorded as usernames, so
`GET / HTTP/1.1` appears in the credential data and even formed a small
four-source campaign. The sensor no longer does this. The existing rows were
deliberately left in place: they are what it genuinely recorded, and a capture
store that edits its own history is worth less than one carrying a documented
wart.
