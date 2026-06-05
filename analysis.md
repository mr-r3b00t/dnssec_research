# DNSSEC Adoption Analysis — Majestic Million

**Source:** `dnssec_report.csv` (1,000,000 domains, full run)
**Method:** For each listed name, a DNSSEC-aware resolver (round-robin over 1.1.1.1 / 8.8.8.8 / 9.9.9.9) was queried for A/AAAA records with the DO bit set. A name is counted **Signed** when the response contains an RRSIG whose owner name equals the queried name (so signed apexes *and* signed sub-domains are caught, while CNAMEs pointing at a signed CDN are not false positives).

---

## Headline

| Metric | Value |
|---|---|
| Domains scanned | 1,000,000 |
| **Signed (DNSSEC enabled)** | **67,462 (6.75%)** |
| Unsigned | 754,303 (75.43%) |
| Did not resolve (NoAnswer) | 178,235 (17.82%) |
| Errors | 0 |
| **Adoption among *resolvable* domains** | **8.21%** (67,462 / 821,765) |

Two defensible "adoption rate" figures: **6.75%** of all listed domains, or **8.21%** of the domains that actually resolve. The latter is the fairer measure of live-domain adoption (it excludes the ~18% that are dead/parked/non-responding).

---

## Adoption is heavily front-loaded by rank

| Rank band | Adoption | Signed / Total |
|---|---|---|
| 1 – 1,000 | **17.90%** | 179 / 1,000 |
| 1,000 – 10,000 | 12.37% | 1,113 / 9,000 |
| 10,000 – 100,000 | 8.39% | 7,550 / 90,000 |
| 100,000 – 1,000,000 | 6.51% | 58,620 / 900,000 |

The most popular domains are ~3× more likely to be signed than the long tail. (The bulk of *signed* domains still come from the tail simply because that's where most domains are.)

---

## The story is almost entirely about TLD

DNSSEC adoption is wildly bimodal. A handful of ccTLDs — mostly ones whose registries financially incentivise signing — dominate, while the big generic TLDs are near the floor.

### Top TLDs by adoption rate (min. 1,000 domains)

| TLD | Adoption | Signed / Total |
|---|---|---|
| .dk | 61.16% | 1,439 / 2,353 |
| .cz | 58.30% | 2,711 / 4,650 |
| .nl | 56.91% | 7,965 / 13,995 |
| .no | 43.47% | 812 / 1,868 |
| .sk | 41.15% | 437 / 1,062 |
| .se | 40.51% | 1,324 / 3,268 |
| .gov | 40.19% | 885 / 2,202 |
| .ch | 33.43% | 1,209 / 3,616 |
| .be | 23.42% | 724 / 3,091 |
| .sg | 21.71% | 224 / 1,032 |
| .br | 15.28% | 1,100 / 7,199 |
| .eu | 15.27% | 742 / 4,859 |
| .fr | 13.99% | 1,368 / 9,777 |
| .pl | 13.79% | 1,236 / 8,963 |
| .io | 12.27% | 464 / 3,781 |

### Largest TLDs by volume (and their adoption)

| TLD | Domains | Signed | Adoption |
|---|---|---|---|
| .com | 501,962 | 23,226 | 4.63% |
| .org | 84,189 | 4,986 | 5.92% |
| .net | 45,659 | 1,963 | 4.30% |
| .ru | 33,723 | 2,324 | 6.89% |
| .de | 31,954 | 1,483 | 4.64% |
| .cn | 26,529 | 141 | **0.53%** |
| .uk | 25,042 | 924 | 3.69% |
| .jp | 16,192 | 964 | 5.95% |
| .nl | 13,995 | 7,965 | **56.91%** |

**`.com` alone is half the list at 4.6%** — that single TLD is what drags the global average down to ~7%. `.nl` is the standout: nearly 14k domains at ~57% signed, contributing more signed domains than `.net` + `.de` + `.uk` combined despite being far smaller.

---

## How the signed domains are signed

Distribution of the record type whose RRSIG proved signing (a domain can count under more than one, e.g. `SOA,NSEC`):

| Signed via | Count |
|---|---|
| A (address record) | 64,023 |
| SOA | 3,126 |
| NSEC | 1,424 |
| CNAME | 141 |
| AAAA | 4 |

- **A** dominates: most signed domains have a signed address record at the queried name.
- **SOA / NSEC** (~3k): signed zones whose apex has *no* A record — detected via the authenticated NODATA proof. The owner-name match correctly flags these as Signed (e.g. `civilservicepensionscheme.org.uk`).
- **CNAME** (141): genuinely signed sub-domains that are CNAMEs inside a signed zone.

---

## Caveats

- **NoAnswer (17.8%) is a mix.** Most are dead/parked/NXDOMAIN or names that only carry non-address records, but some fraction may be transient timeouts under resolver rate-limiting during the run. If re-checked, a few might flip to Signed/Unsigned — unlikely to move the headline by more than a few tenths of a percent. They are excluded from the 8.21% "resolvable" rate.
- **TLD = last label.** `.uk` here lumps together `co.uk`, `org.uk`, `gov.uk`, etc. (e.g. `gov.uk` is signed but `ncsc.gov.uk` under it is not).
- **Snapshot in time.** DNSSEC status changes; this reflects the day of the scan.
- **"Signed" ≠ validated chain of trust.** This detects that the answering RRset is signed (RRSIG present). A zone could in principle be signed but missing its parent DS ("island of security"); that's rare and not separately broken out here.

---

## Bottom line

DNSSEC adoption across the top million is **~7% overall (~8% of live domains)**, and that number is almost meaningless as an average — it's the blend of a few registry-driven ccTLDs at 40–60% and the generic TLDs (`.com`/`.net`/`.org`) at 4–6%. Where a registry pushes it (`.nl`, `.cz`, `.dk`, the Nordics) adoption is high; everywhere else, and especially on CDN-fronted commercial domains, it stays marginal.
