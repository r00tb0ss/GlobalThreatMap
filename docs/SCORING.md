# Threat score and confidence

Implemented in `backend/gti/scoring.py`; covered by `backend/tests/test_parsers_scoring.py`.

Each source has a fixed weight: how strong a signal a listing from it is.

| Source | Weight |
|---|---|
| Feodo Tracker (confirmed botnet C2) | 90 |
| AbuseIPDB | 65 |
| Emerging Threats compromised | 60 |
| Local sensor (observed here) | 60 |
| CINS Army | 55 |
| blocklist.de | 50 |

For one IP, the distinct sources that currently list it are combined with a noisy-OR, then scaled by
recency of the newest listing:

```
base  = 1 - Π (1 - weight_i / 100)        (each source counted once)
score = round(100 × base × recency)
recency = 1.0 if seen ≤ 2 days ago, 0.9 ≤ 7 days, 0.75 ≤ 30 days, else 0.6
```

**Confidence** describes corroboration, not severity: *low* = 1 source, *medium* = 2, *high* = 3+.

Verified test cases:

| Input | Score | Confidence |
|---|---|---|
| Feodo only, today | 90 | low |
| weights 50 + 60, today | 80 | medium |
| Feodo + blocklist.de, today | 95 | medium |
| weight 80, 5 days old | 72 | low |
| weight 80, 20 days old | 60 | low |
| weight 80, 90 days old | 48 | low |
| same source listed twice | counted once | |

**A score is reputation, not proof of an attack.** The IP detail panel shows the formula's inputs for
every IP, and says separately whether anything was observed directly.

GreyNoise arcs carry no IP and are not scored.
