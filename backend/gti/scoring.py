"""Transparent threat scoring.

Each *source* has a fixed weight (0-100) describing how strong a signal a listing from it is
(see feeds.FEEDS and docs/SCORING.md). For one IP the per-source weights are combined with a
noisy-OR (independent corroboration raises the score but never exceeds 100):

    base  = 1 - prod(1 - w_i/100)            over distinct sources
    score = round(100 * base * recency)      recency: <=2d 1.0, <=7d 0.9, <=30d 0.75, else 0.6

Confidence reflects corroboration, not severity:
    high = >=3 distinct sources, medium = 2, low = 1.

A score is an indicator reputation, NOT proof that the IP attacked anything.
"""
import time

RECENCY = [(2 * 86400, 1.0), (7 * 86400, 0.9), (30 * 86400, 0.75)]
OLD = 0.6
UNKNOWN_SOURCE_WEIGHT = 30


def recency_factor(last_seen, now=None):
    age = (now or time.time()) - last_seen
    for limit, f in RECENCY:
        if age <= limit:
            return f
    return OLD


def score_ip(rows, weights, now=None):
    """rows: iterable of (source, last_seen). Returns dict with score, confidence, breakdown."""
    best = {}
    for src, last_seen in rows:
        best[src] = max(best.get(src, 0), last_seen)
    if not best:
        return {"score": 0, "confidence": "none", "recency_factor": 0, "breakdown": []}
    prod = 1.0
    breakdown = []
    newest = 0
    for src, ls in sorted(best.items()):
        w = weights.get(src, UNKNOWN_SOURCE_WEIGHT)
        prod *= 1 - w / 100.0
        newest = max(newest, ls)
        breakdown.append({"source": src, "weight": w, "last_seen": ls})
    base = 1 - prod
    rec = recency_factor(newest, now)
    n = len(best)
    return {
        "score": int(round(100 * base * rec)),
        "confidence": "high" if n >= 3 else "medium" if n == 2 else "low",
        "recency_factor": rec,
        "breakdown": breakdown,
    }
