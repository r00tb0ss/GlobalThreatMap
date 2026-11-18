import pytest
from gti import feeds as F, scoring


def test_norm_ip_rejects_private_and_garbage():
    assert F.norm_ip("8.8.8.8") == "8.8.8.8"
    for bad in ["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "999.1.1.1", "", "abc", "::1", "fe80::1"]:
        assert F.norm_ip(bad) is None, bad


def test_norm_ip_ipv6_and_mapped():
    assert F.norm_ip("2001:4860:4860:0:0:0:0:8888") == "2001:4860:4860::8888"
    assert F.norm_ip("::ffff:8.8.8.8") == "8.8.8.8"


def test_plain_list_parser_skips_comments_and_bad_lines():
    out = F.parse_plain_ip_list("# hi\n8.8.8.8 # trailing\n; x\n\nfoo\n1.1.1.1\n10.1.1.1\n", "x")
    assert [r["ip"] for r in out] == ["8.8.8.8", "1.1.1.1"]


def test_feodo_parser_and_bad_shape():
    out = F.parse_feodo('[{"ip_address":"1.1.1.1","port":443,"malware":"Emotet"},{"ip_address":"nope"},"junk",{"ip_address":"2.2.2.2","port":99999}]')
    assert out[0] == {"ip": "1.1.1.1", "category": "botnet_c2", "malware": "Emotet", "port": 443}
    assert out[1]["port"] is None and len(out) == 2
    with pytest.raises(ValueError):
        F.parse_feodo('{"unexpected": 1}')
    with pytest.raises(Exception):
        F.parse_feodo("<html>not json</html>")


def test_abuseipdb_parser():
    out = F.parse_abuseipdb('{"data":[{"ipAddress":"1.1.1.1","abuseConfidenceScore":100},{"ipAddress":"10.0.0.1"}]}')
    assert [r["ip"] for r in out] == ["1.1.1.1"]


NOW = 1_000_000_000


def test_score_single_source_known_values():
    r = scoring.score_ip([("feodo", NOW)], {"feodo": 90}, now=NOW)
    assert r["score"] == 90 and r["confidence"] == "low"


def test_score_noisy_or_two_sources():
    r = scoring.score_ip([("a", NOW), ("b", NOW)], {"a": 50, "b": 60}, now=NOW)
    assert r["score"] == 80 and r["confidence"] == "medium"   # 1-(0.5*0.4)=0.8


def test_score_recency_decay_and_bounds():
    w = {"a": 80}
    assert scoring.score_ip([("a", NOW - 5 * 86400)], w, now=NOW)["score"] == 72
    assert scoring.score_ip([("a", NOW - 20 * 86400)], w, now=NOW)["score"] == 60
    assert scoring.score_ip([("a", NOW - 90 * 86400)], w, now=NOW)["score"] == 48
    r = scoring.score_ip([("a", NOW), ("b", NOW), ("c", NOW)], {"a": 99, "b": 99, "c": 99}, now=NOW)
    assert r["score"] <= 100 and r["confidence"] == "high"


def test_score_same_source_twice_not_double_counted():
    r = scoring.score_ip([("a", NOW), ("a", NOW - 100)], {"a": 50}, now=NOW)
    assert r["score"] == 50 and len(r["breakdown"]) == 1


def test_score_empty():
    assert scoring.score_ip([], {})["score"] == 0
