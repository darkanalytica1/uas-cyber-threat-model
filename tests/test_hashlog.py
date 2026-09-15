from uasthreat.hashlog import GENESIS, HashChainLog

KEY = b"anchor-key-held-elsewhere"


def make(n=5):
    log = HashChainLog()
    for i in range(n):
        log.append({"event": f"e{i}"}, ts=100.0 + i)
    return log


def test_intact_chain_verifies_and_links():
    log = make()
    assert log.verify().ok
    assert log.entries[0]["prev"] == GENESIS
    assert all(log.entries[i]["prev"] == log.entries[i - 1]["hash"] for i in range(1, 5))


def test_edit_detected_at_edited_entry():
    log = make()
    log.entries[2] = {**log.entries[2], "event": {"event": "changed"}}
    r = log.verify()
    assert not r.ok and r.first_bad_index == 2


def test_delete_detected():
    log = make()
    del log.entries[1]
    r = log.verify()
    assert not r.ok and r.first_bad_index == 1


def test_reorder_detected():
    log = make()
    log.entries[1], log.entries[2] = log.entries[2], log.entries[1]
    assert not log.verify().ok


def test_truncation_needs_anchor():
    log = make()
    anchor = log.anchor(KEY)
    short = HashChainLog(log.entries[:3])
    assert short.verify().ok                                  # a chain alone cannot see truncation
    assert not short.verify_against_anchor(anchor, KEY).ok


def test_full_rewrite_needs_anchor():
    log = make()
    anchor = log.anchor(KEY)
    forged = HashChainLog()
    for i in range(5):
        forged.append({"event": "forged" if i == 2 else f"e{i}"}, ts=100.0 + i)
    assert forged.verify().ok                                 # internally consistent
    assert not forged.verify_against_anchor(anchor, KEY).ok   # but not the anchored history


def test_growth_after_anchor_is_fine_and_forged_anchor_fails():
    log = make()
    anchor = log.anchor(KEY)
    log.append({"event": "later"}, ts=200.0)
    assert log.verify_against_anchor(anchor, KEY).ok
    assert not log.verify_against_anchor(anchor, b"wrong key").ok


def test_jsonl_roundtrip():
    log = make()
    again = HashChainLog.from_jsonl(log.to_jsonl())
    assert again.verify().ok and again.head == log.head
