from uasthreat.update_chain import Device, HmacDemoVerifier, make_signed_manifest

ROOT = HmacDemoVerifier(b"root")
FW = b"firmware 2.0"


def dev():
    return Device(ROOT)


def test_valid_update_accepted_and_raises_floor():
    d = dev()
    sm = make_signed_manifest(ROOT, "fc", "2.0", 4, FW)
    assert d.install("fc", FW, sm).accepted
    assert d.min_security_version["fc"] == 4


def test_altered_image_rejected():
    sm = make_signed_manifest(ROOT, "fc", "2.0", 4, FW)
    assert dev().install("fc", FW + b"x", sm).reason.startswith("image does not match")


def test_unknown_signer_rejected():
    sm = make_signed_manifest(HmacDemoVerifier(b"other"), "fc", "2.0", 4, FW)
    assert dev().install("fc", FW, sm).reason == "manifest signature invalid"


def test_rollback_rejected_after_newer_install():
    d = dev()
    assert d.install("fc", FW, make_signed_manifest(ROOT, "fc", "2.0", 4, FW)).accepted
    old = b"firmware 1.0"
    r = d.install("fc", old, make_signed_manifest(ROOT, "fc", "1.0", 2, old))
    assert not r.accepted and "rollback" in r.reason
    assert d.min_security_version["fc"] == 4


def test_wrong_component_rejected():
    img = b"payload"
    r = dev().install("fc", img, make_signed_manifest(ROOT, "payload", "1", 1, img))
    assert not r.accepted and "not 'fc'" in r.reason


def test_failed_install_does_not_raise_floor():
    d = dev()
    sm = make_signed_manifest(ROOT, "fc", "3.0", 9, FW)
    d.install("fc", FW + b"tampered", sm)
    assert d.min_security_version.get("fc", 0) == 0


def test_boot_chain_stops_at_first_failure():
    boot, app = b"boot", b"app"
    chain = [
        ("bootloader", boot, make_signed_manifest(ROOT, "bootloader", "1", 1, boot)),
        ("fc", b"modified", make_signed_manifest(ROOT, "fc", "1", 1, FW)),
        ("app", app, make_signed_manifest(ROOT, "app", "1", 1, app)),
    ]
    trace = dev().boot(chain)
    assert [d.accepted for d in trace] == [True, False]
