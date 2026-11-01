"""Reading which certificate signed an APK (isdi/scanner/apk_signers.py).

Stalkerware vendors rename packages to get past package-name lists; the
signing certificate stays the same, and the AssoEchap list records it.
"""

import io
import struct
import zipfile

import pytest

from isdi.scanner import apk_signers
from tests import apkfactory as f


@pytest.fixture(scope="module")
def certs():
    return {n: f.make_cert(n) for n in ("vendor", "rotated", "other")}


def _write(tmp_path, data, name="app.apk"):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_v2_signer(tmp_path, certs):
    cert, _ = certs["vendor"]
    apk = f.build(block=f.signing_block([(f.V2_ID, f.v2_value(cert))]))
    assert apk_signers.signer_sha1s(_write(tmp_path, apk)) == {f.sha1(cert)}


def test_v3_signer(tmp_path, certs):
    cert, _ = certs["vendor"]
    apk = f.build(block=f.signing_block([(f.V3_ID, f.v3_value(cert))]))
    assert apk_signers.signer_sha1s(_write(tmp_path, apk)) == {f.sha1(cert)}


def test_v1_signer(tmp_path, certs):
    apk = f.build(v1=certs["vendor"])
    assert apk_signers.signer_sha1s(_write(tmp_path, apk)) == {
        f.sha1(certs["vendor"][0])
    }


def test_all_schemes_are_read(tmp_path, certs):
    """A rotated key signs v3 while v1/v2 keep the old one: either may be
    the one the list records."""
    old, new = certs["vendor"][0], certs["rotated"][0]
    block = f.signing_block([(f.V2_ID, f.v2_value(old)), (f.V3_ID, f.v3_value(new))])
    apk = f.build(v1=certs["vendor"], block=block)
    assert apk_signers.signer_sha1s(_write(tmp_path, apk)) == {
        f.sha1(old),
        f.sha1(new),
    }


def test_unknown_block_entries_are_skipped(tmp_path, certs):
    cert = certs["vendor"][0]
    block = f.signing_block(
        [(0x42726577, b"\x00" * 100), (f.V2_ID, f.v2_value(cert))]  # padding id
    )
    apk = f.build(block=block)
    assert apk_signers.signer_sha1s(_write(tmp_path, apk)) == {f.sha1(cert)}


def test_zip_comment_does_not_hide_the_block(tmp_path, certs):
    cert = certs["vendor"][0]
    apk = f.build(
        block=f.signing_block([(f.V2_ID, f.v2_value(cert))]),
        comment=b"PK\x05\x06 not really an end record" + b"x" * 300,
    )
    assert apk_signers.signer_sha1s(_write(tmp_path, apk)) == {f.sha1(cert)}


def test_v1_only_apk_with_a_decoy_end_record_cannot_be_checked(tmp_path, certs):
    apk = f.build(v1=certs["vendor"], comment=b"PK\x05\x06" + b"x" * 40)
    with pytest.raises(apk_signers.ApkError):
        apk_signers.signer_sha1s(_write(tmp_path, apk))


def test_unsigned_apk_has_no_signers(tmp_path):
    assert apk_signers.signer_sha1s(_write(tmp_path, f.build())) == set()


def test_not_a_zip(tmp_path):
    with pytest.raises(apk_signers.ApkError):
        apk_signers.signer_sha1s(_write(tmp_path, b"not an apk at all" * 10))


def test_empty_file(tmp_path):
    with pytest.raises(apk_signers.ApkError):
        apk_signers.signer_sha1s(_write(tmp_path, b""))


@pytest.mark.parametrize("cut", [1, 9, 30, 60])
def test_truncated_signer_is_an_error(tmp_path, certs, cut):
    value = f.v2_value(certs["vendor"][0])
    block = f.signing_block([(f.V2_ID, value[:-cut])])
    with pytest.raises(apk_signers.ApkError):
        apk_signers.signer_sha1s(_write(tmp_path, f.build(block=block)))


def test_lengths_past_the_block_are_an_error(tmp_path):
    # A pair whose length runs past the end of the block.
    body = struct.pack("<Q", 2**40) + struct.pack("<I", f.V2_ID) + b"\x00" * 8
    size = len(body) + 24
    block = struct.pack("<Q", size) + body + struct.pack("<Q", size) + f.MAGIC
    with pytest.raises(apk_signers.ApkError):
        apk_signers.signer_sha1s(_write(tmp_path, f.build(block=block)))


def test_block_size_larger_than_file_is_an_error(tmp_path, certs):
    block = bytearray(f.signing_block([(f.V2_ID, f.v2_value(certs["vendor"][0]))]))
    struct.pack_into("<Q", block, len(block) - 24, 2**50)
    with pytest.raises(apk_signers.ApkError):
        apk_signers.signer_sha1s(_write(tmp_path, f.build(block=bytes(block))))


def test_oversized_v1_signature_file_is_an_error(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("META-INF/CERT.RSA", b"\x00" * (apk_signers.MAX_V1_BYTES + 1))
    with pytest.raises(apk_signers.ApkError):
        apk_signers.signer_sha1s(_write(tmp_path, buf.getvalue()))


def test_garbage_v1_signature_is_an_error(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("META-INF/CERT.RSA", b"\x30\x03\x02\x01\x00")
    with pytest.raises(apk_signers.ApkError):
        apk_signers.signer_sha1s(_write(tmp_path, buf.getvalue()))


def test_agrees_with_androguard(tmp_path, certs):
    """An independent implementation reads the same certificates."""
    androguard_apk = pytest.importorskip("androguard.core.apk")
    old, new = certs["vendor"][0], certs["rotated"][0]
    block = f.signing_block([(f.V2_ID, f.v2_value(old)), (f.V3_ID, f.v3_value(new))])
    path = _write(tmp_path, f.build(v1=certs["vendor"], block=block))
    a = androguard_apk.APK(str(path))
    theirs = set()
    for der in (a.get_certificates_der_v3() + a.get_certificates_der_v2()) + [
        c.dump() for c in a.get_certificates_v1()
    ]:
        import hashlib

        theirs.add(hashlib.sha1(der).hexdigest().upper())
    assert apk_signers.signer_sha1s(path) == theirs
