"""Builds small APK files for the signature tests.

They carry real X.509 certificates in the places Android keeps them: a
v1 (JAR) signature in META-INF, and APK Signing Blocks (v2, v3) just
before the zip's central directory. The signatures are not valid, which
does not matter: ISDi reads which certificate signed an installed app
(Android has already checked the signature before installing it); it
does not verify signatures itself.
"""

import datetime
import hashlib
import io
import struct
import zipfile
from typing import Iterable, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

V2_ID = 0x7109871A
V3_ID = 0xF05368C0
MAGIC = b"APK Sig Block 42"


def make_cert(name: str):
    """A self-signed certificate and its key."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return cert, key


def der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def sha1(cert) -> str:
    return hashlib.sha1(der(cert)).hexdigest().upper()


def _lp(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def _seq(items: Iterable[bytes]) -> bytes:
    return _lp(b"".join(_lp(i) for i in items))


def _signer_v2(certs: List[bytes]) -> bytes:
    digests = _seq([struct.pack("<I", 0x0103) + _lp(b"\x00" * 32)])
    signed = digests + _seq(certs) + _seq([])
    sigs = _seq([struct.pack("<I", 0x0103) + _lp(b"\x00" * 64)])
    return _lp(signed) + sigs + _lp(b"pubkey")


def _signer_v3(certs: List[bytes]) -> bytes:
    digests = _seq([struct.pack("<I", 0x0103) + _lp(b"\x00" * 32)])
    sdk = struct.pack("<II", 28, 0x7FFFFFFF)
    signed = digests + _seq(certs) + sdk + _seq([])
    sigs = _seq([struct.pack("<I", 0x0103) + _lp(b"\x00" * 64)])
    return _lp(signed) + sdk + sigs + _lp(b"pubkey")


def signing_block(pairs: List[tuple]) -> bytes:
    body = b"".join(
        struct.pack("<Q", 4 + len(value)) + struct.pack("<I", pid) + value
        for pid, value in pairs
    )
    size = len(body) + 8 + 16
    return struct.pack("<Q", size) + body + struct.pack("<Q", size) + MAGIC


def v2_value(*certs) -> bytes:
    return _lp(_lp(_signer_v2([der(c) for c in certs])))


def v3_value(*certs) -> bytes:
    return _lp(_lp(_signer_v3([der(c) for c in certs])))


def _zip(v1_cert=None, v1_key=None, comment: bytes = b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 60)
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        if v1_cert is not None:
            sf = b"Signature-Version: 1.0\r\n\r\n"
            z.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n")
            z.writestr("META-INF/CERT.SF", sf)
            sig = (
                pkcs7.PKCS7SignatureBuilder()
                .set_data(sf)
                .add_signer(v1_cert, v1_key, hashes.SHA256())
                .sign(
                    serialization.Encoding.DER,
                    [pkcs7.PKCS7Options.DetachedSignature],
                )
            )
            z.writestr("META-INF/CERT.EC", sig)
        z.comment = comment
    return buf.getvalue()


def _eocd_offset(data: bytes, comment: bytes) -> int:
    i = len(data) - 22 - len(comment)
    assert data[i : i + 4] == b"PK\x05\x06"
    return i


def build(
    v1=None,
    block: Optional[bytes] = None,
    comment: bytes = b"",
) -> bytes:
    """An APK: v1 is (cert, key) or None; block is an APK Signing Block
    (signing_block([...])) or None."""
    data = _zip(*(v1 or (None, None)), comment=comment)
    if block is None:
        return data
    eocd = _eocd_offset(data, comment)
    cd_size, cd_offset = struct.unpack_from("<II", data, eocd + 12)
    new_eocd = bytearray(data[eocd:])
    struct.pack_into("<I", new_eocd, 16, cd_offset + len(block))
    return data[:cd_offset] + block + data[cd_offset:eocd] + bytes(new_eocd)
