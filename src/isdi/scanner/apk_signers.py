"""Which certificates signed an APK.

Stalkerware vendors rename their apps' packages to get past lists of
package names. The certificate that signs the app stays the same, and
the AssoEchap stalkerware-indicators list records its SHA-1 (the
fingerprint Google Play shows for an app's signing key). This reads the
signer certificates from an APK pulled off the phone:

- v2 and v3 signatures (Android 7 and 9 on): the APK Signing Block that
  sits just before the zip's central directory
  (https://source.android.com/docs/security/features/apksigning/v2);
- v1 (JAR) signatures: the PKCS#7 files in META-INF.

Signatures are not verified: Android checked them when it installed the
app, so the certificates of an installed APK are its signer's. The file
comes from the phone and is not trusted: every length is checked against
the bytes that are really there, and nothing is read without a bound.
"""

import hashlib
import os
import struct
import zipfile
import zlib
from typing import BinaryIO, Iterator, Set, Tuple, Union

from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

V2_ID = 0x7109871A
V3_ID = 0xF05368C0
V31_ID = 0x1B93AD61
_MAGIC = b"APK Sig Block 42"
_EOCD_SIG = b"PK\x05\x06"
_EOCD_MIN = 22
# A zip comment is at most 65535 bytes.
_EOCD_SEARCH = _EOCD_MIN + 0xFFFF
# Real signing blocks are a few KB to a few hundred KB.
MAX_BLOCK_BYTES = 16 * 1024 * 1024
MAX_V1_BYTES = 1024 * 1024
_V1_SUFFIXES = (".RSA", ".DSA", ".EC")


class ApkError(ValueError):
    """The file is not an APK this can read."""


# What Python's zip reader raises on a file it cannot read. The file is
# built by whoever wrote the app, so all of these mean "cannot check",
# never a failed scan. NotImplementedError: a newer "version needed to
# extract" or an unsupported compression; zlib.error and EOFError: a
# broken compressed stream.
_ZIP_ERRORS = (
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    OSError,
    RuntimeError,
    NotImplementedError,
    EOFError,
    ValueError,
    zlib.error,
)


def signer_sha1s(path: Union[str, "os.PathLike[str]"]) -> Set[str]:
    """Upper-case hex SHA-1 of every certificate that signed the APK,
    from all signature schemes it carries. Empty for an unsigned APK."""
    found: Set[str] = set()
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        cd_offset = _central_directory_offset(fh, size)
        block = _signing_block(fh, cd_offset)
        if block is not None:
            for pid, value in _pairs(block):
                if pid in (V2_ID, V3_ID, V31_ID):
                    for cert in _scheme_certs(value, v3=pid != V2_ID):
                        found.add(_sha1(cert))
    try:
        found |= _v1_signers(path)
    except ApkError:
        # Python's zip reader trips over some files Android reads (an end
        # record repeated in the zip comment). The v2/v3 certificates
        # already identify the signer; without them, the app cannot be
        # checked.
        if not found:
            raise
    return found


def _sha1(der: bytes) -> str:
    return hashlib.sha1(der).hexdigest().upper()


def _central_directory_offset(fh: BinaryIO, size: int) -> int:
    if size < _EOCD_MIN:
        raise ApkError("too small to be a zip file")
    start = max(0, size - _EOCD_SEARCH)
    fh.seek(start)
    tail = fh.read(size - start)
    # The end record is the last signature whose comment length reaches
    # exactly the end of the file (a comment may contain the signature).
    i = tail.rfind(_EOCD_SIG)
    while i >= 0:
        if len(tail) - i >= _EOCD_MIN:
            (comment_len,) = struct.unpack_from("<H", tail, i + 20)
            if i + _EOCD_MIN + comment_len == len(tail):
                (cd_offset,) = struct.unpack_from("<I", tail, i + 16)
                if cd_offset > start + i:
                    raise ApkError("central directory offset is past its end")
                return cd_offset
        i = tail.rfind(_EOCD_SIG, 0, i)
    raise ApkError("no zip end of central directory record")


def _signing_block(fh: BinaryIO, cd_offset: int):
    """The pairs region of the APK Signing Block, or None if there is none."""
    if cd_offset < 32:
        return None
    fh.seek(cd_offset - 24)
    footer = fh.read(24)
    if len(footer) != 24 or footer[8:] != _MAGIC:
        return None
    (size,) = struct.unpack_from("<Q", footer, 0)
    # size counts everything after the leading size field.
    if size < 24 or size > MAX_BLOCK_BYTES or size + 8 > cd_offset:
        raise ApkError("APK Signing Block size is out of range")
    start = cd_offset - size - 8
    fh.seek(start)
    block = fh.read(size + 8)
    if len(block) != size + 8 or struct.unpack_from("<Q", block, 0)[0] != size:
        raise ApkError("APK Signing Block sizes do not match")
    return block[8:-24]


def _pairs(region: bytes) -> Iterator[Tuple[int, bytes]]:
    pos = 0
    while pos < len(region):
        if len(region) - pos < 12:
            raise ApkError("truncated APK Signing Block entry")
        (length,) = struct.unpack_from("<Q", region, pos)
        if length < 4 or length > len(region) - pos - 8:
            raise ApkError("APK Signing Block entry runs past the block")
        (pid,) = struct.unpack_from("<I", region, pos + 8)
        yield pid, region[pos + 12 : pos + 8 + length]
        pos += 8 + length


class _Reader:
    """Length-prefixed fields (uint32 little-endian lengths)."""

    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def done(self) -> bool:
        return self.pos >= len(self.data)

    def uint32(self) -> int:
        if len(self.data) - self.pos < 4:
            raise ApkError("truncated signature data")
        (v,) = struct.unpack_from("<I", self.data, self.pos)
        self.pos += 4
        return v

    def prefixed(self) -> bytes:
        n = self.uint32()
        if n > len(self.data) - self.pos:
            raise ApkError("signature field runs past its container")
        v = self.data[self.pos : self.pos + n]
        self.pos += n
        return v


def _scheme_certs(value: bytes, v3: bool) -> Iterator[bytes]:
    """Certificates in a v2 or v3 signature scheme block. In both, a
    signer's signed data starts with the digests and then the
    certificates."""
    signers = _Reader(_Reader(value).prefixed())
    while not signers.done():
        signer = _Reader(signers.prefixed())
        signed = _Reader(signer.prefixed())
        signed.prefixed()  # digests
        certs = _Reader(signed.prefixed())
        while not certs.done():
            yield certs.prefixed()
        if v3:
            signed.uint32(), signed.uint32()  # min and max SDK
        signed.prefixed()  # additional attributes


def _v1_signers(path) -> Set[str]:
    try:
        z = zipfile.ZipFile(path)
    except _ZIP_ERRORS as e:
        raise ApkError("not a zip file") from e
    found: Set[str] = set()
    with z:
        for info in z.infolist():
            name = info.filename.upper()
            if not (name.startswith("META-INF/") and name.endswith(_V1_SUFFIXES)):
                continue
            if name.count("/") != 1:
                continue
            if info.file_size > MAX_V1_BYTES:
                raise ApkError("v1 signature file is too large")
            try:
                with z.open(info) as member:
                    data = member.read(MAX_V1_BYTES + 1)
            except _ZIP_ERRORS as e:
                raise ApkError("cannot read a v1 signature file") from e
            if len(data) > MAX_V1_BYTES:
                raise ApkError("v1 signature file is too large")
            try:
                certs = pkcs7.load_der_pkcs7_certificates(data)
            except ValueError as e:
                raise ApkError("v1 signature file is not PKCS#7") from e
            for cert in certs:
                found.add(_sha1(cert.public_bytes(Encoding.DER)))
    return found
