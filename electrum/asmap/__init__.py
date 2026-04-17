"""
ASMap: compact binary prefix tree mapping IP addresses to Autonomous
System Numbers. Used by Network for AS-aware peer-diversity bucketing.

The binary file format is the one produced by Bitcoin Core's
contrib/asmap tooling and https://asmap.org/. We implement the reader
and lookup side here; regeneration stays with upstream tooling so that
Electrum's shipped asmap.dat can be byte-compared against the published
source. See Bitcoin Core's contrib/asmap/asmap.py for a reference
encoder.

The lookup walks the binary stream directly rather than materialising
the full prefix trie in memory: a real-world asmap.dat covers ~800k
routed Internet prefixes and a Python trie object for that would be
on the order of 100MB.
"""

import hashlib
import ipaddress
import json
import os
from typing import Optional, Tuple, Union

from ..logging import get_logger
from ..util import resource_path

_logger = get_logger(__name__)


class ASMapParseError(Exception):
    pass


_INS_RETURN = 0
_INS_JUMP = 1
_INS_MATCH = 2
_INS_DEFAULT = 3

_CODER_INS = (0, (0, 0, 1))
_CODER_ASN = (1, tuple(range(15, 25)))
_CODER_MATCH = (2, tuple(range(1, 9)))
_CODER_JUMP = (17, tuple(range(5, 31)))

_MIN_FILE_SIZE = 4
_MAX_FILE_SIZE = 16 * 1024 * 1024

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class ASMap:
    """Parsed ASMap. Read-only after construction and safe to share
    across threads."""

    __slots__ = ("_bits", "_sha256", "_metadata")

    def __init__(self, data: bytes, *, metadata: Optional[dict] = None):
        if not (_MIN_FILE_SIZE <= len(data) <= _MAX_FILE_SIZE):
            raise ASMapParseError(f"asmap size out of range: {len(data)}")
        self._bits = bytes(data)
        self._sha256 = hashlib.sha256(self._bits).hexdigest()
        self._metadata = metadata
        # Smoke-test: at least the first instruction must decode.
        self._decode_varlen(*_CODER_INS, bitpos=0)

    @classmethod
    def from_file(cls, path: str,
                  metadata: Optional[dict] = None) -> "ASMap":
        with open(path, "rb") as f:
            data = f.read()
        return cls(data, metadata=metadata)

    @property
    def sha256(self) -> str:
        return self._sha256

    @property
    def size(self) -> int:
        return len(self._bits)

    @property
    def metadata(self) -> Optional[dict]:
        return self._metadata

    def _decode_varlen(self, minval: int, clsbits: Tuple[int, ...],
                       bitpos: int) -> Tuple[int, int]:
        bits = self._bits
        nbits = len(bits) * 8
        val = minval
        chosen = clsbits[-1]
        for k in range(len(clsbits) - 1):
            if bitpos >= nbits:
                raise ASMapParseError("unexpected end of asmap stream")
            bit = (bits[bitpos >> 3] >> (bitpos & 7)) & 1
            bitpos += 1
            if not bit:
                chosen = clsbits[k]
                break
            val += 1 << clsbits[k]
        for i in range(chosen):
            if bitpos >= nbits:
                raise ASMapParseError("unexpected end of asmap stream")
            bit = (bits[bitpos >> 3] >> (bitpos & 7)) & 1
            bitpos += 1
            val += bit << (chosen - 1 - i)
        return val, bitpos

    def lookup_asn(self, ip: Union[str, IPAddress]) -> Optional[int]:
        """Return the ASN for an IP address, or None if the address is
        not covered by this ASMap. Accepts either a string or an
        already-parsed ``ipaddress`` object."""
        if isinstance(ip, str):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return None
        else:
            addr = ip
        if isinstance(addr, ipaddress.IPv4Address):
            packed = b"\x00" * 10 + b"\xff\xff" + addr.packed
        else:
            packed = addr.packed
        return self._lookup_packed(packed)

    def _lookup_packed(self, packed: bytes) -> Optional[int]:
        """Walk the bit stream alongside a 16-byte big-endian address."""
        bits = self._bits
        nbits = len(bits) * 8
        bitpos = 0
        addr_pos = 0
        max_addr = len(packed) * 8
        default: Optional[int] = None
        try:
            while bitpos < nbits:
                ins, bitpos = self._decode_varlen(*_CODER_INS, bitpos=bitpos)
                if ins == _INS_RETURN:
                    asn, _ = self._decode_varlen(*_CODER_ASN, bitpos=bitpos)
                    return asn if asn > 0 else default
                if ins == _INS_JUMP:
                    jump, bitpos = self._decode_varlen(
                        *_CODER_JUMP, bitpos=bitpos)
                    if addr_pos >= max_addr:
                        return default
                    if (packed[addr_pos >> 3] >> (7 - (addr_pos & 7))) & 1:
                        bitpos += jump
                    addr_pos += 1
                elif ins == _INS_MATCH:
                    match_val, bitpos = self._decode_varlen(
                        *_CODER_MATCH, bitpos=bitpos)
                    match_len = match_val.bit_length() - 1
                    for i in range(match_len):
                        if addr_pos >= max_addr:
                            return default
                        expected = (match_val >> (match_len - 1 - i)) & 1
                        actual = (packed[addr_pos >> 3]
                                  >> (7 - (addr_pos & 7))) & 1
                        if actual != expected:
                            return default
                        addr_pos += 1
                elif ins == _INS_DEFAULT:
                    asn, bitpos = self._decode_varlen(
                        *_CODER_ASN, bitpos=bitpos)
                    default = asn if asn > 0 else None
                else:
                    return default
        except ASMapParseError:
            return default
        return default


def _load_metadata(dat_path: str) -> Optional[dict]:
    json_path = os.path.splitext(dat_path)[0] + ".json"
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, OSError, ValueError):
        return None


def load_bundled_asmap() -> Optional["ASMap"]:
    """Load the ASMap file that ships with the Electrum package.

    Returns None and logs a warning/info line on any failure; the caller
    is expected to fall back to the legacy ``/16``/``/48`` prefix
    bucketing when this returns None."""
    path = resource_path("asmap", "asmap.dat")
    try:
        metadata = _load_metadata(path)
        asmap = ASMap.from_file(path, metadata=metadata)
    except FileNotFoundError:
        _logger.info(
            f"asmap file not present at {path}; "
            f"using /16,/48 prefix bucketing")
        return None
    except (OSError, ASMapParseError) as e:
        _logger.warning(
            f"failed to load asmap from {path}: {e!r}; "
            f"using /16,/48 prefix bucketing")
        return None
    meta_str = ""
    if asmap.metadata:
        generated = asmap.metadata.get("generated_at")
        source = asmap.metadata.get("source_url")
        if generated or source:
            meta_str = f", generated_at={generated}, source={source}"
    _logger.info(
        f"loaded asmap from {path}: {asmap.size} bytes, "
        f"sha256={asmap.sha256}{meta_str}")
    return asmap
