"""Maps IP addresses to the Autonomous System (AS) that announces them.

Reads the asmap file format of Bitcoin Core: a bit stream of instructions that is walked
alongside the bits of the IP address. See contrib/asmap/asmap.py in bitcoin/bitcoin.
"""

from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Sequence, Tuple, Union

from ..crypto import sha256
from ..logging import get_logger
from ..util import resource_path

_logger = get_logger(__name__)

# asmap.dat is 2026/1793895420_asmap.dat from https://github.com/bitcoin-core/asmap-data
ASMAP_SHA256 = "d6b0662b787e39621900370323610005eba1106e08e917126807047529af4c2a"

# instructions
_RETURN, _JUMP, _MATCH, _DEFAULT = range(4)

# variable-length integer encodings: (minimum value, mantissa bit size of each class)
_ENC_INSTRUCTION = (0, (0, 0, 1))
_ENC_ASN = (1, tuple(range(15, 25)))
_ENC_MATCH = (2, tuple(range(1, 9)))
_ENC_JUMP = (17, tuple(range(5, 31)))


class ASMap:

    def __init__(self, data: bytes):
        self._data = data

    def _read_bit(self, pos: int) -> int:
        return (self._data[pos >> 3] >> (pos & 7)) & 1

    def _read_int(self, pos: int, minval: int, bit_sizes: Sequence[int]) -> Tuple[int, int]:
        """Decodes the integer at bit position pos. Returns it and the position after it."""
        val = minval
        mantissa_size = bit_sizes[-1]
        for size in bit_sizes[:-1]:  # the class is unary-coded
            bit = self._read_bit(pos)
            pos += 1
            if not bit:
                mantissa_size = size
                break
            val += 1 << size
        for shift in reversed(range(mantissa_size)):
            val += self._read_bit(pos) << shift
            pos += 1
        return val, pos

    def lookup_asn(self, ip_addr: Union[IPv4Address, IPv6Address]) -> Optional[int]:
        """Returns the number of the AS that announces ip_addr, or None if the map does not cover it."""
        ip = int(ip_addr)
        if ip_addr.version == 4:  # looked up as IPv4-mapped IPv6 address
            ip |= 0xffff << 32
        ip_bits_left = 128
        default_asn = None
        pos = 0
        while True:
            ins, pos = self._read_int(pos, *_ENC_INSTRUCTION)
            if ins == _RETURN:
                asn, pos = self._read_int(pos, *_ENC_ASN)
                return asn
            elif ins == _JUMP:
                offset, pos = self._read_int(pos, *_ENC_JUMP)
                ip_bits_left -= 1
                if (ip >> ip_bits_left) & 1:
                    pos += offset
            elif ins == _MATCH:
                match, pos = self._read_int(pos, *_ENC_MATCH)
                match_len = match.bit_length() - 1  # the highest set bit only marks the length
                ip_bits_left -= match_len
                if (ip >> ip_bits_left) & ((1 << match_len) - 1) != match - (1 << match_len):
                    return default_asn
            else:
                assert ins == _DEFAULT
                default_asn, pos = self._read_int(pos, *_ENC_ASN)


def load_bundled_asmap() -> Optional[ASMap]:
    """Returns the asmap shipped with Electrum, or None if the file is missing or not the expected one."""
    path = resource_path("asmap", "asmap.dat")
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        _logger.warning(f"asmap file not found at {path}")
        return None
    if sha256(data).hex() != ASMAP_SHA256:
        _logger.error(f"asmap file at {path} does not have the expected hash. ignoring it.")
        return None
    return ASMap(data)
