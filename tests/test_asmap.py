from typing import List, Tuple

from electrum.asmap import (
    ASMap,
    ASMapParseError,
    _CODER_ASN,
    _CODER_INS,
    _CODER_JUMP,
    _CODER_MATCH,
    _INS_DEFAULT,
    _INS_JUMP,
    _INS_MATCH,
    _INS_RETURN,
)

from . import ElectrumTestCase


def _encode_varlen(val: int, minval: int, clsbits: Tuple[int, ...]) -> List[int]:
    """Mirror of Bitcoin Core's _VarLenCoder.encode. Used only by tests
    to synthesize binary ASMaps inline."""
    maxval = minval + sum(1 << b for b in clsbits) - 1
    assert minval <= val <= maxval, (val, minval, maxval)
    val -= minval
    out: List[int] = []
    chosen = clsbits[-1]
    for k, bits in enumerate(clsbits):
        if val >> bits:
            val -= 1 << bits
            out.append(1)
        else:
            if k + 1 < len(clsbits):
                out.append(0)
            chosen = bits
            break
    out.extend((val >> (chosen - 1 - b)) & 1 for b in range(chosen))
    return out


def _encode_ins(ins: int) -> List[int]:
    return _encode_varlen(ins, *_CODER_INS)


def _encode_asn(asn: int) -> List[int]:
    return _encode_varlen(asn, *_CODER_ASN)


def _encode_jump(jump: int) -> List[int]:
    return _encode_varlen(jump, *_CODER_JUMP)


def _encode_match_int(match_val: int) -> List[int]:
    return _encode_varlen(match_val, *_CODER_MATCH)


def _encode_return(asn: int) -> List[int]:
    return _encode_ins(_INS_RETURN) + _encode_asn(asn)


def _encode_jump_node(left: List[int], right: List[int]) -> List[int]:
    return _encode_ins(_INS_JUMP) + _encode_jump(len(left)) + left + right


def _encode_match_node(prefix_bits: List[int], child: List[int]) -> List[int]:
    # match_val: leading 1 bit (length marker) followed by N prefix bits.
    match_val = 1
    for b in prefix_bits:
        match_val = (match_val << 1) | (b & 1)
    return _encode_ins(_INS_MATCH) + _encode_match_int(match_val) + child


def _encode_default_node(asn: int, child: List[int]) -> List[int]:
    return _encode_ins(_INS_DEFAULT) + _encode_asn(asn) + child


def _bits_to_bytes(bits: List[int]) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        out[i >> 3] |= (b & 1) << (i & 7)
    return bytes(out)


def _pad_to_minimum(data: bytes, minimum: int = 4) -> bytes:
    if len(data) < minimum:
        return data + b"\x00" * (minimum - len(data))
    return data


class TestReturnLookups(ElectrumTestCase):

    def test_asn_small(self):
        data = _pad_to_minimum(_bits_to_bytes(_encode_return(1)))
        asmap = ASMap(data)
        self.assertEqual(asmap.lookup_asn("8.8.8.8"), 1)

    def test_asn_midrange(self):
        data = _pad_to_minimum(_bits_to_bytes(_encode_return(13335)))
        asmap = ASMap(data)
        self.assertEqual(asmap.lookup_asn("1.1.1.1"), 13335)

    def test_asn_higher_class(self):
        # AS 50000 requires the second bit-width class (>= 2^15).
        data = _pad_to_minimum(_bits_to_bytes(_encode_return(50000)))
        asmap = ASMap(data)
        self.assertEqual(asmap.lookup_asn("8.8.8.8"), 50000)


class TestJumpAndMatch(ElectrumTestCase):

    def test_jump_branches_on_first_bit(self):
        # v4-mapped-v6 addresses all have first bit 0, so we test using
        # v6 addresses whose first bits differ.
        root = _encode_jump_node(_encode_return(1), _encode_return(2))
        asmap = ASMap(_pad_to_minimum(_bits_to_bytes(root)))
        self.assertEqual(asmap.lookup_asn("::1"), 1)       # first bit 0
        self.assertEqual(asmap.lookup_asn("8000::"), 2)    # first bit 1

    def test_default_then_match(self):
        # Tree: DEFAULT AS9999 -> MATCH 8 bits of 1 -> RETURN AS42
        # MATCH's maximum prefix length is 8 (clsbits tops out at 8).
        # To match the first 16 bits of an address we chain two MATCH
        # nodes.
        inner_match = _encode_match_node([1] * 8, _encode_return(42))
        outer_match = _encode_match_node([1] * 8, inner_match)
        root = _encode_default_node(9999, outer_match)
        asmap = ASMap(_pad_to_minimum(_bits_to_bytes(root)))
        # IP starting with 0xFFFF -> AS42
        self.assertEqual(asmap.lookup_asn("ffff::"), 42)
        # Other IPv6 -> fallback AS9999
        self.assertEqual(asmap.lookup_asn("2001:db8::"), 9999)
        # IPv4 -> mapped under ::ffff:0:0/96, so first 16 bits are zero,
        # not 0xFFFF -> AS9999
        self.assertEqual(asmap.lookup_asn("1.2.3.4"), 9999)


class TestIPv4Mapping(ElectrumTestCase):

    def test_ipv4_and_v4_mapped_v6_lookups_agree(self):
        root = _encode_default_node(42, _encode_return(42))
        asmap = ASMap(_pad_to_minimum(_bits_to_bytes(root)))
        self.assertEqual(
            asmap.lookup_asn("1.2.3.4"),
            asmap.lookup_asn("::ffff:1.2.3.4"),
        )


class TestRejection(ElectrumTestCase):

    def test_too_small_file_rejected(self):
        with self.assertRaises(ASMapParseError):
            ASMap(b"\x00" * 3)

    def test_too_large_file_rejected(self):
        with self.assertRaises(ASMapParseError):
            ASMap(b"\x00" * (16 * 1024 * 1024 + 1))

    def test_invalid_ip_string_returns_none(self):
        asmap = ASMap(_pad_to_minimum(_bits_to_bytes(_encode_return(1))))
        self.assertIsNone(asmap.lookup_asn("not an ip"))

    def test_truncation_in_jump_subtree_returns_default(self):
        # 0x01 0x00 0x00 0x00 = JUMP(17), with left = RETURN AS1 but the
        # right subtree is truncated. Addresses whose first bit is 1
        # must fall back to default (which is None).
        data = bytes([0x01, 0x00, 0x00, 0x00])
        asmap = ASMap(data)
        self.assertEqual(asmap.lookup_asn("::1"), 1)       # left branch
        self.assertIsNone(asmap.lookup_asn("8000::"))      # right branch, truncated


class TestSha256AndMetadata(ElectrumTestCase):

    def test_sha256_is_stable(self):
        data = _pad_to_minimum(_bits_to_bytes(_encode_return(1)))
        self.assertEqual(ASMap(data).sha256, ASMap(data).sha256)
        self.assertEqual(len(ASMap(data).sha256), 64)

    def test_metadata_stored(self):
        data = _pad_to_minimum(_bits_to_bytes(_encode_return(1)))
        meta = {"generated_at": "2026-04-01", "sha256": "deadbeef"}
        asmap = ASMap(data, metadata=meta)
        self.assertEqual(asmap.metadata, meta)

    def test_size_reports_file_size(self):
        data = _pad_to_minimum(_bits_to_bytes(_encode_return(1)))
        self.assertEqual(ASMap(data).size, len(data))


class TestInterfaceBucketIntegration(ElectrumTestCase):

    def _everything_as42(self) -> ASMap:
        return ASMap(_pad_to_minimum(_bits_to_bytes(
            _encode_default_node(42, _encode_return(42)))))

    def _make_interface(self, *, host: str, ip: str, asmap):
        from electrum.interface import Interface, ServerAddr

        class _Net:
            pass
        net = _Net()
        net.asmap = asmap
        net.proxy = None
        iface = Interface.__new__(Interface)
        iface.server = ServerAddr(host=host, port=50002, protocol="s")
        iface.network = net
        iface._ipaddr_bucket = None
        iface.ip_addr = lambda: ip  # type: ignore[assignment]
        return iface

    def test_public_ipv4_uses_asmap_bucket(self):
        iface = self._make_interface(
            host="example.com", ip="8.8.8.8", asmap=self._everything_as42())
        self.assertEqual(iface.bucket_based_on_ipaddress(), "AS42")

    def test_public_ipv4_without_asmap_falls_back_to_slash16(self):
        iface = self._make_interface(
            host="example.com", ip="8.8.8.8", asmap=None)
        self.assertEqual(iface.bucket_based_on_ipaddress(), "8.8.0.0/16")

    def test_private_ipv4_falls_back_to_slash16_even_with_asmap(self):
        iface = self._make_interface(
            host="example.com", ip="10.1.2.3", asmap=self._everything_as42())
        self.assertEqual(iface.bucket_based_on_ipaddress(), "10.1.0.0/16")

    def test_loopback_returns_empty_bucket(self):
        iface = self._make_interface(
            host="example.com", ip="127.0.0.1",
            asmap=self._everything_as42())
        self.assertEqual(iface.bucket_based_on_ipaddress(), "")

    def test_tor_host_unaffected_by_asmap(self):
        from electrum.interface import BUCKET_NAME_OF_ONION_SERVERS

        iface = self._make_interface(
            host="foo.onion", ip="", asmap=self._everything_as42())
        self.assertEqual(
            iface.bucket_based_on_ipaddress(),
            BUCKET_NAME_OF_ONION_SERVERS,
        )

