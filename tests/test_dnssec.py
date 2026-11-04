import asyncio
import dataclasses
import socket
import struct
import time
from types import SimpleNamespace
from typing import Dict, List, Optional, Sequence, Set, Tuple
from unittest import mock

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ed25519

from electrum import dnssec
from electrum.network import Network, ProxySettings

from . import ElectrumTestCase


OPENALIAS_TXT = '"oa1:btc recipient_address=bc1qtest; recipient_name=Alice;"'


class SignedZone:
    """A DNSSEC-signed zone with a single (combined signing) key."""

    def __init__(self, origin: str, nameservers: Sequence[str]):
        self.origin = dns.name.from_text(origin)
        self.nameservers = list(nameservers)
        self._key = ed25519.Ed25519PrivateKey.generate()
        self.dnskey = dns.dnssec.make_dnskey(self._key.public_key(), dns.dnssec.Algorithm.ED25519, flags=257)
        self.rrsets: Dict[Tuple[dns.name.Name, int], dns.rrset.RRset] = {}
        self.sigs: Dict[Tuple[dns.name.Name, int], dns.rrset.RRset] = {}
        self.cuts: Dict[dns.name.Name, dns.rrset.RRset] = {}  # delegated child -> its NS rrset
        hostmaster = 'hostmaster.' + ('' if origin == '.' else origin)
        self.add(origin, 'SOA', f'{nameservers[0]}. {hostmaster} 1 7200 3600 1209600 3600')
        self.add(origin, 'NS', *[f'{ns}.' for ns in nameservers])
        self.add_rrset(dns.rrset.from_rdata(self.origin, 3600, self.dnskey))

    def add(self, name: str, rdtype: str, *rdatas: str) -> None:
        self.add_rrset(dns.rrset.from_text_list(dns.name.from_text(name), 3600, 'IN', rdtype, list(rdatas)))

    def add_rrset(self, rrset: dns.rrset.RRset) -> None:
        key = (rrset.name, rrset.rdtype)
        self.rrsets[key] = rrset
        sig = dns.dnssec.sign(rrset, self._key, self.origin, self.dnskey, lifetime=3600)
        self.sigs[key] = dns.rrset.from_rdata(rrset.name, rrset.ttl, sig)

    def delegate(self, child: 'SignedZone') -> None:
        self.cuts[child.origin] = dns.rrset.from_text_list(
            child.origin, 3600, 'IN', 'NS', [f'{ns}.' for ns in child.nameservers])
        ds = dns.dnssec.make_ds(child.origin, child.dnskey, 'SHA256')
        self.add_rrset(dns.rrset.from_rdata(child.origin, 3600, ds))


def respond(zones: Sequence[SignedZone], q: dns.message.Message) -> dns.message.Message:
    """Answer `q` like a server that is authoritative for `zones` (no NSEC records).
    Given all zones of a hierarchy, this behaves like a recursive resolver."""
    qname, qtype = q.question[0].name, q.question[0].rdtype
    with_sigs = bool(q.ednsflags & dns.flags.DO)
    resp = dns.message.make_response(q)
    candidates = [z for z in zones
                  if qname.is_subdomain(z.origin) and not (qtype == dns.rdatatype.DS and qname == z.origin)]
    if not candidates:
        resp.set_rcode(dns.rcode.REFUSED)
        return resp
    zone = max(candidates, key=lambda z: len(z.origin))

    def add(section: List[dns.rrset.RRset], key) -> None:
        section.append(zone.rrsets[key])
        if with_sigs:
            section.append(zone.sigs[key])

    for cut, ns_rrset in zone.cuts.items():
        if qname.is_subdomain(cut) and not (qtype == dns.rdatatype.DS and qname == cut):
            resp.authority.append(ns_rrset)  # referral
            if with_sigs:
                add(resp.authority, (cut, dns.rdatatype.DS))
            return resp
    resp.flags |= dns.flags.AA
    if (qname, qtype) in zone.rrsets:
        add(resp.answer, (qname, qtype))
        return resp
    if not any(name.is_subdomain(qname) for name, _ in zone.rrsets):
        resp.set_rcode(dns.rcode.NXDOMAIN)
    add(resp.authority, (zone.origin, dns.rdatatype.SOA))
    return resp


def build_hierarchy(example_nameservers=('ns1.example-dns.test', 'ns2.example-dns.test')):
    """. -> org. -> example.org. with an OpenAlias TXT record at alias.example.org."""
    root = SignedZone('.', dnssec.ROOT_SERVERS)
    org = SignedZone('org.', ['a0.org-servers.test', 'b0.org-servers.test'])
    example = SignedZone('example.org.', example_nameservers)
    example.add('alias.example.org.', 'TXT', OPENALIAS_TXT)
    root.delegate(org)
    org.delegate(example)
    return root, org, example


@dataclasses.dataclass
class Fault:
    hosts: Set[str]
    # unreachable, refused, servfail, hang, bogus_referral, mismatched_response, garbage,
    # or answer_once: further queries on a connection hang (and count as triggering the fault)
    mode: str
    times: Optional[int] = 1  # None: forever
    triggered: int = 0

    def applies(self, host: str) -> bool:
        if host not in self.hosts or (self.times is not None and self.triggered >= self.times):
            return False
        self.triggered += 1
        return True


async def serve_dns(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                    zones: Sequence[SignedZone], host: str, fault: Optional[Fault]) -> None:
    """Answer DNS-over-TCP queries on a connection until the client closes it."""
    try:
        answered = 0
        while True:
            try:
                length, = struct.unpack('!H', await reader.readexactly(2))
                q = dns.message.from_wire(await reader.readexactly(length))
            except asyncio.IncompleteReadError:
                return
            if fault and fault.mode == 'answer_once':  # like Cloudflare's nameservers
                mode = 'hang' if answered and fault.applies(host) else None
            else:
                mode = fault.mode if fault and fault.applies(host) else None
            answered += 1
            if mode == 'hang':
                await reader.read()  # until the client gives up
                return
            if mode == 'garbage':
                wire = b'\x00\x01garbage'
            else:
                resp = respond(zones, q)
                if mode in ('refused', 'servfail'):
                    resp = dns.message.make_response(q)
                    resp.set_rcode(dns.rcode.REFUSED if mode == 'refused' else dns.rcode.SERVFAIL)
                    if mode == 'servfail':
                        resp.flags |= dns.flags.AA
                elif mode == 'bogus_referral':
                    resp = dns.message.make_response(q)
                    resp.authority.append(dns.rrset.from_text('evil.test.', 3600, 'IN', 'NS', 'ns.evil.test.'))
                elif mode == 'mismatched_response':  # like a late response to an earlier query
                    resp = respond(zones, dns.message.make_query(q.question[0].name, 'SOA', want_dnssec=True))
                wire = resp.to_wire()
            writer.write(struct.pack('!H', len(wire)) + wire)
            await writer.drain()
    finally:
        writer.close()


class FakeSocksProxy:
    """A SOCKS5 proxy that does not connect out: it serves DNS-over-TCP itself for the
    nameserver hostnames it knows (hostname -> zones that nameserver is authoritative for)."""

    def __init__(self, servers: Dict[str, Sequence[SignedZone]]):
        self.servers = servers
        self.connects: List[Tuple[str, int, Optional[str]]] = []  # (host, port, socks username)
        self.fault: Optional[Fault] = None
        self._server = None

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, '127.0.0.1', 0)
        return self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            ver, nmethods = await reader.readexactly(2)
            methods = await reader.readexactly(nmethods)
            username = None
            if 2 in methods:  # username/password, RFC 1929
                writer.write(b'\x05\x02')
                _ver, ulen = await reader.readexactly(2)
                username = (await reader.readexactly(ulen)).decode()
                plen, = await reader.readexactly(1)
                await reader.readexactly(plen)
                writer.write(b'\x01\x00')
            else:
                writer.write(b'\x05\x00')
            _ver, _cmd, _rsv, atyp = await reader.readexactly(4)
            if atyp == 3:
                length, = await reader.readexactly(1)
                host = (await reader.readexactly(length)).decode()
            else:
                assert atyp == 1, atyp
                host = socket.inet_ntoa(await reader.readexactly(4))
            port, = struct.unpack('!H', await reader.readexactly(2))
            self.connects.append((host, port, username))
            if host not in self.servers or (self.fault and self.fault.mode == 'unreachable' and self.fault.applies(host)):
                writer.write(b'\x05\x04\x00\x01' + bytes(6))  # host unreachable
                writer.close()
                return
            writer.write(b'\x05\x00\x00\x01' + bytes(6))
            fault = self.fault if self.fault and self.fault.mode != 'unreachable' else None
            await serve_dns(reader, writer, self.servers[host], host, fault)
        except (asyncio.IncompleteReadError, ConnectionError):
            writer.close()


def fake_network(proxy_port: Optional[int], *, is_proxy_tor: bool = False) -> SimpleNamespace:
    proxy = ProxySettings.from_dict({'enabled': True, 'mode': 'socks5', 'host': '127.0.0.1', 'port': str(proxy_port)})
    return SimpleNamespace(proxy=proxy, is_proxy_tor=is_proxy_tor)


class TestDnssecQuery(ElectrumTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.root, self.org, self.example = build_hierarchy()
        self.socks = FakeSocksProxy(self._servers(self.root, self.org, self.example))
        port = await self.socks.start()
        self.addAsyncCleanup(self.socks.stop)
        self._patch(dnssec, 'trust_anchors', [dns.rrset.from_rdata(dns.name.root, 3600, self.root.dnskey)])
        self.network = fake_network(port)
        self._patch(Network, 'get_instance', lambda: self.network)
        # a recursive resolver, standing in for the one used without a proxy
        self.direct_connections = []

        async def handle(reader, writer):
            self.direct_connections.append(writer)
            await serve_dns(reader, writer, [self.root, self.org, self.example], 'resolver', None)

        resolver = await asyncio.start_server(handle, '127.0.0.1', 0)
        self.addAsyncCleanup(resolver.wait_closed)
        self.addCleanup(resolver.close)
        self._patch(dnssec, 'DIRECT_NAMESERVER', ('127.0.0.1', resolver.sockets[0].getsockname()[1]))

    def _patch(self, target, attribute, value):
        patcher = mock.patch.object(target, attribute, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def _servers(*zones: SignedZone) -> Dict[str, List[SignedZone]]:
        servers = {}
        for zone in zones:
            for ns in zone.nameservers:
                servers.setdefault(ns, []).append(zone)
        return servers

    def assert_alias_record(self, records):
        self.assertEqual([OPENALIAS_TXT], [rdata.to_text() for rdata in records])

    async def test_proxied_lookup_validates_via_root_tld_and_authoritative_servers(self):
        records, validated = await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertTrue(validated)
        self.assert_alias_record(records)
        contacted = {host for host, port, _user in self.socks.connects}
        self.assertTrue(contacted & set(self.root.nameservers))
        self.assertTrue(contacted & set(self.org.nameservers))
        self.assertTrue(contacted & set(self.example.nameservers))
        self.assertEqual({53}, {port for _host, port, _user in self.socks.connects})
        self.assertEqual([], self.direct_connections)

    async def test_proxied_lookup_works_with_nameservers_answering_once_per_connection(self):
        self._patch(dnssec, 'QUERY_TIMEOUT_PROXIED', 0.5)
        self.socks.fault = fault = Fault(hosts=set(self.socks.servers), mode='answer_once', times=None)
        records, validated = await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertTrue(validated)
        self.assert_alias_record(records)
        self.assertEqual(0, fault.triggered)  # never sent a second query on a connection

    async def test_proxied_lookup_avoids_nameserver_that_failed(self):
        self._patch(dnssec, 'QUERY_TIMEOUT_PROXIED', 0.5)
        self._patch(dnssec.random, 'sample', lambda population, k: sorted(population)[:k])  # a0 before b0
        self.socks.fault = fault = Fault(hosts={'a0.org-servers.test'}, mode='hang', times=None)
        records, validated = await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertTrue(validated)
        # 3 queries go to the org. nameservers: org. DNSKEY, example.org. NS and DS
        self.assertEqual(1, fault.triggered)

    async def test_proxied_lookup_survives_misbehaving_nameserver(self):
        self._patch(dnssec, 'QUERY_TIMEOUT_PROXIED', 0.5)
        for mode in ('unreachable', 'refused', 'servfail', 'hang', 'bogus_referral', 'mismatched_response', 'garbage'):
            with self.subTest(mode=mode):
                # the first org. nameserver we talk to misbehaves once
                self.socks.fault = fault = Fault(hosts=set(self.org.nameservers), mode=mode)
                records, validated = await dnssec.query('alias.example.org', dns.rdatatype.TXT)
                self.assertEqual(1, fault.triggered)
                self.assertTrue(validated)
                self.assert_alias_record(records)

    async def test_proxied_unvalidated_fallback_goes_through_proxy(self):
        name = dns.name.from_text('alias.example.org.')
        forged = dns.rrset.from_text(name, 3600, 'IN', 'TXT', '"oa1:btc recipient_address=bc1qforged;"')
        self.example.rrsets[(name, dns.rdatatype.TXT)] = forged  # keeps the signature of the original
        records, validated = await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertFalse(validated)
        self.assertEqual([forged[0].to_text()], [rdata.to_text() for rdata in records])
        self.assertEqual([], self.direct_connections)

    async def test_proxied_lookup_raises_dnsexception_if_proxy_unreachable(self):
        server = await asyncio.start_server(lambda reader, writer: None, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        server.close()
        await server.wait_closed()  # nothing listens on `port` anymore
        self.network = fake_network(port)
        with self.assertRaises(dns.exception.DNSException):
            await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertEqual([], self.direct_connections)  # no fallback to unproxied DNS

    async def test_proxied_lookup_gives_up_after_deadline(self):
        self._patch(dnssec, 'LOOKUP_TIMEOUT', 0.5)
        self.socks.fault = Fault(hosts=set(self.root.nameservers), mode='hang', times=None)
        start = time.monotonic()
        with self.assertRaises(dns.exception.DNSException):
            await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertLess(time.monotonic() - start, 5)

    async def test_tor_lookup_uses_one_circuit_per_lookup(self):
        self.network.is_proxy_tor = True
        await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        first = {user for _host, _port, user in self.socks.connects}
        self.socks.connects.clear()
        await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        second = {user for _host, _port, user in self.socks.connects}
        # Tor isolates streams by SOCKS credentials: same credentials within a lookup, new ones per lookup
        self.assertEqual(1, len(first))
        self.assertEqual(1, len(second))
        self.assertNotEqual(first, second)
        self.assertIsNotNone(first.pop())

    async def test_direct_lookup_without_proxy(self):
        self.network = None
        records, validated = await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertTrue(validated)
        self.assert_alias_record(records)
        self.assertEqual([], self.socks.connects)
        self.assertTrue(self.direct_connections)

    async def test_direct_lookup_raises_dnsexception_if_nameserver_unreachable(self):
        server = await asyncio.start_server(lambda reader, writer: None, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        server.close()
        await server.wait_closed()
        self._patch(dnssec, 'DIRECT_NAMESERVER', ('127.0.0.1', port))
        self.network = None
        with self.assertRaises(dns.exception.DNSException):
            await dnssec.query('alias.example.org', dns.rdatatype.TXT)
