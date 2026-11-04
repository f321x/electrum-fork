import asyncio
import dataclasses
import datetime
import ipaddress
import os
import socket
import ssl
import struct
import time
from types import SimpleNamespace
from typing import Dict, List, Optional, Sequence, Tuple
from unittest import mock

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from electrum import dnssec
from electrum.network import Network, ProxySettings

from . import ElectrumTestCase


OPENALIAS_TXT = '"oa1:btc recipient_address=bc1qtest; recipient_name=Alice;"'
RESOLVER_1 = ('192.0.2.1', 853)
RESOLVER_2 = ('192.0.2.2', 853)


class SignedZone:
    """A DNSSEC-signed zone with a single (combined signing) key."""

    def __init__(self, origin: str):
        self.origin = dns.name.from_text(origin)
        self._key = ed25519.Ed25519PrivateKey.generate()
        self.dnskey = dns.dnssec.make_dnskey(self._key.public_key(), dns.dnssec.Algorithm.ED25519, flags=257)
        self.rrsets: Dict[Tuple[dns.name.Name, int], dns.rrset.RRset] = {}
        self.sigs: Dict[Tuple[dns.name.Name, int], dns.rrset.RRset] = {}
        suffix = '' if origin == '.' else origin
        self.add(origin, 'SOA', f'ns.{suffix} hostmaster.{suffix} 1 7200 3600 1209600 3600')
        self.add(origin, 'NS', f'ns.{suffix}')
        self.add_rrset(dns.rrset.from_rdata(self.origin, 3600, self.dnskey))

    def add(self, name: str, rdtype: str, *rdatas: str) -> None:
        self.add_rrset(dns.rrset.from_text_list(dns.name.from_text(name), 3600, 'IN', rdtype, list(rdatas)))

    def add_rrset(self, rrset: dns.rrset.RRset) -> None:
        key = (rrset.name, rrset.rdtype)
        self.rrsets[key] = rrset
        sig = dns.dnssec.sign(rrset, self._key, self.origin, self.dnskey, lifetime=3600)
        self.sigs[key] = dns.rrset.from_rdata(rrset.name, rrset.ttl, sig)

    def delegate(self, child: 'SignedZone') -> None:
        ds = dns.dnssec.make_ds(child.origin, child.dnskey, 'SHA256')
        self.add_rrset(dns.rrset.from_rdata(child.origin, 3600, ds))


def build_hierarchy() -> List[SignedZone]:
    """. -> org. -> example.org. with an OpenAlias TXT record at alias.example.org."""
    root, org, example = SignedZone('.'), SignedZone('org.'), SignedZone('example.org.')
    example.add('alias.example.org.', 'TXT', OPENALIAS_TXT)
    root.delegate(org)
    org.delegate(example)
    return [root, org, example]


def respond(zones: Sequence[SignedZone], q: dns.message.Message) -> dns.message.Message:
    """Answer `q` like a recursive resolver that knows `zones` (no NSEC records)."""
    qname, qtype = q.question[0].name, q.question[0].rdtype
    resp = dns.message.make_response(q)
    # DS records are served by the parent zone
    zone = max((z for z in zones if qname.is_subdomain(z.origin)
                and not (qtype == dns.rdatatype.DS and qname == z.origin)), key=lambda z: len(z.origin))

    def add(section: List[dns.rrset.RRset], key) -> None:
        section.append(zone.rrsets[key])
        if q.ednsflags & dns.flags.DO:
            section.append(zone.sigs[key])

    if (qname, qtype) in zone.rrsets:
        add(resp.answer, (qname, qtype))
        return resp
    if not any(name.is_subdomain(qname) for name, _ in zone.rrsets):
        resp.set_rcode(dns.rcode.NXDOMAIN)
    add(resp.authority, (zone.origin, dns.rdatatype.SOA))
    return resp


def make_certificate_authority(directory: str, name: str):
    """Returns the CA certificate file, and an SSLContext for a server with a certificate
    of that CA, valid for 127.0.0.1 and the RESOLVER_* addresses."""
    def build(subject, issuer, public_key, signing_key, *, ca: bool):
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
                   .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
                   .public_key(public_key)
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(hours=1))
                   .not_valid_after(now + datetime.timedelta(hours=1))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()),
                                  critical=False))
        if ca:
            builder = builder.add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
        else:
            ips = ['127.0.0.1', RESOLVER_1[0], RESOLVER_2[0]]
            builder = builder.add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]), critical=False)
        return builder.sign(signing_key, hashes.SHA256())

    ca_key, server_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_cert = build(name, name, ca_key.public_key(), ca_key, ca=True)
    server_cert = build('resolver', name, server_key.public_key(), ca_key, ca=False)
    pem = lambda cert: cert.public_bytes(serialization.Encoding.PEM)
    ca_file = os.path.join(directory, f'{name}-ca.pem')
    chain_file = os.path.join(directory, f'{name}-server.pem')
    with open(ca_file, 'wb') as f:
        f.write(pem(ca_cert))
    with open(chain_file, 'wb') as f:
        f.write(pem(server_cert) + server_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_context.load_cert_chain(chain_file)
    return ca_file, server_context


@dataclasses.dataclass
class Fault:
    mode: str  # refused, hang, garbage, mismatched_response, close_after_answer
    times: Optional[int] = None  # None: forever
    triggered: int = 0

    def applies(self) -> bool:
        if self.times is not None and self.triggered >= self.times:
            return False
        self.triggered += 1
        return True


class FakeResolver:
    """A DNS-over-TLS resolver for `zones`."""

    def __init__(self, zones: Sequence[SignedZone], ssl_context: ssl.SSLContext):
        self.zones = zones
        self.ssl_context = ssl_context
        self.connections = 0
        self.query_sizes: List[int] = []
        self.fault: Optional[Fault] = None
        self._server = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, '127.0.0.1', 0, ssl=self.ssl_context)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            while True:
                try:
                    length, = struct.unpack('!H', await reader.readexactly(2))
                    q = dns.message.from_wire(await reader.readexactly(length))
                except asyncio.IncompleteReadError:
                    return
                self.query_sizes.append(length)
                mode = self.fault.mode if self.fault and self.fault.applies() else None
                if mode == 'hang':
                    await reader.read()  # until the client gives up
                    return
                if mode == 'garbage':
                    wire = b'\x00\x01garbage'
                else:
                    resp = respond(self.zones, q)
                    if mode == 'refused':
                        resp = dns.message.make_response(q)
                        resp.set_rcode(dns.rcode.REFUSED)
                    elif mode == 'mismatched_response':  # like a late response to an earlier query
                        resp = respond(self.zones, dns.message.make_query(q.question[0].name, 'SOA', want_dnssec=True))
                    wire = resp.to_wire()
                writer.write(struct.pack('!H', len(wire)) + wire)
                await writer.drain()
                if mode == 'close_after_answer':
                    return
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


class FakeSocksProxy:
    """A SOCKS5 proxy that forwards connections to the addresses in `routes` to local ports."""

    def __init__(self, routes: Dict[Tuple[str, int], int]):
        self.routes = routes
        self.connects: List[Tuple[str, int, Optional[str]]] = []  # (host, port, socks username)
        self._server = None

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, '127.0.0.1', 0)
        return self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            _ver, nmethods = await reader.readexactly(2)
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
            if (host, port) not in self.routes:
                writer.write(b'\x05\x04\x00\x01' + bytes(6))  # host unreachable
                writer.close()
                return
            upstream_reader, upstream_writer = await asyncio.open_connection('127.0.0.1', self.routes[(host, port)])
            writer.write(b'\x05\x00\x00\x01' + bytes(6))
            await asyncio.gather(_pipe(reader, upstream_writer), _pipe(upstream_reader, writer))
        except (asyncio.IncompleteReadError, ConnectionError):
            writer.close()


def fake_network(proxy_port: int, *, is_proxy_tor: bool = False) -> SimpleNamespace:
    proxy = ProxySettings.from_dict({'enabled': True, 'mode': 'socks5', 'host': '127.0.0.1', 'port': str(proxy_port)})
    return SimpleNamespace(proxy=proxy, is_proxy_tor=is_proxy_tor)


async def closed_port() -> int:
    server = await asyncio.start_server(lambda reader, writer: None, '127.0.0.1', 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    return port


class TestDnssecQuery(ElectrumTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.zones = build_hierarchy()
        ca_file, self.server_context = make_certificate_authority(self.electrum_path, 'test')
        self._patch(dnssec, 'ca_path', ca_file)
        self._patch(dnssec, 'trust_anchors', [dns.rrset.from_rdata(dns.name.root, 3600, self.zones[0].dnskey)])
        self.resolver1 = await self._start_resolver(self.server_context)
        self.resolver2 = await self._start_resolver(self.server_context)
        self._patch(dnssec, 'RESOLVERS', [RESOLVER_1, RESOLVER_2])
        self.socks = FakeSocksProxy({RESOLVER_1: self.resolver1.port, RESOLVER_2: self.resolver2.port})
        proxy_port = await self.socks.start()
        self.addAsyncCleanup(self.socks.stop)
        self.network = fake_network(proxy_port)
        self._patch(Network, 'get_instance', lambda: self.network)

    async def _start_resolver(self, ssl_context: ssl.SSLContext) -> FakeResolver:
        resolver = FakeResolver(self.zones, ssl_context)
        await resolver.start()
        self.addAsyncCleanup(resolver.stop)
        return resolver

    def _patch(self, target, attribute, value):
        patcher = mock.patch.object(target, attribute, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def assert_alias_record(self, records):
        self.assertEqual([OPENALIAS_TXT], [rdata.to_text() for rdata in records])

    async def test_proxied_lookup_goes_over_tls_through_proxy(self):
        records, validated = await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertTrue(validated)
        self.assert_alias_record(records)
        self.assertEqual([(*RESOLVER_1, None)], self.socks.connects)
        self.assertEqual(0, self.resolver2.connections)

    async def test_lookup_uses_one_connection(self):
        await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        # root DNSKEY, then NS, DNSKEY and DS for org. and example.org., NS and TXT for the alias
        self.assertEqual(9, len(self.resolver1.query_sizes))
        self.assertEqual(1, self.resolver1.connections)

    async def test_queries_are_padded(self):
        await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertTrue(self.resolver1.query_sizes)
        self.assertEqual({0}, {size % 128 for size in self.resolver1.query_sizes}, self.resolver1.query_sizes)

    async def test_lookup_reconnects_when_resolver_closed_connection(self):
        self._patch(dnssec, 'RESOLVERS', [RESOLVER_1])  # no other resolver to switch to
        self.resolver1.fault = Fault('close_after_answer')
        records, validated = await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertTrue(validated)
        self.assert_alias_record(records)
        self.assertEqual(9, self.resolver1.connections)

    async def test_lookup_switches_to_next_resolver_if_one_fails(self):
        self._patch(dnssec, 'QUERY_TIMEOUT_PROXIED', 0.5)
        rogue = await self._start_resolver(make_certificate_authority(self.electrum_path, 'rogue')[1])
        for mode in ('unreachable', 'untrusted_certificate', 'refused', 'hang', 'garbage', 'mismatched_response'):
            with self.subTest(mode=mode):
                self.socks.connects.clear()
                self.resolver1.fault = None
                self.resolver2.query_sizes.clear()
                self.socks.routes[RESOLVER_1] = self.resolver1.port
                if mode == 'unreachable':
                    del self.socks.routes[RESOLVER_1]
                elif mode == 'untrusted_certificate':  # e.g. a Tor exit intercepting the connection
                    self.socks.routes[RESOLVER_1] = rogue.port
                else:
                    self.resolver1.fault = Fault(mode)
                records, validated = await dnssec.query('alias.example.org', dns.rdatatype.TXT)
                self.assertTrue(validated)
                self.assert_alias_record(records)
                self.assertTrue(self.resolver2.query_sizes)
                # a failed resolver is not tried again for the next queries of the lookup
                self.assertEqual(1, sum(1 for host, port, _ in self.socks.connects if (host, port) == RESOLVER_1))
        self.assertEqual([], rogue.query_sizes)

    async def test_unvalidated_fallback_uses_the_same_resolver(self):
        example = self.zones[2]
        name = dns.name.from_text('alias.example.org.')
        forged = dns.rrset.from_text(name, 3600, 'IN', 'TXT', '"oa1:btc recipient_address=bc1qforged;"')
        example.rrsets[(name, dns.rdatatype.TXT)] = forged  # keeps the signature of the original
        records, validated = await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertFalse(validated)
        self.assertEqual([forged[0].to_text()], [rdata.to_text() for rdata in records])
        self.assertEqual(1, self.resolver1.connections)

    async def test_proxied_lookup_raises_dnsexception_if_proxy_unreachable(self):
        self.network = fake_network(await closed_port())
        with self.assertRaises(dns.exception.DNSException):
            await dnssec.query('alias.example.org', dns.rdatatype.TXT)

    async def test_lookup_gives_up_after_deadline(self):
        self._patch(dnssec, 'LOOKUP_TIMEOUT', 0.5)
        self.resolver1.fault = Fault('hang')
        self.resolver2.fault = Fault('hang')
        start = time.monotonic()
        with self.assertRaises(dns.exception.DNSException):
            await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(1, self.resolver1.fault.triggered)

    async def test_tor_lookup_uses_one_circuit_per_lookup(self):
        self.network.is_proxy_tor = True
        del self.socks.routes[RESOLVER_1]  # so that each lookup makes two connections
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
        self._patch(dnssec, 'RESOLVERS', [('127.0.0.1', self.resolver1.port)])
        records, validated = await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertTrue(validated)
        self.assert_alias_record(records)
        self.assertEqual([], self.socks.connects)
        self.assertEqual(1, self.resolver1.connections)

    async def test_direct_lookup_switches_to_next_resolver_if_one_is_unreachable(self):
        self.network = None
        self._patch(dnssec, 'RESOLVERS', [('127.0.0.1', await closed_port()), ('127.0.0.1', self.resolver1.port)])
        records, validated = await dnssec.query('alias.example.org', dns.rdatatype.TXT)
        self.assertTrue(validated)
        self.assert_alias_record(records)
