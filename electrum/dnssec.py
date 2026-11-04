#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Check DNSSEC trust chain.
#
# Based on
#  http://backreference.org/2010/11/17/dnssec-verification-with-dig/
#  https://github.com/rthalley/dnspython/blob/master/tests/test_dnssec.py

import asyncio
import logging
import secrets
import ssl
import struct

import aiorpcx
import dns
import dns.name
import dns.dnssec
import dns.exception
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.NS
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.DLV
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.rdtypes.ANY.NSEC
import dns.rdtypes.ANY.NSEC3
import dns.rdtypes.ANY.NSEC3PARAM
import dns.rdtypes.ANY.RRSIG
import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.TXT
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA

from .logging import get_logger
from .util import ESocksProxy, ca_path, wait_for2
from typing import Optional, Tuple


_logger = get_logger(__name__)


# hard-coded trust anchors (root KSKs)
trust_anchors = [
    # KSK-2024 (key tag 38696). Signs the root DNSKEY RRset from 2026-10-11 (root KSK rollover).
    # https://data.iana.org/root-anchors/root-anchors.xml
    dns.rrset.from_text('.', 1    , 'IN', 'DNSKEY', '257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc='),
    # KSK-2017:
    dns.rrset.from_text('.', 1    , 'IN', 'DNSKEY', '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU='),
]

# DNS-over-TLS resolvers (RFC 7858): Google, Quad9, Cloudflare.
# We connect to their IP addresses, which their certificates are valid for.
RESOLVERS = [('8.8.8.8', 853), ('9.9.9.9', 853), ('1.1.1.1', 853)]

QUERY_TIMEOUT_DIRECT = 5
# Tor only retries a stream on another circuit after 10 seconds
QUERY_TIMEOUT_PROXIED = 15
# for a whole lookup, including the unvalidated fallback
LOOKUP_TIMEOUT = 60
# queries are padded to a multiple of this (RFC 8467), so that their size reveals less about the name
QUERY_PADDING = 128

_NETWORK_ERRORS = (OSError, EOFError, asyncio.TimeoutError, aiorpcx.socks.SOCKSError, dns.exception.DNSException)


class _TLSTransport:
    """Sends DNS queries over TLS (RFC 7858) to the first of RESOLVERS that works, through the
    proxy if there is one. All queries of a lookup go over one connection. Not for concurrent use."""

    def __init__(self, proxy: Optional[ESocksProxy]):
        self._proxy = proxy
        self._timeout = QUERY_TIMEOUT_PROXIED if proxy else QUERY_TIMEOUT_DIRECT
        self._resolvers = list(RESOLVERS)
        self._connection: Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = None
        self._ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)

    async def send(self, q: dns.message.Message) -> dns.message.Message:
        """Raises DNSException if no resolver answers."""
        errors = []
        while self._resolvers:
            host, port = self._resolvers[0]
            try:
                response = await self._query(host, port, q)
            except _NETWORK_ERRORS as e:
                errors.append(f'{host}: {e!r}')
            else:
                if response.rcode() != dns.rcode.REFUSED:
                    return response
                errors.append(f'{host}: REFUSED')
            # don't use this resolver again for the rest of the lookup
            self.close()
            self._resolvers.pop(0)
        raise dns.exception.DNSException(f'no resolver answered: {errors}')

    async def _query(self, host: str, port: int, q: dns.message.Message) -> dns.message.Message:
        reused = self._connection is not None
        try:
            return await self._exchange(host, port, q)
        except _NETWORK_ERRORS:
            if not reused:
                raise
        # the resolver might have closed the connection since the last query, try once more on a new one
        return await self._exchange(host, port, q)

    async def _exchange(self, host: str, port: int, q: dns.message.Message) -> dns.message.Message:
        if self._connection is None:
            self._connection = await wait_for2(self._open_connection(host, port), self._timeout)
        reader, writer = self._connection

        async def roundtrip() -> dns.message.Message:
            wire = q.to_wire()
            writer.write(struct.pack('!H', len(wire)) + wire)
            await writer.drain()
            length, = struct.unpack('!H', await reader.readexactly(2))
            return dns.message.from_wire(await reader.readexactly(length))

        try:
            response = await wait_for2(roundtrip(), self._timeout)
            if not q.is_response(response):
                raise dns.exception.DNSException('response does not match the query')
            return response
        except BaseException:
            self.close()  # we don't know where in the stream we are
            raise

    async def _open_connection(self, host: str, port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        # the certificate gets checked against `host`, an IP address
        if self._proxy:
            return await self._proxy.open_connection(host, port, ssl=self._ssl_context)
        return await asyncio.open_connection(host, port, ssl=self._ssl_context)

    def close(self) -> None:
        if self._connection is not None:
            self._connection[1].close()
            self._connection = None


def _make_transport() -> _TLSTransport:
    from .network import Network
    proxy = ESocksProxy.from_network_settings(Network.get_instance())
    if proxy is not None and isinstance(proxy.auth, aiorpcx.socks.SOCKSRandomAuth):
        # Tor would use a new circuit for each connection. Use one circuit for the
        # whole lookup instead, still separate from our other traffic.
        proxy.auth = aiorpcx.socks.SOCKSUserAuth(secrets.token_hex(16), secrets.token_hex(16))
    return _TLSTransport(proxy)


def _make_query(name, rdtype, *, want_dnssec: bool = False) -> dns.message.Message:
    return dns.message.make_query(name, rdtype, use_edns=0, want_dnssec=want_dnssec, pad=QUERY_PADDING)


async def _query_signed(transport: _TLSTransport, sub, _type) -> Tuple[dns.rrset.RRset, dns.rrset.RRset]:
    """Returns the (not yet validated) rrset and its rrsig."""
    name = dns.name.from_text(sub)
    q = _make_query(name, _type, want_dnssec=True)
    response = await transport.send(q)
    assert response.rcode() == 0, 'No answer'
    # only accept the queried name and type, otherwise any validly signed rrset of the zone could be replayed
    rrset = response.get_rrset(response.answer, name, dns.rdataclass.IN, _type)
    assert rrset is not None, ('No DNS record found', sub, _type)
    rrsig = response.get_rrset(response.answer, name, dns.rdataclass.IN, dns.rdatatype.RRSIG, _type)
    assert rrsig is not None, ('No DNSSEC record found', sub, _type)
    # reject wildcard expansions, we don't verify the NSEC(3) proof that the name itself doesn't exist
    assert all(sig.labels == len(name) - 1 for sig in rrsig), ('Wildcard DNS record not supported', sub, _type)
    return rrset, rrsig


async def _check_query(transport: _TLSTransport, sub, _type, keys) -> dns.rrset.RRset:
    rrset, rrsig = await _query_signed(transport, sub, _type)
    dns.dnssec.validate(rrset, rrsig, keys)
    return rrset


async def _get_and_validate(transport: _TLSTransport, url, _type) -> dns.rrset.RRset:
    # get trusted root key
    root_rrset = None
    for dnskey_rr in trust_anchors:
        try:
            # Check if there is a valid signature for the root dnskey
            root_rrset = await _check_query(transport, '', dns.rdatatype.DNSKEY, {dns.name.root: dnskey_rr})
            break
        except dns.dnssec.ValidationFailure:
            # It's OK as long as one key validates
            continue
    if not root_rrset:
        raise dns.dnssec.ValidationFailure('None of the trust anchors found in DNS')
    keys = {dns.name.root: root_rrset}
    # top-down verification
    sub = ''
    for label in reversed(url.split('.')):
        sub = f'{label}.{sub}'
        name = dns.name.from_text(sub)
        # If server is authoritative, don't fetch DNSKEY
        query = _make_query(sub, dns.rdatatype.NS)
        response = await transport.send(query)
        assert response.rcode() == dns.rcode.NOERROR, "query error"
        rrset = response.authority[0] if len(response.authority) > 0 else response.answer[0]
        rr = rrset[0]
        if rr.rdtype == dns.rdatatype.SOA:
            continue
        # get DNSKEY (not yet validated)
        rrset, rrsig = await _query_signed(transport, sub, dns.rdatatype.DNSKEY)
        # get DS (signed by parent)
        ds_rrset = await _check_query(transport, sub, dns.rdatatype.DS, keys)
        # find the DNSKEYs committed to by the signed DS
        ds_keys = []
        for dnskey in rrset:
            for ds in ds_rrset:
                try:
                    good_ds = dns.dnssec.make_ds(name, dnskey, ds.digest_type, validating=True)
                except (dns.dnssec.UnsupportedAlgorithm, dns.dnssec.DeniedByPolicy):
                    continue  # skip digest types we cannot verify
                if ds == good_ds:
                    ds_keys.append(dnskey)
                    break
        if not ds_keys:
            raise Exception("DS does not match DNSKEY")
        # the DNSKEY RRset must be signed by one of those keys (RFC 4035 5.2),
        # otherwise an attacker could add their own key to it and self-sign
        dns.dnssec.validate(rrset, rrsig, {name: dns.rrset.from_rdata_list(name, rrset.ttl, ds_keys)})
        # set key for next iteration
        keys = {name: rrset}
    # get TXT record (signed by zone)
    rrset = await _check_query(transport, url, _type, keys)
    return rrset


async def _resolve_unvalidated(transport: _TLSTransport, url, rtype) -> dns.rrset.RRset:
    name = dns.name.from_text(url)
    response = await transport.send(_make_query(name, rtype))
    rrset = response.get_rrset(response.answer, name, dns.rdataclass.IN, rtype)
    if rrset is None:
        raise dns.exception.DNSException(
            f'no {dns.rdatatype.to_text(rtype)} record for {url!r}: {dns.rcode.to_text(response.rcode())}')
    return rrset


async def _query(transport: _TLSTransport, url: str, rtype) -> Tuple[dns.rrset.RRset, bool]:
    try:
        out = await _get_and_validate(transport, url, rtype)
        validated = True
    except Exception as e:
        log_level = logging.WARNING if isinstance(e, ImportError) else logging.INFO
        _logger.log(log_level, f"DNSSEC error: {repr(e)}")
        # same transport, so that this does not leak to the system resolver
        out = await _resolve_unvalidated(transport, url, rtype)
        validated = False
    return out, validated


async def query(url: str, rtype: dns.rdatatype.RdataType) -> Tuple[dns.rrset.RRset, bool]:
    """Try to do DNS resolution, including DNSSEC.
    'validated' shows whether the DNSSEC checks passed. DNS is completely INSECURE without DNSSEC,
    so the caller must carefully consider whether the response can be used for anything if validated=False.

    We ask one of RESOLVERS, over TLS, through the network proxy if one is enabled: a SOCKS proxy
    cannot carry UDP, and Tor's RESOLVE extension only does A/AAAA/PTR records (see
    https://spec.torproject.org/socks-extensions.html). TLS keeps the names we look up from
    e.g. a Tor exit. The resolver sees them, but it cannot forge answers, as we check DNSSEC.
    """
    transport = _make_transport()
    try:
        return await wait_for2(_query(transport, url, rtype), LOOKUP_TIMEOUT)
    except asyncio.TimeoutError as e:
        raise dns.exception.Timeout(timeout=LOOKUP_TIMEOUT) from e
    finally:
        transport.close()
