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
import functools
import logging
import random
import secrets
import struct

import aiorpcx
import dns
import dns.name
import dns.dnssec
import dns.exception
import dns.flags
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
from .util import ESocksProxy, wait_for2
from typing import Awaitable, Callable, Dict, List, Optional, Set, Tuple


_logger = get_logger(__name__)


# hard-coded trust anchors (root KSKs)
trust_anchors = [
    # KSK-2024 (key tag 38696). Signs the root DNSKEY RRset from 2026-10-11 (root KSK rollover).
    # https://data.iana.org/root-anchors/root-anchors.xml
    dns.rrset.from_text('.', 1    , 'IN', 'DNSKEY', '257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc='),
    # KSK-2017:
    dns.rrset.from_text('.', 1    , 'IN', 'DNSKEY', '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU='),
]

# root server hostnames (https://www.iana.org/domains/root/servers)
ROOT_SERVERS = [f'{letter}.root-servers.net' for letter in 'abcdefghijklm']

# without a proxy, we ask a recursive resolver. 8.8.8.8 is Google's public DNS server
DIRECT_NAMESERVER = ('8.8.8.8', 53)

QUERY_TIMEOUT_DIRECT = 5
# Tor only retries a stream on another circuit after 10 seconds
QUERY_TIMEOUT_PROXIED = 15
# for a whole lookup, including the unvalidated fallback
LOOKUP_TIMEOUT = 60
# nameservers of a zone to try before giving up on a query
MAX_NAMESERVER_ATTEMPTS = 3
MAX_REFERRALS = 16

_NETWORK_ERRORS = (OSError, EOFError, asyncio.TimeoutError, aiorpcx.socks.SOCKSError, dns.exception.DNSException)


async def _query_over_tcp(
        open_connection: Callable[[], Awaitable[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]],
        q: dns.message.Message,
        *,
        timeout: float,
) -> dns.message.Message:
    """Sends a DNS query on a new TCP connection (RFC 7766 framing). One query per connection,
    as some nameservers (e.g. Cloudflare's) ignore any further queries on a connection."""
    async def roundtrip() -> dns.message.Message:
        reader, writer = await open_connection()
        try:
            wire = q.to_wire()
            writer.write(struct.pack('!H', len(wire)) + wire)
            await writer.drain()
            length, = struct.unpack('!H', await reader.readexactly(2))
            return dns.message.from_wire(await reader.readexactly(length))
        finally:
            writer.close()

    response = await wait_for2(roundtrip(), timeout)
    if not q.is_response(response):
        raise dns.exception.DNSException('response does not match the query')
    return response


class _Transport:
    async def send(self, q: dns.message.Message) -> dns.message.Message:
        """Raises DNSException on failure."""
        raise NotImplementedError()


class _DirectTransport(_Transport):
    """Asks a recursive resolver. Used without proxy."""

    def __init__(self, nameserver: Tuple[str, int]):
        self._host, self._port = nameserver

    async def send(self, q):
        try:
            return await _query_over_tcp(
                functools.partial(asyncio.open_connection, self._host, self._port), q, timeout=QUERY_TIMEOUT_DIRECT)
        except _NETWORK_ERRORS as e:
            raise dns.exception.DNSException(f'nameserver {self._host} failed: {e!r}') from e


class _IterativeTransport(_Transport):
    """Resolves like a recursive resolver would: starting at the root servers, following
    referrals down to the zone's own nameservers. So there is no third-party resolver that
    sees all our queries. Connections go through the proxy, which also resolves the
    nameserver hostnames. Answers are authenticated by DNSSEC, not by where they come from."""

    def __init__(self, proxy: ESocksProxy):
        self._proxy = proxy
        # zone cuts we know about, and their nameservers
        self._zones: Dict[dns.name.Name, List[str]] = {dns.name.root: list(ROOT_SERVERS)}
        self._failed_nameservers: Set[str] = set()

    async def send(self, q):
        qname, qtype = q.question[0].name, q.question[0].rdtype
        # start at the closest zone we know. DS records are served by the parent zone
        zone = max((z for z in self._zones if qname.is_subdomain(z)
                    and not (qtype == dns.rdatatype.DS and z == qname)), key=len)
        for _ in range(MAX_REFERRALS):
            response, delegation = await self._query_zone(zone, q)
            if delegation is None:
                return response
            zone = delegation.name
            self._zones[zone] = [ns.target.to_text(omit_final_dot=True) for ns in delegation]
            if zone == qname and qtype in (dns.rdatatype.NS, dns.rdatatype.DS):
                # for NS, the referral is the answer: there is a zone cut at qname.
                # for DS, the parent should have answered. let the validation fail
                return response
        raise dns.exception.DNSException(f'too many referrals for {qname}')

    async def _query_zone(
            self, zone: dns.name.Name, q: dns.message.Message,
    ) -> Tuple[dns.message.Message, Optional[dns.rrset.RRset]]:
        """Asks the nameservers of `zone` until one answers, or refers us further down
        towards the queried name. Returns the response, and the NS rrset of a referral."""
        qname = q.question[0].name
        nameservers = random.sample(self._zones[zone], len(self._zones[zone]))
        nameservers.sort(key=lambda ns: ns in self._failed_nameservers)  # stable sort, failed ones last
        errors = []
        for ns in nameservers[:MAX_NAMESERVER_ATTEMPTS]:
            try:
                response = await _query_over_tcp(
                    functools.partial(self._proxy.open_connection, ns, 53), q, timeout=QUERY_TIMEOUT_PROXIED)
            except _NETWORK_ERRORS as e:
                error = repr(e)
            else:
                if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                    error = dns.rcode.to_text(response.rcode())
                elif response.answer or response.flags & dns.flags.AA:
                    return response, None
                else:
                    delegation = next((rrset for rrset in response.authority if rrset.rdtype == dns.rdatatype.NS), None)
                    if (delegation is not None and delegation.name != zone
                            and delegation.name.is_subdomain(zone) and qname.is_subdomain(delegation.name)):
                        return response, delegation
                    error = 'neither an answer nor a referral'
            errors.append(f'{ns}: {error}')
            self._failed_nameservers.add(ns)
        raise dns.exception.DNSException(f'nameservers of {zone} failed: {errors}')


def _make_transport() -> _Transport:
    from .network import Network
    proxy = ESocksProxy.from_network_settings(Network.get_instance())
    if proxy is None:
        return _DirectTransport(DIRECT_NAMESERVER)
    if isinstance(proxy.auth, aiorpcx.socks.SOCKSRandomAuth):
        # Tor would build a new circuit for each connection. Use one circuit for the
        # whole lookup instead, still separate from our other traffic.
        proxy.auth = aiorpcx.socks.SOCKSUserAuth(secrets.token_hex(16), secrets.token_hex(16))
    return _IterativeTransport(proxy)


async def _query_signed(transport: _Transport, sub, _type) -> Tuple[dns.rrset.RRset, dns.rrset.RRset]:
    """Returns the (not yet validated) rrset and its rrsig."""
    name = dns.name.from_text(sub)
    q = dns.message.make_query(name, _type, want_dnssec=True)
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


async def _check_query(transport: _Transport, sub, _type, keys) -> dns.rrset.RRset:
    rrset, rrsig = await _query_signed(transport, sub, _type)
    dns.dnssec.validate(rrset, rrsig, keys)
    return rrset


async def _get_and_validate(transport: _Transport, url, _type) -> dns.rrset.RRset:
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
        query = dns.message.make_query(sub, dns.rdatatype.NS)
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


async def _resolve_unvalidated(transport: _Transport, url, rtype) -> dns.rrset.RRset:
    name = dns.name.from_text(url)
    response = await transport.send(dns.message.make_query(name, rtype))
    rrset = response.get_rrset(response.answer, name, dns.rdataclass.IN, rtype)
    if rrset is None:
        raise dns.exception.DNSException(
            f'no {dns.rdatatype.to_text(rtype)} record for {url!r}: {dns.rcode.to_text(response.rcode())}')
    return rrset


async def _query(transport: _Transport, url: str, rtype) -> Tuple[dns.rrset.RRset, bool]:
    try:
        out = await _get_and_validate(transport, url, rtype)
        validated = True
    except Exception as e:
        log_level = logging.WARNING if isinstance(e, ImportError) else logging.INFO
        _logger.log(log_level, f"DNSSEC error: {repr(e)}")
        # same transport, so a proxied lookup does not leak to the system resolver
        out = await _resolve_unvalidated(transport, url, rtype)
        validated = False
    return out, validated


async def query(url: str, rtype: dns.rdatatype.RdataType) -> Tuple[dns.rrset.RRset, bool]:
    """Try to do DNS resolution, including DNSSEC.
    'validated' shows whether the DNSSEC checks passed. DNS is completely INSECURE without DNSSEC,
    so the caller must carefully consider whether the response can be used for anything if validated=False.

    Without a proxy, we ask DIRECT_NAMESERVER. With a proxy, we resolve iteratively, over TCP
    through the proxy: a SOCKS proxy cannot carry UDP, and Tor's RESOLVE extension only does
    A/AAAA/PTR records (see https://spec.torproject.org/socks-extensions.html).
    """
    try:
        return await wait_for2(_query(_make_transport(), url, rtype), LOOKUP_TIMEOUT)
    except asyncio.TimeoutError as e:
        raise dns.exception.Timeout(timeout=LOOKUP_TIMEOUT) from e
