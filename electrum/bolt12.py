# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2025 The Electrum developers
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

import attr
import copy
import io
import os
import time
from dataclasses import dataclass, field, asdict, fields
import re
from decimal import Decimal
from typing import TYPE_CHECKING, Union, Optional, Tuple, Iterable, Type, TypeVar, Any, ClassVar, Sequence
from abc import ABC, abstractmethod

import electrum_ecc as ecc

from . import constants
from .bitcoin import COIN
from .bolt11 import BOLT11Addr
from .json_db import stored_in, StoredObject
from .lnmsg import OnionWireSerializer, batched
from .lnutil import LnFeatures, validate_features, hex_to_bytes, bytes_to_hex
from .onion_message import Timeout, BlindedPath, BlindedPayInfo, BlindedPathInfo, get_blinded_paths_to_me, get_blinded_reply_paths, NoRouteBlindingChannelPeers
from .segwit_addr import (
    bech32_decode, convertbits, bech32_encode, Encoding, INVALID_BECH32,
    CHARSET as BECH32_CHARSET,
)
>>>>>>> d3138090d (bolt12: return more errors on invoice request)

if TYPE_CHECKING:
    from .lnworker import LNWallet


DEFAULT_INVOICE_EXPIRY = 7200


TBOLT12Base = TypeVar("TBOLT12Base", bound="BOLT12Base")


@dataclass(frozen=True, kw_only=True)
class BOLT12Base(ABC):
    tlv_stream_name: ClassVar[str]
    signing_key_path: ClassVar[Optional[tuple[str, ...]]]
    hrp: ClassVar[str]  # human-readable part of the bech32 encoded string
    _unknown_fields: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def decode(cls: Type[TBOLT12Base], data: str | bytes) -> TBOLT12Base:
        d = bolt12_bech32_to_bytes(data) if isinstance(data, str) else data
        with io.BytesIO(d) as fd:
            protocol_dict = OnionWireSerializer.read_tlv_stream(
                fd=fd,
                tlv_stream_name=cls.tlv_stream_name,
                signing_key_path=cls.signing_key_path,
            )
        return cls.deserialize(protocol_dict)

    def encode(self, *, signing_key: bytes = None, as_bech32: bool = False) -> str | bytes:
        if self.signing_key_path:
            # if no signing_key is passed we keep the existing signature, else a new one is created
            assert signing_key or hasattr(self, 'signature') and getattr(self, 'signature')
        else:
            assert signing_key is None, "cannot sign offer"

        data = self.serialize(with_signature=False if signing_key else True)
        with io.BytesIO() as fd:
            OnionWireSerializer.write_tlv_stream(
                fd=fd,
                tlv_stream_name=self.tlv_stream_name,
                signing_key=signing_key,
                **data,
            )
            if not as_bech32:
                return fd.getvalue()
            bech32_data = convertbits(list(fd.getvalue()), 8, 5, True)
            return bech32_encode(Encoding.BECH32, self.hrp, bech32_data, with_checksum=False)

    _ENCODE_MAP = {}
    def serialize(self, *, with_signature: bool = False) -> dict:
        protocol_dict = copy.deepcopy(self._unknown_fields)
        for f in fields(self):
            if f.name.startswith('_'):
                continue
            if f.name.endswith('_signature') and not with_signature:
                continue
            value = getattr(self, f.name)
            if value is None or value == LnFeatures(0):
                continue
            protocol_dict[f.name] = self._ENCODE_MAP[f.name](value)
        return protocol_dict

    @classmethod
    @abstractmethod
    def deserialize(cls: Type[TBOLT12Base], protocol_dict: dict) -> TBOLT12Base:
        pass

    def compare(self, *, against: 'BOLT12Base', ranges: Sequence[tuple[int, int]]) -> bool:
        """Compare fields of 'against' in the given TLV type ranges against the fields of self."""
        def in_ranges(ftype: int) -> bool:
            return any(start <= ftype <= end for start, end in ranges)

        def get_value(obj: BOLT12Base, field_name: str):
            val = getattr(obj, field_name, None)
            if val is None:
                val = obj._unknown_fields.get(field_name)
            return val

        # fetch keys to compare for the given range
        keys = filter(
            lambda item: in_ranges(item[0]),
            OnionWireSerializer.in_tlv_stream_get_record_name_from_type[against.tlv_stream_name].items()
        )
        for _type, name in keys:
            if get_value(self, name) != get_value(against, name):
                return False
        return True

    @property
    def is_expired(self) -> bool:
        now = int(time.time())
        expiry_time = None
        if type(self) == BOLT12Invoice:
            expiry_time = self.invoice_created_at + self.invoice_relative_expiry
        elif type(self) == BOLT12Offer:
            expiry_time = self.offer_absolute_expiry
        return now > expiry_time if expiry_time is not None else False


@dataclass(frozen=True, kw_only=True)
class BOLT12Offer(BOLT12Base):
    """
    https://github.com/lightning/bolts/blob/34455ffe28b308dd7ac7552234d565890af8605b/12-offer-encoding.md?plain=1#L182
    """
    tlv_stream_name = 'offer'
    signing_key_path = None  # offers are not signed
    hrp = 'lno'

    offer_features: Optional[LnFeatures] = None
    offer_chains: Optional[list[bytes]] = None
    offer_metadata: Optional[bytes] = None
    offer_currency: Optional[str] = None
    offer_amount: Optional[int] = None
    offer_description: Optional[str] = None
    offer_absolute_expiry: Optional[int] = None
    offer_paths: Optional[tuple[BlindedPath, ...]] = None
    offer_issuer: Optional[str] = None
    offer_quantity_max: Optional[int] = None
    offer_issuer_id: Optional[bytes] = None

    def __post_init__(self):
        # if the chain for the invoice is not solely bitcoin:
        # MUST specify offer_chains the offer is valid for.
        if not matches_our_chain(self.offer_chains):
            raise NoMatchingChainError()
        if self.offer_chains is not None and not self.offer_chains:
            raise ValueError('empty offer_chains')
        # if offer_features contains unknown even bits that are non-zero: MUST NOT respond to the offer
        if self.offer_features:
            validate_features(self.offer_features)
        # if offer_amount is set and offer_description is not set: MUST NOT respond to the offer
        if self.offer_amount is not None and self.offer_description is None:
            raise ValueError('missing offer_description, but has offer_amount')
        # if offer_currency is set and offer_amount is not set: MUST NOT respond to the offer
        if self.offer_currency is not None and self.offer_amount is None:
            raise ValueError('missing offer_amount, but has offer_currency')
        # if neither offer_issuer_id nor offer_paths are set: MUST NOT respond to the offer
        if not self.offer_issuer_id and not self.offer_paths:
            raise ValueError('neither offer_issuer_id nor offer_paths are given')
        if self.offer_issuer_id is not None:
            ecc.ECPubkey(b=self.offer_issuer_id)

    @classmethod
    def deserialize(cls, o: dict) -> 'BOLT12Offer':
        o = copy.deepcopy(o)
        if (offer_features := o.pop('offer_features', {}).get('features')) is not None:
            offer_features = LnFeatures(int.from_bytes(offer_features, byteorder="big", signed=False))
        if (offer_chains := o.pop('offer_chains', {}).get('chains')) is not None:
            offer_chains = [bytes(c) for c in batched(offer_chains, 32)]
        if (offer_paths := o.pop('offer_paths', {}).get('paths')) is not None:
            offer_paths = tuple(BlindedPath.from_dict(p) for p in offer_paths)

        return BOLT12Offer(
            offer_chains=offer_chains,
            offer_metadata=o.pop('offer_metadata', {}).get('data'),
            offer_currency=o.pop('offer_currency', {}).get('iso4217'),
            offer_amount=o.pop('offer_amount', {}).get('amount'),
            offer_description=o.pop('offer_description', {}).get('description'),
            offer_features=offer_features,
            offer_absolute_expiry=o.pop('offer_absolute_expiry', {}).get('seconds_from_epoch'),
            offer_paths=offer_paths,
            offer_issuer=o.pop('offer_issuer', {}).get('issuer'),
            offer_quantity_max=o.pop('offer_quantity_max', {}).get('max'),
            offer_issuer_id=o.pop('offer_issuer_id', {}).get('id'),
            _unknown_fields=o,
        )

    _ENCODE_MAP = BOLT12Base._ENCODE_MAP | {
        'offer_chains': lambda v: {'chains': b''.join(v)},
        'offer_metadata': lambda v: {'data': v},
        'offer_currency': lambda v: {'iso4217': v},
        'offer_amount': lambda v: {'amount': v},
        'offer_description': lambda v: {'description': v},
        'offer_features': lambda v: {'features': v.to_tlv_bytes()},
        'offer_absolute_expiry': lambda v: {'seconds_from_epoch': v},
        'offer_paths': lambda v: {'paths': [asdict(p) for p in v]},
        'offer_issuer': lambda v: {'issuer': v},
        'offer_quantity_max': lambda v: {'max': v},
        'offer_issuer_id': lambda v: {'id': v},
    }


@dataclass(frozen=True, kw_only=True)
class BOLT12InvoiceRequest(BOLT12Offer):
    """
    https://github.com/lightning/bolts/blob/34455ffe28b308dd7ac7552234d565890af8605b/12-offer-encoding.md?plain=1#L357
    """
    tlv_stream_name = 'invoice_request'
    signing_key_path = ('invreq_payer_id', 'key')
    hrp = 'lnr'

    invreq_metadata: bytes
    invreq_chain: Optional[bytes] = None
    invreq_amount: Optional[int] = None
    invreq_features: Optional[LnFeatures] = None
    invreq_quantity: Optional[int] = None
    invreq_payer_id: bytes
    invreq_payer_note: Optional[str] = None
    invreq_paths: Optional[tuple[BlindedPath, ...]] = None
    invreq_bip_353_name: Optional[Tuple[str, str]] = None  # name, domain
    invreq_signature: Optional[bytes] = None  # sig for incoming req is validated in OnionWireSerializer

    def __post_init__(self):
        super().__post_init__()
        # MUST reject the invoice request if invreq_payer_id or invreq_metadata are not present
        if not self.invreq_payer_id or not self.invreq_metadata:
            raise ValueError(f"{bool(self.invreq_payer_id)=} or {bool(self.invreq_metadata)=} missing")
        if self.invreq_features:
            pass
            # validate_features(self.invreq_features)
        # if offer_issuer_id or offer_paths are present (response to an offer):
        if self.offer_issuer_id or self.offer_paths:
            # if offer_quantity_max is present:
            if self.offer_quantity_max is not None:
                if self.invreq_quantity is None:
                    # MUST reject the invoice request if there is no invreq_quantity field.
                    raise ValueError("offer_quantity_max is given but no invreq_quantity")
                # if offer_quantity_max is non-zero
                if self.offer_quantity_max and self.invreq_quantity > self.offer_quantity_max:
                    # MUST reject the invoice request if invreq_quantity is zero, OR greater than offer_quantity_max
                    raise ValueError("invreq_quantity > offer_quantity_max")
            else:
                # otherwise: MUST reject the invoice request if there is an invreq_quantity field
                if self.invreq_quantity is not None:
                    raise ValueError("invreq_quantity given but no offer_quantity_max")
            # if offer_amount is present:
            if (expected_amount := self.offer_amount) is not None:
                # MUST calculate the expected amount using the offer_amount
                if self.offer_currency and self.offer_currency.upper() != 'BTC':
                    # TODO: if offer_currency is not the invreq_chain currency, convert to the invreq_chain currency
                    raise NotImplementedError("no fx conversion support yet, will this be used?")
                # if invreq_quantity is present, multiply by invreq_quantity.quantity
                if self.invreq_quantity:
                    # NOTE: not allowing self.invreq_quantity of 0 here, this seems unsafe?
                    expected_amount *= self.invreq_quantity
                # if invreq_amount is present
                if self.invreq_amount is not None:
                    # MUST reject the invoice request if invreq_amount.msat is less than the expected amount.
                    if self.invreq_amount < expected_amount:
                        raise ValueError(f"{self.invreq_amount=} < {expected_amount=}")
                    # MAY reject the invoice request if invreq_amount.msat greatly exceeds the expected amount
                    elif self.invreq_amount > int(expected_amount * 1.5):
                        raise ValueError(f"{self.invreq_amount=} > {int(expected_amount * 1.5)=}")
            # otherwise (no offer_amount):
            else:
                # MUST reject the invoice request if it does not contain invreq_amount
                if self.invreq_amount is None:
                    raise ValueError("no offer_amount and no invreq_amount")
        # otherwise (no offer_issuer_id or offer_paths, not a response to our offer):
        else:
            # MUST reject the invoice request if any of the following are present:
            if self.offer_chains is not None or self.offer_features is not None or self.offer_quantity_max is not None:
                raise ValueError("offer_chains, offer_features or offer_quantity_max present")
            # MUST reject the invoice request if invreq_amount is not present
            if self.invreq_amount is None:
                raise ValueError("invreq_amount missing")
        if not matches_our_chain([self.invreq_chain] if self.invreq_chain else None):
            raise NoMatchingChainError()
        if self.invreq_bip_353_name is not None:
            name, domain = self.invreq_bip_353_name
            if not validate_bip_353_name(name, domain):
                raise ValueError(f"invalid bip 353 name: {self.invreq_bip_353_name}")

    @classmethod
    def deserialize(cls, ir: dict) -> 'BOLT12InvoiceRequest':
        ir = copy.deepcopy(ir)
        offer = BOLT12Offer.deserialize(ir)
        d = offer._unknown_fields
        if (invreq_features := d.pop('invreq_features', {}).get('features')) is not None:
            invreq_features = LnFeatures(int.from_bytes(invreq_features, byteorder="big", signed=False))
        if (invreq_paths := d.pop('invreq_paths', {}).get('paths')) is not None:
            invreq_paths = tuple(BlindedPath.from_dict(p) for p in invreq_paths)
        if invreq_bip_353_name := d.pop('invreq_bip_353_name', None):
            name, domain = invreq_bip_353_name['name'], invreq_bip_353_name['domain']
            invreq_bip_353_name = (name, domain)

        offer_fields = {f.name: getattr(offer, f.name) for f in fields(BOLT12Offer) if not f.name.startswith('_')}

        return BOLT12InvoiceRequest(
            **offer_fields,
            invreq_metadata=d.pop('invreq_metadata', {}).get('blob'),
            invreq_chain=d.pop('invreq_chain', {}).get('chain'),
            invreq_amount=d.pop('invreq_amount', {}).get('msat'),
            invreq_features=invreq_features,
            invreq_quantity=d.pop('invreq_quantity', {}).get('quantity'),
            invreq_payer_id=d.pop('invreq_payer_id', {}).get('key'),
            invreq_payer_note=d.pop('invreq_payer_note', {}).get('note'),
            invreq_paths=invreq_paths,
            invreq_bip_353_name=invreq_bip_353_name,
            invreq_signature=d.pop('signature', {}).get('sig'),
            _unknown_fields=d,
        )

    _ENCODE_MAP = BOLT12Offer._ENCODE_MAP | {
        'invreq_metadata': lambda v: {'blob': v},
        'invreq_chain': lambda v: {'chain': v},
        'invreq_amount': lambda v: {'msat': v},
        'invreq_features': lambda v: {'features': v.to_tlv_bytes()},
        'invreq_quantity': lambda v: {'quantity': v},
        'invreq_payer_id': lambda v: {'key': v},
        'invreq_payer_note': lambda v: {'note': v},
        'invreq_paths': lambda v: {'paths': [asdict(p) for p in v]},
        'invreq_bip_353_name': lambda v: {'name': v},
        'invreq_signature': lambda v: {'sig': v},
    }


@dataclass(frozen=True, kw_only=True)
class BOLT12Invoice(BOLT12InvoiceRequest):
    tlv_stream_name = 'invoice'
    signing_key_path = ('invoice_node_id', 'node_id')
    hrp = 'lni'

    invoice_paths: tuple[BlindedPath, ...]
    invoice_blindedpay: tuple[BlindedPayInfo, ...]
    invoice_created_at: int
    invoice_relative_expiry: Optional[int] = DEFAULT_INVOICE_EXPIRY
    invoice_payment_hash: bytes
    invoice_amount: int
    invoice_fallbacks: Optional[tuple[dict]] = None
    invoice_features: Optional[LnFeatures] = None
    invoice_node_id: bytes
    invoice_signature: Optional[bytes] = None

    def __post_init__(self):
        super().__post_init__()
        # MUST reject the invoice if invoice_amount is not present
        if self.invoice_amount is None:
            raise ValueError("invoice_amount missing")
        # MUST reject the invoice if invoice_created_at is not present
        if self.invoice_created_at is None:
            raise ValueError("invoice_created_at missing")
        elif self.invoice_created_at > int(time.time()) + 10:
            raise ValueError("invoice_created_at in the future")
        # MUST reject the invoice if invoice_payment_hash is not present
        if self.invoice_payment_hash is None:
            raise ValueError("invoice_payment_hash missing")
        # MUST reject the invoice if invoice_node_id is not present
        if self.invoice_node_id is None:
            raise ValueError("invoice_node_id missing")
        if self.invoice_features:
            pass  # FIXME: validate_features raises with invoices from core lightning, is this the right approach?
            # validate_features(self.invoice_features)
        # MUST reject the invoice if invoice_paths is not present or is empty
        if not self.invoice_paths:
            raise ValueError("invoice_paths missing or empty")
        # MUST reject the invoice if invoice_blindedpay is not present.
        if self.invoice_blindedpay is None:
            raise ValueError("invoice_blindedpay missing")
        # MUST reject the invoice if invoice_blindedpay does not contain exactly one blinded_payinfo per invoice_paths.blinded_path.
        if len(self.invoice_blindedpay) != len(self.invoice_paths):
            raise ValueError("invoice_blindedpay length mismatch")
        if all(payinfo.requires_unknown_mandatory_features for payinfo in self.invoice_blindedpay):
            # MUST reject the invoice if this leaves no usable paths.
            raise ValueError("no payinfo with sane features")
        # if offer_issuer_id is present (invoice_request for an offer):
        if self.offer_issuer_id is not None:
            # MUST reject the invoice if invoice_node_id is not equal to offer_issuer_id
            if self.invoice_node_id != self.offer_issuer_id:
                raise ValueError(f"{self.offer_issuer_id.hex()=} != {self.invoice_node_id.hex()=}")
        if self.invreq_amount is not None:
            if self.invoice_amount != self.invreq_amount:
                raise ValueError("invoice_amount != invreq_amount")

    @classmethod
    def deserialize(cls, inv: dict) -> 'BOLT12Invoice':
        inv = copy.deepcopy(inv)
        invoice_signature = inv.pop('signature', {}).get('sig')
        invreq = BOLT12InvoiceRequest.deserialize(inv)
        d = invreq._unknown_fields

        if (invoice_features := d.pop('invoice_features', {}).get('features')) is not None:
            invoice_features = LnFeatures(int.from_bytes(invoice_features, byteorder="big", signed=False))
        if (invoice_paths := d.pop('invoice_paths', {}).get('paths')) is not None:
            invoice_paths = tuple(BlindedPath.from_dict(p) for p in invoice_paths)
        if (invoice_blindedpay := d.pop('invoice_blindedpay', {}).get('payinfo')) is not None:
            invoice_blindedpay = tuple(BlindedPayInfo.from_dict(p) for p in invoice_blindedpay)
        if (invoice_fallbacks := d.pop('invoice_fallbacks', {}).get('fallbacks')) is not None:
            invoice_fallbacks = tuple(invoice_fallbacks)

        parent_fields = {f.name: getattr(invreq, f.name) for f in fields(BOLT12InvoiceRequest) if not f.name.startswith('_')}

        return BOLT12Invoice(
            **parent_fields,
            invoice_paths=invoice_paths,
            invoice_blindedpay=invoice_blindedpay,
            invoice_created_at=d.pop('invoice_created_at', {}).get('timestamp'),
            invoice_relative_expiry=d.pop('invoice_relative_expiry', {}).get('seconds_from_creation', DEFAULT_INVOICE_EXPIRY),
            invoice_payment_hash=d.pop('invoice_payment_hash', {}).get('payment_hash'),
            invoice_amount=d.pop('invoice_amount', {}).get('msat'),
            invoice_fallbacks=invoice_fallbacks,
            invoice_features=invoice_features,
            invoice_node_id=d.pop('invoice_node_id', {}).get('node_id'),
            invoice_signature=invoice_signature,
            _unknown_fields=d
        )

    _ENCODE_MAP = BOLT12InvoiceRequest._ENCODE_MAP | {
        'invoice_paths': lambda v: {'paths': [asdict(p) for p in v]},
        'invoice_blindedpay': lambda v: {'payinfo': [p.to_dict() for p in v]},
        'invoice_created_at': lambda v: {'timestamp': v},
        'invoice_relative_expiry': lambda v: {'seconds_from_creation': v},
        'invoice_payment_hash': lambda v: {'payment_hash': v},
        'invoice_amount': lambda v: {'msat': v},
        'invoice_fallbacks': lambda v: {'fallbacks': list(v)},
        'invoice_features': lambda v: {'features': v.to_tlv_bytes()},
        'invoice_node_id': lambda v: {'node_id': v},
        'invoice_signature': lambda v: {'sig': v},
    }


def is_offer(data: str) -> bool:
    try:
        data = remove_bolt12_whitespace(data)
    except ValueError:
        return False
    d = bech32_decode(data, ignore_long_length=True, with_checksum=False)
    if d == INVALID_BECH32:
        return False
    return d.hrp == 'lno'


def matches_our_chain(chains: Optional[Iterable[bytes]]) -> bool:
    # chains is a 32 bytes record list stored in a single bytes object (see TODO above lnmsg._read_field)
    if not chains:
        # empty chains is indicative of only Bitcoin mainnet
        return True if constants.net == constants.BitcoinMainnet else False
    our_chain_hash = constants.net.rev_genesis_bytes()
    return our_chain_hash in chains


def bolt12_bech32_to_bytes(data: str) -> bytes:
    data = remove_bolt12_whitespace(data)
    d = bech32_decode(data, ignore_long_length=True, with_checksum=False)
    if d == INVALID_BECH32:
        raise ValueError(f"Failed to bech32 decode: {data[:64]=}...")
    d = convertbits(d.data, 5, 8, pad=False)
    if d is None:
        raise ValueError(f"Invalid bech32 data: {data[:64]=}...")
    return bytes(d)


def create_offer(
    *,
    offer_paths: Optional[Iterable[BlindedPathInfo]] = None,
    node_id: Optional[bytes] = None,
    amount_msat: Optional[int] = None,
    memo: Optional[str] = None,
    expiry: Optional[int] = None,
    issuer: Optional[str] = None,
) -> tuple[bytes, BOLT12Offer]:
    offer_id = os.urandom(16)  # todo: use hmac instead of random id?

    chains = None
    if constants.net != constants.BitcoinMainnet:
        chains = [constants.net.rev_genesis_bytes()]

    offer = BOLT12Offer(
        offer_metadata=offer_id,
        offer_issuer=issuer,
        offer_description=memo,
        offer_chains=chains,
        offer_amount=amount_msat,
        offer_absolute_expiry=int(time.time()) + expiry if expiry else None,
        # TODO: remove adding of offer_issuer_id, once we can sign invoices properly based on invreq used blinded path
        offer_issuer_id=node_id, # node_id if not offer_paths else None,
        offer_paths=tuple(p.path for p in offer_paths) if offer_paths else None,
    )
    return offer_id, offer


@stored_in('offers')
@attr.s
class Offer(StoredObject):
    offer_id = attr.ib(kw_only=True, type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)
    offer_bech32 = attr.ib(kw_only=True, type=str)


def to_lnaddr(data: BOLT12Invoice) -> BOLT11Addr:
    # FIXME: abusing BOLT11 oriented BOLT11Addr for BOLT12 fields
    net = constants.net
    addr = BOLT11Addr()

    # NOTE: CLN puts the real node_id here, which defeats the whole purpose of blinded paths
    # also, this should not be used as routing destination in payments (introduction point in set of blinded paths
    # must be used instead
    pubkey = data.invoice_node_id

    class WrappedBytesKey:
        serialize = lambda: pubkey
    addr.pubkey = WrappedBytesKey
    addr.net = net
    addr.date = data.invoice_created_at
    addr.paymenthash = data.invoice_payment_hash
    addr.payment_secret = b'\x00' * 32  # Note: payment secret is not needed, recipient can use path_id in encrypted_recipient_data
    msat = data.invoice_amount
    if msat is not None:
        addr.amount = Decimal(msat) / COIN / 1000
    fallbacks = data.invoice_fallbacks or []
    fallbacks = list(filter(lambda x: x['version'] <= 16 and 2 <= len(x['address'] <= 40), fallbacks))
    if fallbacks:
        addr.tags.append(('f', fallbacks[0]))
    exp = data.invoice_relative_expiry
    if exp:
        addr.tags.append(('x', int(exp)))
    description = data.offer_description
    if description:
        addr.tags.append(('d', description))
    return addr


async def request_invoice(
        lnwallet: 'LNWallet',
        bolt12_offer: BOLT12Offer,
        amount_msat: int,
        *,
        note: Optional[str] = None,
) -> Tuple[BOLT12Invoice, bytes]:
    # NOTE: offer_chains isn't checked here, BOLT12Offer.decode already raises on invalid chains.

    #   - if it chooses to send an `invoice_request`, it sends an onion message:
    #     - if `offer_paths` is set:
    #       - MUST send the onion message via any path in `offer_paths` to the final `onion_msg_hop`.`blinded_node_id` in that path
    #     - otherwise:
    #       - MUST send the onion message to `offer_issuer_id`
    #     - MAY send more than one `invoice_request` onion message at once.

    if paths := bolt12_offer.offer_paths:
        assert len(paths)
        node_id_or_blinded_paths = paths
    else:
        node_id_or_blinded_paths = bolt12_offer.offer_issuer_id

    # spec: MUST set invreq_payer_id to a transient public key.
    # spec: MUST remember the secret key corresponding to invreq_payer_id.
    session_key = os.urandom(32)
    blinding = ecc.ECPrivkey(session_key).get_public_key_bytes()

    if bolt12_offer.offer_amount is not None:
        assert amount_msat >= bolt12_offer.offer_amount, "cannot request less than offer amount, sat->msat rounding issue?"

    # One is a response to an offer; this contains the `offer_issuer_id` or `offer_paths` and
    # all other offer details, and is generally received over an onion
    # message: if it's valid and refers to a known offer, the response is
    # generally to reply with an `invoice` using the `reply_path` field of
    # the onion message.
    invreq = BOLT12InvoiceRequest(
        **bolt12_offer.__dict__,
        invreq_amount=amount_msat,
        invreq_metadata=os.urandom(8),  # TODO: fill invreq_metadata unique, and store for association
        invreq_payer_id=blinding,
        invreq_payer_note=note,
        invreq_features=None,  # TODO: should we add anything here? Invoice features fail.
        invreq_chain=None if constants.net == constants.BitcoinMainnet else constants.net.rev_genesis_bytes(),
    )

    invreq_tlv = invreq.encode(signing_key=session_key)
    req_payload = {
        'invoice_request': {'invoice_request': invreq_tlv}
    }

    try:
        lnwallet.logger.info(f'requesting bolt12 invoice')
        rcpt_data, payload = await lnwallet.onion_message_manager.submit_send(
            payload=req_payload, node_id_or_blinded_paths=node_id_or_blinded_paths
        )
        lnwallet.logger.debug(f'{rcpt_data=} {payload=}')
        if 'invoice_error' in payload:
            return _raise_invoice_error(payload)
        if 'invoice' not in payload:
            raise Exception('reply is not an invoice')
        invoice_tlv = payload['invoice']['invoice']
        invoice = BOLT12Invoice.decode(invoice_tlv)
        lnwallet.logger.info('received bolt12 invoice')
        lnwallet.logger.debug(f'invoice_data: {invoice!r}')
    except Timeout:
        lnwallet.logger.info('timeout waiting for bolt12 invoice')
        raise
    except Exception as e:
        lnwallet.logger.error(f'error requesting bolt12 invoice: {e!r}')
        raise

    if not invoice.compare(against=invreq, ranges=[(0, 159), (1_000_000_000, 2_999_999_999)]):
        raise ValueError("invoice fields don't match invoice request")

    if invoice.offer_issuer_id is None:
        # TODO: MUST reject the invoice if invoice_node_id is not equal to the final blinded_node_id
        pass

    return invoice, invoice_tlv


def verify_request_and_create_invoice(
        lnwallet: 'LNWallet',
        bolt12_offer: BOLT12Offer,
        bolt12_invreq: BOLT12InvoiceRequest,
        invoice_expiry: int = DEFAULT_INVOICE_EXPIRY,
) -> BOLT12Invoice:
    """
    If Bolt12InvoiceError is raised we will send back an error to the sender, otherwise we don't and
    let them time out.
    """
    now = int(time.time())

    # - MUST reject the invoice request if the offer fields do not exactly match a valid, unexpired offer.
    if not bolt12_invreq.compare(against=bolt12_offer, ranges=((0, 159), (1_000_000_000, 2_999_999_999))):
        raise Bolt12InvoiceError(f'invalid bolt12 invoice_request, non-matching offer {bolt12_offer=}')

    if bolt12_offer.offer_absolute_expiry and now > bolt12_offer.offer_absolute_expiry:
        raise Bolt12InvoiceError('offer expired')

    # TODO: store invreq_metadata in lnwallet (no need for persistence)
    # spec: if offer_issuer_id is present, and invreq_metadata is identical to a previous invoice_request:
    #     MAY simply reply with the previous invoice.
    # otherwise:
    #     MUST NOT reply with a previous invoice.

    # spec: if invreq_amount is present: MUST set invoice_amount to invreq_amount
    # otherwise: 'expected' amount (or amount == 0 invoice? or min_htlc_msat from channel set?)
    # TODO: raise if neither offer nor invreq specify amount?
    invoice_amount = bolt12_invreq.invreq_amount or bolt12_offer.offer_amount or 0

    # TODO cltv, expiry
    invoice_payment_hash = lnwallet.create_payment_info(amount_msat=invoice_amount)

    # determine invoice features
    # TODO: not yet supporting jit channels. see lnwallet.get_bolt11_invoice()
    invoice_features = lnwallet.features.for_invoice()
    if not lnwallet.uses_trampoline():
        invoice_features &= ~ LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM

    # spec: if offer_issuer_id is present: MUST set invoice_node_id to the offer_issuer_id
    # spec: otherwise, if offer_paths is present: MUST set invoice_node_id to the final blinded_node_id
    # on the path it received the invoice request
    if bolt12_offer.offer_issuer_id:
        invoice_node_id = bolt12_offer.offer_issuer_id
        # TODO for non-blinded path, where to store payment secret?
    else:
        # NOTE: requires knowledge of invreq incoming path and its final blinded_node_id
        # and corresponding secret for signing invoice

        # if offer_paths := bolt12_offer.get('offer_paths', {}).get('paths'):
        #     # TODO match path, assuming path[0] for now
        #     path_last_blinded_node_id = offer_paths[0].get('path')[-1].get('blinded_node_id')
        #     invoice.update({
        #         'invoice_node_id': {'node_id': path_last_blinded_node_id}
        #     })

        # we don't have invreq used path available here atm. see also request_invoice()
        raise NotImplementedError('branch not implemented, electrum should set offer_issuer_id')

    recipient_data = {}

    # collect suitable channels for payment
    invoice_channels = [
        chan for chan in lnwallet.channels.values()
        if chan.is_active() and chan.can_receive(amount_msat=invoice_amount, check_frozen=True)
    ]
    if not invoice_channels:
        raise Bolt12InvoiceError('no active channels with sufficient receive capacity, cannot receive this payment.')

    try:
        invoice_path_info = get_blinded_paths_to_me(
            lnwallet, final_recipient_data=recipient_data, my_channels=invoice_channels)
    except NoRouteBlindingChannelPeers as e:
        raise Bolt12InvoiceError("no peers with route blinding support") from e

    try:
        invoice = BOLT12Invoice(
            **bolt12_invreq.__dict__,
            invoice_amount=invoice_amount,
            invoice_created_at=now,
            invoice_relative_expiry=invoice_expiry,
            invoice_payment_hash=invoice_payment_hash,
            invoice_features=invoice_features,
            invoice_node_id=invoice_node_id,
            invoice_paths=tuple(p.path for p in invoice_path_info),
            invoice_blindedpay=tuple(p.payinfo for p in invoice_path_info),
        )
    except Exception as e:
        raise Bolt12InvoiceError(str(e)) from e

    lnwallet.add_path_ids_for_payment_hash(invoice_payment_hash, invoice_path_info)

    return invoice


# offer/request/invoice uses different chain than we do
class NoMatchingChainError(Exception): pass


# wraps invoice_error
class Bolt12InvoiceError(Exception):
    def __init__(self, msg: str, *, erroneous_field: Optional[int] = None, suggested_value: Optional[bytes] = None):
        assert msg
        assert suggested_value is None if erroneous_field is None else True

        super().__init__(self, msg)
        self.message = msg
        self.erroneous_field = erroneous_field
        self.suggested_value = suggested_value

    def to_tlv(self):
        data = {'error': {'msg': self.message}}
        if self.erroneous_field is not None:
            data.update({'erroneous_field': {'tlv_fieldnum': self.erroneous_field}})
        if self.suggested_value is not None:
            data.update({'suggested_value': {'value': self.suggested_value}})
        with io.BytesIO() as fd:
            OnionWireSerializer.write_tlv_stream(fd=fd, tlv_stream_name='invoice_error', **data)
            return fd.getvalue()


def _raise_invoice_error(payload):
    invoice_error_tlv = payload['invoice_error']['invoice_error']
    with io.BytesIO(invoice_error_tlv) as fd:
        invoice_error = OnionWireSerializer.read_tlv_stream(fd=fd, tlv_stream_name='invoice_error')
    raise Bolt12InvoiceError(invoice_error.get('error', {}).get('msg'),
                             erroneous_field=invoice_error.get('erroneous_field', {}).get('tlv_fieldnum'),
                             suggested_value=invoice_error.get('suggested_value', {}).get('value'))


def remove_bolt12_whitespace(bolt12_bech32: str) -> str:
    """
    Readers of a bolt12 string:
    if it encounters a + followed by zero or more whitespace characters between two bech32 characters:
        MUST remove the + and whitespace.
    """
    assert isinstance(bolt12_bech32, str)
    res = re.sub(
        r'(?<=[' + BECH32_CHARSET + r'])\+\s*(?=[' + BECH32_CHARSET + r'])',
        '',
        bolt12_bech32,
        flags=re.IGNORECASE,
    )
    if '+' in res:
        raise ValueError('Invalid bolt 12 whitespace')
    return res


def validate_bip_353_name(name: str, domain: str) -> bool:
    """
    MUST reject the (invoice request) if name or domain contain any bytes
    which are not 0-9, a-z, A-Z, -, _ or .
    """
    for s in (name, domain):
        if not re.match(r'^[a-zA-Z0-9._-]+$', s):
            return False
    return True
