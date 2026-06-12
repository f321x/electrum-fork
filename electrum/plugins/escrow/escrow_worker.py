import asyncio
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Callable, Coroutine, Any
from abc import ABC, abstractmethod
from concurrent.futures import Future, CancelledError

import attr

from electrum_aionostr.key import PrivateKey, PublicKey

from electrum import constants
from electrum.bip32 import BIP32Node, BIP32_PRIME
from electrum.util import get_asyncio_loop, is_hex_str
from electrum.logging import Logger
from electrum.crypto import sha256
from electrum.stored_dict import StoredObject

from .constants import (
    PROTOCOL_VERSION, MIN_TRADE_AMOUNT_SAT, MAX_TRADE_AMOUNT_SAT, MAX_BOND_AMOUNT_SAT,
    MAX_AGENT_FEE_PPM, MAX_TITLE_LEN_CHARS, MAX_CONTRACT_LEN_CHARS,
    TradePaymentDirection, TradePaymentProtocol, TradeState,
)

if TYPE_CHECKING:
    from .nostr_worker import EscrowNostrWorker
    from electrum.wallet import Abstract_Wallet

# Dedicated BIP32 key family for escrow nostr keys, following the derivation scheme of the
# lightning keys (see lnutil.LnKeyFamily). The large value (ascii 'esc') cannot collide with
# present or future LnKeyFamily entries, which are allocated sequentially from 0.
NOSTR_KEY_FAMILY_ESCROW = 0x657363 | BIP32_PRIME


class NestedStoredObject(StoredObject):
    """
    StoredObject that wires nested StoredObject attributes into the db patch hierarchy,
    so that attribute mutations on children also generate db patches.
    Note: plain electrum StoredObjects only generate patches when they are direct values
    of a StoredDict.
    """

    def set_db(self, db):
        StoredObject.set_db(self, db)
        for key, value in vars(self).items():
            if not key.startswith('_') and isinstance(value, StoredObject):
                value.set_db(db)
                value.set_parent(key=key, parent=self)

    def __setattr__(self, key: str, value):
        old = getattr(self, key, None) if not key.startswith('_') else None
        StoredObject.__setattr__(self, key, value)
        if not key.startswith('_'):
            if isinstance(old, StoredObject) and old is not value:
                # unwire the replaced child so stale references can't emit patches anymore
                old._parent = None
            if isinstance(value, StoredObject):
                value.set_db(self._db)
                value.set_parent(key=key, parent=self)


def _to_payment_direction(v) -> TradePaymentDirection:
    return TradePaymentDirection(v)

def _to_payment_protocol(v) -> TradePaymentProtocol:
    return TradePaymentProtocol(v)

# attrs converters shared by the client and agent trade objects
def to_trade_state(v) -> TradeState:
    return TradeState(v)

def to_trade_contract(v) -> 'TradeContract':
    if isinstance(v, dict):
        return TradeContract(**v)
    return v


@attr.s(kw_only=True)
class TradeContract(NestedStoredObject):
    """
    The canonical trade document all three parties (maker, taker, agent) sign or verify.
    The contract hash also commits to the protocol version and the bitcoin network,
    so signatures cannot be replayed across networks or protocol versions.
    """
    title = attr.ib(type=str)
    text = attr.ib(type=str)  # the human readable contract conditions
    trade_amount_sat = attr.ib(type=int)
    bond_sat = attr.ib(type=int)  # bond is paid by the trader who receives the main payment
    agent_fee_ppm = attr.ib(type=int)  # agent fee locked in at trade creation, of trade amount
    maker_payment_direction = attr.ib(converter=_to_payment_direction)  # type: TradePaymentDirection
    payment_protocol = attr.ib(converter=_to_payment_protocol)  # type: TradePaymentProtocol
    agent_pubkey = attr.ib(type=str)  # nostr identity of the escrow agent

    def validate_sanity(self) -> None:
        """Raises ValueError on malformed or unreasonable contract values."""
        if not isinstance(self.title, str) or not self.title or len(self.title) > MAX_TITLE_LEN_CHARS:
            raise ValueError("invalid title")
        if not isinstance(self.text, str) or not self.text or len(self.text) > MAX_CONTRACT_LEN_CHARS:
            raise ValueError("invalid contract text")
        if not isinstance(self.trade_amount_sat, int) or isinstance(self.trade_amount_sat, bool) \
                or not (MIN_TRADE_AMOUNT_SAT <= self.trade_amount_sat <= MAX_TRADE_AMOUNT_SAT):
            raise ValueError("invalid trade_amount_sat")
        if not isinstance(self.bond_sat, int) or isinstance(self.bond_sat, bool) \
                or not (0 <= self.bond_sat <= MAX_BOND_AMOUNT_SAT):
            raise ValueError("invalid bond_sat")
        if not isinstance(self.agent_fee_ppm, int) or isinstance(self.agent_fee_ppm, bool) \
                or not (0 <= self.agent_fee_ppm <= MAX_AGENT_FEE_PPM):
            raise ValueError("invalid agent_fee_ppm")
        if not is_hex_str(self.agent_pubkey) or len(self.agent_pubkey) != 64:
            raise ValueError("invalid agent_pubkey")

    def contract_hash(self) -> str:
        preimage = json.dumps(
            {
                "domain": "electrum-escrow-contract",
                "protocol_version": PROTOCOL_VERSION,
                "network": constants.net.NET_NAME,
                "title": self.title,
                "text": self.text,
                "trade_amount_sat": self.trade_amount_sat,
                "bond_sat": self.bond_sat,
                "agent_fee_ppm": self.agent_fee_ppm,
                "maker_payment_direction": int(self.maker_payment_direction),
                "payment_protocol": int(self.payment_protocol),
                "agent_pubkey": self.agent_pubkey,
            },
            sort_keys=True,
            separators=(',', ':'),
        )
        digest = sha256(preimage.encode('utf-8'))
        return digest.hex()

    def verify(self, *, sig_hex: str, pubkey_hex: str) -> bool:
        try:
            pubkey = PublicKey(bytes.fromhex(pubkey_hex))
            return pubkey.verify_signed_message_hash(sig=sig_hex, hash=self.contract_hash())
        except Exception:
            return False

    def sign(self, *, privkey_hex: str) -> str:
        msg = self.contract_hash()
        privkey = PrivateKey(bytes.fromhex(privkey_hex))
        sig = privkey.sign_message_hash(hash=bytes.fromhex(msg))
        return sig

    def payment_direction(self, *, is_maker: bool) -> TradePaymentDirection:
        if is_maker:
            return self.maker_payment_direction
        return self.maker_payment_direction.inverted()

    def funding_amount_sat(self, direction: TradePaymentDirection) -> int:
        """What a participant paying in `direction` has to lock up with the agent."""
        if direction == TradePaymentDirection.SENDING:
            return self.trade_amount_sat
        return self.bond_sat

    def agent_fee_sat(self) -> int:
        return (self.trade_amount_sat * self.agent_fee_ppm) // 1_000_000

    def payout_amount_sat(self) -> int:
        """What the receiver of the main payment gets paid out on success (incl. bond refund)."""
        return self.trade_amount_sat - self.agent_fee_sat() + self.bond_sat

    def pot_sat(self) -> int:
        """Total amount held by the agent once both parties funded."""
        return self.trade_amount_sat + self.bond_sat

    @classmethod
    def from_remote_dict(cls, content: dict) -> 'TradeContract':
        """Constructs and sanity-checks a contract from untrusted remote data.
        Raises ValueError if malformed."""
        if not isinstance(content, dict):
            raise ValueError("contract is not a dict")
        expected_keys = {
            'title', 'text', 'trade_amount_sat', 'bond_sat', 'agent_fee_ppm',
            'maker_payment_direction', 'payment_protocol', 'agent_pubkey',
        }
        if set(content.keys()) != expected_keys:
            raise ValueError("contract has missing or unexpected fields")
        try:
            contract = cls(**content)
        except Exception as e:
            raise ValueError(f"malformed contract: {e!r}") from e
        contract.validate_sanity()
        return contract


@dataclass(frozen=True)
class EscrowAgentProfile:
    """
    Information broadcast by the escrow agent, visible to its customers.
    Using Nostr kind 0 (NIP-01) profile event.
    """
    name: str
    about: str  # short description
    languages: list[str]
    service_fee_ppm: int  # fees of traded amount (excluding bonds) in ppm
    gpg_fingerprint: Optional[str] = None
    picture: Optional[str] = None  # url to profile picture
    website: Optional[str] = None

    @classmethod
    def from_remote_dict(cls, content: dict) -> 'EscrowAgentProfile':
        """Constructs and validates a profile from untrusted remote data.
        Raises ValueError if malformed."""
        if not isinstance(content, dict):
            raise ValueError("profile is not a dict")
        name = content.get('name')
        about = content.get('about')
        languages = content.get('languages')
        fee = content.get('service_fee_ppm')
        if not isinstance(name, str) or not name or len(name) > 50:
            raise ValueError("invalid name")
        if not isinstance(about, str) or len(about) > 1000:
            raise ValueError("invalid about")
        if not isinstance(languages, list) or len(languages) > 20 \
                or not all(isinstance(lang, str) and len(lang) <= 20 for lang in languages):
            raise ValueError("invalid languages")
        if not isinstance(fee, int) or isinstance(fee, bool) or not (0 <= fee <= MAX_AGENT_FEE_PPM):
            raise ValueError("invalid service_fee_ppm")
        optional = {}
        for key, max_len in (('gpg_fingerprint', 100), ('picture', 200), ('website', 200)):
            value = content.get(key)
            if value is not None and (not isinstance(value, str) or len(value) > max_len):
                raise ValueError(f"invalid {key}")
            optional[key] = value
        return cls(
            name=name,
            about=about,
            languages=languages,
            service_fee_ppm=fee,
            **optional,
        )


class EscrowWorker(ABC, Logger):
    def __init__(self, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker', storage: dict):
        Logger.__init__(self)
        self.wallet = wallet
        self.nostr_worker = nostr_worker
        self.storage = storage
        self.main_task: Optional[Future] = None

    @abstractmethod
    async def main_loop(self):
        pass

    async def _run_guarded(self, coro_fn: Callable[[], Coroutine[Any, Any, None]]):
        """Runs a worker subtask and restarts it on unexpected exceptions, so a single
        crashing subtask doesn't take down the whole worker task group."""
        while True:
            try:
                await coro_fn()
                return
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception(f"worker task {coro_fn.__name__} failed, restarting in 10s")
                await asyncio.sleep(10)

    @staticmethod
    def _derive_nostr_privkey(wallet: 'Abstract_Wallet', path: list) -> PrivateKey:
        """
        Derives a nostr key from the wallet's lightning master key, the same way the
        lightning node key itself is derived (see lnutil.generate_keypair), but on a
        dedicated escrow key family. Note that this requires private key material:
        deriving from e.g. the xpub would allow anyone knowing the xpub (watch-only
        copies, servers) to decrypt escrow traffic and impersonate the wallet.
        """
        assert wallet.lnworker is not None, "wallet needs lightning support"
        # the same key material LNWallet itself is instantiated from, see wallet.init_lightning
        ln_xprv = wallet.db.get('lightning_xprv') or wallet.db.get('lightning_privkey2')
        assert ln_xprv is not None, "wallet has no lightning keys"
        root = BIP32Node.from_xkey(ln_xprv)
        child = root.subkey_at_private_derivation(path)
        return PrivateKey(child.eckey.get_secret_bytes())

    @staticmethod
    def get_nostr_privkey_for_wallet(wallet: 'Abstract_Wallet', *, key_id: int = -1) -> PrivateKey:
        """
        key_id -1 is the wallet's stable escrow identity; each trade should use a fresh
        key_id >= 0 to prevent trades from getting linked to each other. All these paths
        end in /0, the backup key (see backup.py) is allocated next to the identity at
        [family, 0, 1].
        """
        assert isinstance(key_id, int) and -1 <= key_id < BIP32_PRIME - 1, f"invalid key_id: {key_id}"
        return EscrowWorker._derive_nostr_privkey(wallet, [NOSTR_KEY_FAMILY_ESCROW, key_id + 1, 0])

    @classmethod
    def create(cls, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker', storage: dict, **kwargs) -> 'EscrowWorker':
        worker = cls(wallet, nostr_worker, storage, **kwargs)
        task = asyncio.run_coroutine_threadsafe(
            worker.main_loop(),
            get_asyncio_loop(),
        )

        def done_callback(f):
            try:
                f.result()
            except (asyncio.CancelledError, CancelledError):
                pass
            except Exception:
                worker.logger.exception("EscrowWorker task failed")

        task.add_done_callback(done_callback)
        worker.main_task = task
        return worker

    def stop(self):
        self.logger.debug("escrow worker stopped")
        # swap before cancelling so concurrent stop() calls from different threads
        # cannot race on a half-cleared task reference
        task, self.main_task = self.main_task, None
        if task:
            task.cancel()
