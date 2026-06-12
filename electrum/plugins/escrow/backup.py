"""
Best-effort backup of the escrow plugin state to nostr relays.

The plugin state (trades, trade keys, agent profile, ...) is published as an encrypted
NIP-78 parameterized replaceable event, signed by a dedicated backup key derived from the
wallet's lightning master key. As the key material is recoverable from the wallet seed,
a wallet restored from seed can locate and decrypt its backup again, while relays and
third parties only see an opaque blob from an unlinkable pubkey.

Nostr relays provide no availability guarantees, so this cannot replace a wallet file
backup and is only a best-effort recovery aid. Known limitations:
  - relays can withhold the backup or serve an outdated copy (the plugin always picks the
    newest authenticated copy it can find, and merges backups so local state always wins)
  - a restored backup is only as fresh as the last published snapshot. For agents this
    means a payout might already have been paid even if the restored state says otherwise.
    For this reason the payout retry queue is excluded from backups: a restored wallet
    never pays out automatically, participants have to claim their allocations again.
  - while the backup pubkey cannot be linked to the wallet or its trade keys by relays,
    it is persistent, so relays can recognize a returning wallet across sessions by it.
  - if the relays hold a backup this plugin version cannot read (e.g. published by a
    newer version), publishing is disabled to protect it until the plugin is upgraded.
"""

import asyncio
import base64
import contextlib
import json
import os
import time
from typing import TYPE_CHECKING, Callable, Optional

from electrum_aionostr.event import Event as nEvent
from electrum_aionostr.key import PrivateKey

from electrum import constants
from electrum.crypto import sha256, chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
from electrum.i18n import _
from electrum.util import MyEncoder, UserFacingException, wait_for2

from .agent import AgentEscrowTrade
from .client import ClientEscrowTrade
from .escrow_worker import EscrowWorker, NOSTR_KEY_FAMILY_ESCROW
from . import constants as escrow_constants
from .constants import (
    BACKUP_EVENT_KIND, BACKUP_VERSION, BACKUP_CHECK_INTERVAL_SEC,
    BACKUP_REPUBLISH_INTERVAL_SEC, TradeState,
)

if TYPE_CHECKING:
    from .nostr_worker import EscrowNostrWorker
    from electrum.wallet import Abstract_Wallet

# domain separation for the symmetric backup encryption
BACKUP_KEY_DERIVATION_TAG = b'electrum-escrow-backup-encryption:'
BACKUP_AAD = b'electrum-escrow-backup'


class NostrStateBackup(EscrowWorker):
    """
    Per-wallet worker that keeps an encrypted snapshot of the escrow plugin state on the
    user's nostr relays. Once per session, before publishing anything, it fetches the
    relay copy and merges it into the local state (local data wins), which restores the
    state of a wallet that was recovered from seed.
    """

    def __init__(
        self,
        wallet: 'Abstract_Wallet',
        nostr_worker: 'EscrowNostrWorker',
        storage: dict,
        *,
        on_state_restored: Optional[Callable[[], None]] = None,
    ):
        # storage is the plugin level storage of the wallet, containing the
        # client_data/agent_data subtrees and the agent mode flag
        EscrowWorker.__init__(self, wallet, nostr_worker, storage)
        self._on_state_restored = on_state_restored
        self._backup_key = self.get_backup_privkey_for_wallet(wallet)
        self._encryption_key = sha256(BACKUP_KEY_DERIVATION_TAG + self._backup_key.raw_secret)
        self._last_published_hash = None  # type: Optional[bytes]
        self._last_published_time = 0.0
        self._last_payload_ts = 0
        # before we know whether a backup exists on the relays we must not publish, as
        # publishing replaces the relay copy (see _try_resolve_remote_state)
        self._publish_allowed = False
        self._next_remote_resolve = 0.0
        self._remote_resolve_backoff = 60.0
        # whether the last fetch saw an authenticated backup we could not use
        # (e.g. published by a newer plugin version)
        self._saw_unusable_backup = False
        self._stopped = False

    def stop(self):
        self._stopped = True
        EscrowWorker.stop(self)

    @staticmethod
    def get_backup_privkey_for_wallet(wallet: 'Abstract_Wallet') -> PrivateKey:
        """
        Derives the nostr key used to publish state backups, recoverable from seed like
        the other escrow keys. The derivation path is a sibling of the identity key that
        cannot collide with the identity or per-trade keys, which all end in /0 (see
        get_nostr_privkey_for_wallet), so the backup pubkey is not linkable to any of them.
        """
        return EscrowWorker._derive_nostr_privkey(wallet, [NOSTR_KEY_FAMILY_ESCROW, 0, 1])

    @staticmethod
    def _d_tag() -> str:
        # the backup key does not depend on the bitcoin network, so the d tag has to
        # separate the networks to prevent them from replacing each other's backup
        return f"electrum-escrow-backup-{constants.net.NET_NAME}"

    def _storage_lock(self):
        # the plugin storage is a StoredDict sharing the wallet db lock at runtime,
        # but a plain dict in unit tests
        return getattr(self.storage, 'lock', None) or contextlib.nullcontext()

    async def main_loop(self):
        self.logger.debug(f"escrow backup worker started: {self.wallet.basename()}")
        # the remote state is resolved once per session, even when local state exists:
        # this seeds the timestamp ordering against the relay copy, and rescues trades
        # that only exist in the backup (e.g. when an old wallet file copy was restored)
        while True:
            try:
                if self._publish_allowed:
                    self._maybe_publish_backup()
                else:
                    await self._try_resolve_remote_state()
            except Exception:
                self.logger.exception("escrow backup cycle failed")
            await asyncio.sleep(BACKUP_CHECK_INTERVAL_SEC)

    # ---------- snapshot ----------

    def _snapshot_data(self) -> dict:
        """JSON snapshot of the plugin storage subtree worth backing up."""
        with self._storage_lock():
            data = json.loads(json.dumps(dict(self.storage), cls=MyEncoder))
        agent_data = data.get('agent_data')
        if isinstance(agent_data, dict):
            # the transient payout retry queue is not backed up, so a restored (stale)
            # backup can never automatically pay out payouts that may already have been
            # paid before the data loss. Participants claim their allocations again instead.
            agent_data.pop('pending_lightning_invoices', None)
        return data

    @staticmethod
    def _has_meaningful_state(data: dict) -> bool:
        """Whether the storage (or a snapshot of it) contains state worth backing up."""
        if data.get('is_escrow_agent'):
            return True
        client_data = data.get('client_data') or {}
        if client_data.get('escrow_client_trades') or client_data.get('agents') \
                or 'trade_key_counter' in client_data:
            return True
        agent_data = data.get('agent_data') or {}
        if agent_data.get('escrow_agent_trades') or agent_data.get('profile'):
            return True
        return False

    @staticmethod
    def _prune_oldest_finished_trade(data: dict) -> bool:
        """Drops the oldest finished trade from the snapshot, used when the backup
        exceeds the relay event size limits. Returns whether something was dropped."""
        candidates = []  # (creation_timestamp, trades dict, trade_id)
        client_trades = (data.get('client_data') or {}).get('escrow_client_trades') or {}
        agent_trades = (data.get('agent_data') or {}).get('escrow_agent_trades') or {}
        for trades in (client_trades, agent_trades):
            for trade_id, trade in trades.items():
                try:
                    if not TradeState(trade.get('state')).is_final():
                        continue
                except ValueError:
                    continue
                candidates.append((trade.get('creation_timestamp') or 0, trades, trade_id))
        if not candidates:
            return False
        _ts, trades, trade_id = min(candidates, key=lambda c: c[0])
        del trades[trade_id]
        return True

    # ---------- encryption ----------

    def _encrypt_payload(self, payload: dict) -> str:
        plaintext = json.dumps(payload).encode('utf-8')
        nonce = os.urandom(12)
        ciphertext = chacha20_poly1305_encrypt(
            key=self._encryption_key, nonce=nonce, associated_data=BACKUP_AAD, data=plaintext)
        return base64.b64encode(nonce + ciphertext).decode('ascii')

    @staticmethod
    def _encrypted_size(payload: dict) -> int:
        """Predicts the encrypted event content size without doing the encryption:
        base64 of 12 byte nonce + ciphertext (same length as plaintext) + 16 byte mac."""
        plaintext_len = len(json.dumps(payload).encode('utf-8'))
        return 4 * ((plaintext_len + 12 + 16 + 2) // 3)

    def _decrypt_payload(self, content: str) -> Optional[dict]:
        """Decrypts and authenticates an event content. Returns None if it is not a
        valid backup payload of ours (tampered, foreign, or malformed)."""
        try:
            blob = base64.b64decode(content, validate=True)
            plaintext = chacha20_poly1305_decrypt(
                key=self._encryption_key, nonce=blob[:12], associated_data=BACKUP_AAD, data=blob[12:])
            payload = json.loads(plaintext.decode('utf-8'))
        except Exception:
            return None
        validated = self._validate_payload(payload)
        if validated is None:
            # the MAC was valid, so this is authentically our backup, we just cannot
            # use it (e.g. published by a newer plugin version). It must be protected
            # from getting replaced, see _try_resolve_remote_state.
            self._saw_unusable_backup = True
        return validated

    @staticmethod
    def _validate_payload(payload) -> Optional[dict]:
        if not isinstance(payload, dict):
            return None
        if payload.get('version') != BACKUP_VERSION:
            return None
        if payload.get('network') != constants.net.NET_NAME:
            return None
        timestamp = payload.get('timestamp')
        if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
            return None
        if timestamp > int(time.time()) + escrow_constants.BACKUP_TS_MAX_RESTORE_AHEAD_SEC:
            return None  # don't let an absurd clock skew incident poison our timestamps
        if not isinstance(payload.get('data'), dict):
            return None
        return payload

    def _build_payload(self, data: dict) -> dict:
        # monotonic timestamp so the newest snapshot always wins on restore. It is
        # seeded from any merged backup, so updates published after a restore outrank
        # the restored copy. Clamped to a small future drift: relays reject events
        # dated too far ahead, and a backup that inherited a skewed timestamp heals
        # once the wall clock catches up.
        now = int(time.time())
        ts = max(now, self._last_payload_ts + 1)
        ts = min(ts, now + escrow_constants.BACKUP_TS_MAX_PUBLISH_AHEAD_SEC)
        self._last_payload_ts = max(self._last_payload_ts, ts)
        return {
            'version': BACKUP_VERSION,
            'timestamp': ts,
            'network': constants.net.NET_NAME,
            'data': data,
        }

    # ---------- publishing ----------

    def _maybe_publish_backup(self) -> None:
        if not self._has_meaningful_state(self.storage):
            # nothing to back up. This also makes sure an empty wallet can never
            # overwrite an existing backup.
            return
        data = self._snapshot_data()
        snapshot_hash = sha256(json.dumps(data, sort_keys=True).encode('utf-8'))
        unchanged = snapshot_hash == self._last_published_hash \
            and time.time() - self._last_published_time < BACKUP_REPUBLISH_INTERVAL_SEC
        if unchanged:
            return
        payload = self._build_payload(data)  # pruning `data` below also prunes the payload
        while self._encrypted_size(payload) > escrow_constants.MAX_BACKUP_EVENT_BYTES \
                and self._prune_oldest_finished_trade(data):
            pass  # relays reject overly large events: drop finished trades until it fits
        if self._encrypted_size(payload) > escrow_constants.MAX_BACKUP_EVENT_BYTES:
            self.logger.warning("escrow state backup is too large to publish, skipping")
            # don't retry until the state changes or the periodic republish is due
            self._last_published_hash = snapshot_hash
            self._last_published_time = time.time()
            return

        def on_result(success: bool):
            if not success and self._last_published_hash == snapshot_hash:
                # no relay accepted the event: retry on the next check cycle instead
                # of waiting for the next state change
                self._last_published_hash = None

        self.nostr_worker.broadcast_replaceable_event(
            kind=BACKUP_EVENT_KIND,
            content=self._encrypt_payload(payload),
            d_tag=self._d_tag(),
            signing_key=self._backup_key,
            # relays replace by created_at, so it has to follow the payload timestamp
            # ordering, otherwise an update published right after a restore could lose
            created_at=payload['timestamp'],
            on_result=on_result,
        )
        self._last_published_hash = snapshot_hash
        self._last_published_time = time.time()
        self.logger.debug("published escrow state backup")

    # ---------- restoring ----------

    async def _try_resolve_remote_state(self):
        """
        Resolves whether a backup exists on the relays before the first publish. This
        order matters: publishing replaces the relay copy, so if fetching the backup
        failed (e.g. relays were unreachable on startup) while the user already started
        trading, publishing right away would permanently destroy the very backup the
        user may still need to recover. Merges any found backup into the local state.
        """
        if time.monotonic() < self._next_remote_resolve:
            return
        payload, conclusive = await self._fetch_best_backup()
        if self._stopped or self.wallet.network is None:
            return  # the wallet was closed while we were fetching
        if payload is not None:
            try:
                num_new = self._apply_backup(payload)
            except Exception:
                self.logger.exception("could not apply escrow state backup")
                self._schedule_remote_resolve_retry()
                return
            self.logger.info(f"merged escrow state backup from relays ({num_new} new trades)")
            self._publish_allowed = True
        elif self._saw_unusable_backup:
            # there is an authenticated backup we cannot use (e.g. from a newer plugin
            # version): never replace it, the user may still need it after an upgrade
            self.logger.warning("found an escrow backup this plugin version cannot use, "
                                "state backups stay disabled to protect it")
            self._schedule_remote_resolve_retry()
        elif conclusive:
            self.logger.debug("no escrow state backup found on the relays")
            self._publish_allowed = True
        else:
            # the relays could not be watched for the full fetch window, a backup
            # might still exist: retry with backoff
            self._schedule_remote_resolve_retry()

    def _schedule_remote_resolve_retry(self):
        self._next_remote_resolve = time.monotonic() + self._remote_resolve_backoff
        self._remote_resolve_backoff = min(900.0, self._remote_resolve_backoff * 2)

    async def restore_from_nostr(self) -> int:
        """
        Fetches the latest state backup from the relays and merges it into the local
        state; existing local data always wins over the (potentially stale) backup.
        Returns the number of newly added trades. Raises UserFacingException if no
        usable backup was found.
        """
        payload, _conclusive = await self._fetch_best_backup()
        if payload is None:
            raise UserFacingException(_("No usable escrow backup was found on your Nostr relays."))
        if self._stopped or self.wallet.network is None:
            # note: the wallet might have been closed without us getting stopped,
            # e.g. when it was loaded by the daemon without a window
            raise UserFacingException(_("The escrow plugin was stopped."))
        try:
            num_new = self._apply_backup(payload)
        except Exception:
            self.logger.exception("could not apply escrow state backup")
            raise UserFacingException(_("The escrow backup data could not be applied."))
        self._publish_allowed = True
        return num_new

    def _apply_backup(self, payload: dict) -> int:
        """Merges a validated backup payload into the local state.
        Returns the number of newly added trades."""
        self._last_payload_ts = max(self._last_payload_ts, payload['timestamp'])
        num_new, changed = self._apply_backup_data(payload['data'])
        if changed:
            self.wallet.save_db()
            if self._on_state_restored:
                self._on_state_restored()
        return num_new

    async def _fetch_best_backup(self) -> tuple[Optional[dict], bool]:
        """
        Collects backup events from the relays and returns (payload of the newest
        authenticated backup, or None, whether the result is conclusive). The result
        is inconclusive when the relays could not be watched for the full fetch
        window, so a missing backup might just not have been served (yet).
        """
        query = {
            "kinds": [BACKUP_EVENT_KIND],
            "authors": [self._backup_key.public_key.hex()],
            "#d": [self._d_tag()],
            "limit": 3,
        }
        best = None  # type: Optional[dict]
        self._saw_unusable_backup = False
        deadline = time.monotonic() + escrow_constants.BACKUP_FETCH_TIMEOUT_SEC
        while not self._stopped:
            event_queue = asyncio.Queue()
            job_id = self.nostr_worker.fetch_events(query, event_queue)
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        # the subscription survived until the deadline
                        return best, True
                    try:
                        event = await wait_for2(event_queue.get(), timeout=remaining)
                    except (asyncio.TimeoutError, TimeoutError):
                        return best, True
                    if event is None:
                        break  # job ended early (e.g. relay error or proxy change)
                    candidate = self._better_candidate(best, event)
                    if candidate is not best:
                        best = candidate
                        # we have a usable backup; only wait a short grace period for
                        # other relays to maybe serve a newer copy
                        deadline = min(
                            deadline, time.monotonic() + escrow_constants.BACKUP_FETCH_GRACE_SEC)
            finally:
                self.nostr_worker.cancel_job(job_id)
            if best is not None:
                # the ended job already served everything the reachable relays had
                return best, True
            # the job died before the deadline without results (e.g. a transient relay
            # error): resubscribe instead of wrongly reporting that no backup exists
            await asyncio.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
            if time.monotonic() >= deadline:
                return None, False
        return best, best is not None

    def _better_candidate(self, best: Optional[dict], event: 'nEvent') -> Optional[dict]:
        if event.pubkey != self._backup_key.public_key.hex():
            return best  # don't rely on relay-side filtering
        # no need to verify the event signature: the payload is authenticated by its MAC,
        # which requires the same secret the event signature would prove possession of
        payload = self._decrypt_payload(event.content)
        if payload is None:
            return best
        if best is None or payload['timestamp'] > best['timestamp']:
            return payload
        return best

    def _apply_backup_data(self, data: dict) -> tuple[int, bool]:
        """
        Merges validated backup data into the plugin storage. Existing local entries
        always win over the (potentially stale) backup data. Returns (number of newly
        added trades, whether anything was written). Raises on malformed data, writing
        nothing in that case.
        """
        if not isinstance(data, dict):
            raise ValueError("backup data is not a dict")
        client_data = data.get('client_data') or {}
        agent_data = data.get('agent_data') or {}
        if not isinstance(client_data, dict) or not isinstance(agent_data, dict):
            raise ValueError("malformed backup data")
        # construct everything before writing, so nothing is written on malformed data.
        # Note: this duplicates the type mapping registered with stored_at (see
        # ClientEscrowTrade/AgentEscrowTrade), which only converts at db load time.
        client_trades = {
            trade_id: ClientEscrowTrade(**trade)
            for trade_id, trade in (client_data.get('escrow_client_trades') or {}).items()
        }
        agent_trades = {
            trade_id: AgentEscrowTrade(**trade)
            for trade_id, trade in (agent_data.get('escrow_agent_trades') or {}).items()
        }
        if not all(isinstance(trade_id, str) for trade_id in [*client_trades, *agent_trades]):
            raise ValueError("malformed trade id")
        key_counter = client_data.get('trade_key_counter')
        if key_counter is not None \
                and (not isinstance(key_counter, int) or isinstance(key_counter, bool) or key_counter < 0):
            raise ValueError("malformed trade_key_counter")
        agents = client_data.get('agents') or []
        if not isinstance(agents, list) or not all(isinstance(a, str) for a in agents):
            raise ValueError("malformed agents list")
        profile = agent_data.get('profile')
        if profile is not None and not isinstance(profile, dict):
            raise ValueError("malformed profile")

        num_new = 0
        changed = False
        with self._storage_lock():
            storage_client = self.storage.setdefault('client_data', {})
            storage_agent = self.storage.setdefault('agent_data', {})
            # write into the existing trade dicts: a running worker holds references to them
            for trades, destination in (
                (client_trades, storage_client.setdefault('escrow_client_trades', {})),
                (agent_trades, storage_agent.setdefault('escrow_agent_trades', {})),
            ):
                for trade_id, trade in trades.items():
                    if trade_id in destination:
                        continue  # the local version of the trade is newer than the backup
                    destination[trade_id] = trade
                    num_new += 1
                    changed = True
            # the counter must never decrease so trade keys are never reused
            if key_counter is not None and key_counter > storage_client.get('trade_key_counter', -1):
                storage_client['trade_key_counter'] = key_counter
                changed = True
            if agents:
                local_agents = storage_client.setdefault('agents', [])
                for agent_pubkey in agents:
                    if agent_pubkey not in local_agents:
                        local_agents.append(agent_pubkey)
                        changed = True
            if profile is not None and 'profile' not in storage_agent:
                storage_agent['profile'] = profile
                changed = True
            if 'is_escrow_agent' not in self.storage and data.get('is_escrow_agent'):
                self.storage['is_escrow_agent'] = True
                changed = True
        # note: agent_data.pending_lightning_invoices is intentionally never restored,
        # see _snapshot_data
        return num_new, changed
