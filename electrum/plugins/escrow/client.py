import asyncio
import dataclasses
import time
import json
from collections import defaultdict
from typing import TYPE_CHECKING, Mapping, Optional
from types import MappingProxyType

from electrum_aionostr.event import Event as nEvent

from electrum.util import OldTaskGroup, is_valid_websocket_url

from .escrow_worker import EscrowWorker, EscrowAgentProfile
from .nostr_worker import EscrowNostrWorker
from .nostr_worker import NostrJobID

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet

@dataclasses.dataclass
class EscrowAgentInfo:
    profile_info: Optional[EscrowAgentProfile] = None
    inbound_liquidity: Optional[int] = None
    outbound_liquidity: Optional[int] = None
    relays: Optional[list[str]] = None  # todo: unused for now
    profile_ts: Optional[int] = None
    status_ts: Optional[int] = None
    relay_ts: Optional[int] = None

    def last_seen_minutes(self) -> int:
        now = int(time.time())
        age = now - self.status_ts
        return age // 60


class EscrowClient(EscrowWorker):

    def __init__(self, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker', storage: dict):
        EscrowWorker.__init__(self, wallet, nostr_worker, storage)
        self.agent_infos = defaultdict(EscrowAgentInfo)  # type: defaultdict[str, EscrowAgentInfo]
        self.fetch_job_id = None  # type: Optional[NostrJobID]

    async def main_loop(self):
        self.logger.debug(f"escrow client started: {self.wallet.basename()}")
        async with OldTaskGroup() as g:
            tasks = (
                self._fetch_agent_events(),
            )
            for task in tasks:
                await g.spawn(task)
                await asyncio.sleep(1)  # prevent rate limiting, however not as critical as we don't broadcast much

    async def _fetch_agent_events(self):
        event_kinds = [
            self.nostr_worker.AGENT_STATUS_EVENT_KIND,
            self.nostr_worker.AGENT_PROFILE_EVENT_KIND,
            self.nostr_worker.AGENT_RELAY_LIST_METADATA_KIND,
        ]
        event_queue = asyncio.Queue()
        while True:
            agent_pubkeys = self.storage.get('agents') or []
            query = {
                "kinds": event_kinds,
                "authors": agent_pubkeys,
            }
            self.fetch_job_id = self.nostr_worker.fetch_events(query, event_queue)
            while True:
                event = await event_queue.get()
                if event is None:
                    break  # job got canceled, maybe proxy changed
                assert isinstance(event, nEvent)

                if event.pubkey not in self.agent_infos and event.pubkey not in agent_pubkeys:
                    self.logger.debug(f"got event for unknown pubkey: {event.pubkey=}")
                    continue

                match event.kind:
                    case self.nostr_worker.AGENT_PROFILE_EVENT_KIND:
                        self._handle_escrow_agent_profile(event)
                    case self.nostr_worker.AGENT_STATUS_EVENT_KIND:
                        self._handle_escrow_agent_status(event)
                    case self.nostr_worker.AGENT_RELAY_LIST_METADATA_KIND:
                        self._handle_escrow_agent_relay_list(event)
                    case _:
                        self.logger.debug(f"got unwanted nostr event kind: {event.kind}")

    def reload_agents(self):
        if self.fetch_job_id:
            # this will put none on the queue, making _fetch_agent_events create a new query
            self.nostr_worker.cancel_job(self.fetch_job_id)

    def _handle_escrow_agent_profile(self, event: nEvent):
        try:
            content = json.loads(event.content)
        except json.JSONDecodeError:
            return

        if not isinstance(content, dict):
            return

        try:
            profile = EscrowAgentProfile(**content)
        except Exception:
            self.logger.debug(f"invalid profile event: {event.id=}")
            return

        current_info = self.agent_infos.get(event.pubkey)
        if current_info:
            if event.created_at <= (current_info.profile_ts or 0):
                return

        self.agent_infos[event.pubkey].profile_info = profile
        self.agent_infos[event.pubkey].profile_ts = event.created_at

    def _handle_escrow_agent_status(self, event: nEvent):
        try:
            content = json.loads(event.content)
        except json.JSONDecodeError:
            return

        if not isinstance(content, dict):
            return

        inbound = content.get('inbound_liquidity_sat')
        if not isinstance(inbound, int):
            return

        outbound = content.get('outbound_liquidity_sat')
        if not isinstance(outbound, int):
            return

        current_info = self.agent_infos.get(event.pubkey)
        if current_info:
            if event.created_at <= (current_info.status_ts or 0):
                return

        self.agent_infos[event.pubkey].inbound_liquidity = inbound
        self.agent_infos[event.pubkey].outbound_liquidity = outbound
        self.agent_infos[event.pubkey].status_ts = event.created_at

    def _handle_escrow_agent_relay_list(self, event: nEvent):
        if (self.agent_infos[event.pubkey].relay_ts or 0) >= event.created_at:
            return
        relays = []
        for tag in event.tags:
            if len(tag) >= 2 and tag[0] == 'r' and is_valid_websocket_url(tag[1]):
                relays.append(tag[1])
        self.agent_infos[event.pubkey].relays = relays[:10]

    def get_escrow_agent_infos(self) -> Mapping[str, EscrowAgentInfo]:
        return MappingProxyType(self.agent_infos)
