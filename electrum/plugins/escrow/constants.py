from enum import IntEnum, Enum
from electrum.i18n import _

PROTOCOL_VERSION = 1
MIN_TRADE_AMOUNT_SAT = 1000
MAX_TRADE_AMOUNT_SAT = 100_000_000  # 1 BTC, lightning trades shouldn't get too large
MAX_BOND_AMOUNT_SAT = MAX_TRADE_AMOUNT_SAT
MAX_AGENT_FEE_PPM = 1_000_000  # 100%
MAX_TITLE_LEN_CHARS = 100
MAX_CONTRACT_LEN_CHARS = 2000

AGENT_STATUS_EVENT_KIND = 30315
AGENT_PROFILE_EVENT_KIND = 0  # regular nostr user profile
AGENT_RELAY_LIST_METADATA_KIND = 10002  # NIP-65 relay list
EPHEMERAL_REQUEST_EVENT_KIND = 25582
ENCRYPTED_DIRECT_MESSAGE_KIND = 4

STATUS_EVENT_INTERVAL_SEC = 1800  # 30 min
PROFILE_EVENT_INTERVAL_SEC = 1_209_600  # 2 weeks
RELAY_EVENT_INTERVAL_SEC = 1_209_800  # 2 weeks
DIRECT_MESSAGE_EXPIRATION_SEC = 15_552_000  # 6 months
# ~3 months, time after which we give up to pay a customer and just keep their money,
# they can contact us out of band and claim again
PAYOUT_TIMEOUT_SEC = 7_776_000
PAYOUT_INTERVAL_SEC = 1800  # how often we retry to pay out an invoice
MAX_AMOUNT_PENDING_TRADES = 200  # how many pending (unfunded) trades we keep in memory until evicting the oldest one
FUNDING_INVOICE_EXPIRY_SEC = 600  # 10 min, funding invoices are paid right away in the wizard
PAYOUT_INVOICE_EXPIRY_SEC = 60 * 60 * 24  # payout invoices should live long enough for the agent to retry
RPC_TIMEOUT_SEC = 30  # how long clients wait for an agent response
SEEN_EVENT_IDS_CACHE_SIZE = 4096  # replay protection cache of the agent

class TradeState(IntEnum):
    WAITING_FOR_TAKER = 0
    ONGOING = 1
    MEDIATION = 2
    FINISHED = 3
    CANCELLED = 4

    def __str__(self):
        return {
            self.WAITING_FOR_TAKER: _("Waiting for taker"),
            self.ONGOING: _("Ongoing"),
            self.MEDIATION: _("Mediation"),
            self.FINISHED: _("Finished"),
            self.CANCELLED: _("Cancelled"),
        }[self]

    def is_final(self) -> bool:
        return self in (TradeState.FINISHED, TradeState.CANCELLED)


class TradePaymentProtocol(IntEnum):
    BITCOIN_ONCHAIN = 0
    BITCOIN_LIGHTNING = 1


class TradePaymentDirection(IntEnum):
    SENDING = 0
    RECEIVING = 1

    def inverted(self) -> 'TradePaymentDirection':
        if self == TradePaymentDirection.SENDING:
            return TradePaymentDirection.RECEIVING
        return TradePaymentDirection.SENDING


class TradeRPC(str, Enum):
    # client -> agent requests
    REGISTER_ESCROW = "register_escrow"  # maker registers trade
    ACCEPT_ESCROW = "accept_escrow"  # taker accepts trade
    COLLABORATIVE_CONFIRM = "collaborative_confirm"
    COLLABORATIVE_CANCEL = "collaborative_cancel"
    REQUEST_MEDIATION = "request_mediation"
    GET_TRADE_STATE = "get_trade_state"
    CLAIM_PAYOUT = "claim_payout"  # participant submits (new) payout invoice for their allocation
    # agent -> client direct message notifications
    TRADE_FUNDED = "trade_funded"  # agent -> maker: "taker has funded"
    TRADE_STATE_CHANGED = "trade_state_changed"  # agent -> participants: "re-sync your trade state"

SUPPORTED_PAYMENT_PROTOCOLS = [TradePaymentProtocol.BITCOIN_LIGHTNING]
