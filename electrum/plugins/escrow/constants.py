from enum import IntEnum, Enum
from electrum.i18n import _

PROTOCOL_VERSION = 1
MIN_TRADE_AMOUNT_SAT = 1000
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
# ~3m, time after which we give up to pay a customer and just keep their money, they can contact out of band
PAYOUT_TIMEOUT_SEC = 7_776_000
PAYOUT_INTERVAL_SEC = 1800  # how often we try to pay out an invoice
MAX_AMOUNT_PENDING_TRADES = 200  # how many pending (unfunded) trades we keep in memory until evicting the oldest one

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


class TradePaymentProtocol(IntEnum):
    BITCOIN_ONCHAIN = 0
    BITCOIN_LIGHTNING = 1


class TradePaymentDirection(IntEnum):
    SENDING = 0
    RECEIVING = 1


class TradeRPC(str, Enum):
    TRADE_FUNDED = "trade_funded"  # agent -> maker: "taker has funded"
    REGISTER_ESCROW = "register_escrow"  # maker registers trade
    ACCEPT_ESCROW = "accept_escrow"  # taker accepts trade
    COLLABORATIVE_CONFIRM = "collaborative_confirm"
    COLLABORATIVE_CANCEL = "collaborative_cancel"
    REQUEST_MEDIATION = "request_mediation"

SUPPORTED_PAYMENT_PROTOCOLS = [TradePaymentProtocol.BITCOIN_LIGHTNING]
