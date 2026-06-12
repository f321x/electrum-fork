"""Helpers shared between the Qt and QML GUIs of the escrow plugin.

GUI-agnostic presentation and validation logic lives here so the two
frontends cannot silently diverge. Amount formatting is parameterized via a
``fmt`` callback (the GUIs format amounts differently, e.g. with fiat)."""
from typing import TYPE_CHECKING, Callable, Optional, Tuple

from electrum.i18n import _
from electrum.network import Network
from electrum.util import make_aiohttp_session

from .agent import EscrowAgent
from .client import ClientEscrowTrade
from .constants import (
    MIN_TRADE_AMOUNT_SAT, TradePaymentDirection, TradePaymentProtocol, TradeState,
)
from .escrow_worker import TradeContract

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from .escrow import EscrowPlugin

MAX_AVATAR_BYTES = 1024 * 1024  # don't fetch arbitrarily large profile pictures

FormatAmount = Callable[[int], str]


async def fetch_url_bytes_async(url: str) -> Optional[bytes]:
    network = Network.get_instance()
    if not network:
        return None
    async with make_aiohttp_session(network.proxy, timeout=20) as session:
        async with session.get(url) as response:
            if response.status != 200:
                return None
            if response.content_length and response.content_length > MAX_AVATAR_BYTES:
                return None
            data = await response.content.read(MAX_AVATAR_BYTES + 1)
            if len(data) > MAX_AVATAR_BYTES:
                return None
            return data


def fetch_url_bytes(url: str) -> Optional[bytes]:
    """Blocking variant, for use from a (non-asyncio) worker thread."""
    network = Network.get_instance()
    if not network:
        return None
    return network.run_from_another_thread(fetch_url_bytes_async(url))


def format_fee_ppm(fee_ppm: int) -> str:
    return f"{fee_ppm / 10_000:g}%"


def help_text() -> str:
    info = _("The Trade Escrow plugin allows you to safely trade with strangers by using a trusted escrow agent as an intermediary. "
             "The agent takes custody of the funds until both participants are satisfied, or decides the outcome of the trade after reviewing evidence.")
    warning = _("The escrow agent is fully trusted and can take your money. Only use escrow agents "
                "with a well-established reputation that you trust.")
    return f"{info}\n\n{warning}"


def plugin_status_warning(plugin: 'EscrowPlugin', wallet: 'Abstract_Wallet') -> Tuple[Optional[str], bool]:
    """Checks if there is any issue that could cause the plugin to be unreliable.
    Returns (message, is_critical), message is None if there is nothing to warn about."""
    if len(plugin.config.get_nostr_relays()) < 3:
        return _("You have configured only a few Nostr relays. To ensure reliable operation, "
                 "you should add more Nostr relays in the network settings."), True
    if not wallet.has_lightning():
        return _("This wallet has no Lightning support. Trading requires a wallet "
                 "with Lightning enabled."), True
    worker = plugin.get_worker_for_wallet(wallet)
    if isinstance(worker, EscrowAgent) and not worker.get_profile():
        return _("Configure your Escrow Agent profile to become visible to other users."), False
    return None, False


def get_trade_validation_error(
    wallet: 'Abstract_Wallet',
    *,
    trade_amount_sat: Optional[int],
    bond_sat: int,
    payment_direction: TradePaymentDirection,
    fmt: FormatAmount,
) -> Optional[str]:
    """Validation of the create-trade form: minimum amount and Lightning liquidity."""
    amount = trade_amount_sat or 0
    bond = bond_sat or 0
    if amount and amount < MIN_TRADE_AMOUNT_SAT:
        return _("Trade amount too small. Minimal trade amount: {}").format(fmt(MIN_TRADE_AMOUNT_SAT))
    if not wallet.has_lightning():
        return _("Your wallet doesn't support the Lightning Network. Please use a wallet with Lightning Network support.")
    # what we have to pay to the agent to fund the trade
    total_send = amount if payment_direction == TradePaymentDirection.SENDING else bond
    can_send = wallet.lnworker.num_sats_can_send() or 0
    if can_send < total_send:
        return _("You cannot send this amount with your Lightning channels. Please open a larger Lightning channel or "
                 "do a submarine swap in the 'Channels' tab to increase your outgoing liquidity. "
                 "You can send: {}").format(fmt(can_send))
    if payment_direction == TradePaymentDirection.RECEIVING:
        # we will receive roughly the trade amount + bond refund as payout later
        can_receive = wallet.lnworker.num_sats_can_receive() or 0
        if can_receive < amount + bond:
            return _("You cannot receive the trade payout with your Lightning channels. Please do a "
                     "submarine swap in the 'Channels' tab to increase your incoming liquidity. "
                     "You can receive: {}").format(fmt(can_receive))
    return None


def build_new_maker_trade(
    wallet: 'Abstract_Wallet',
    *,
    title: str,
    contract_text: str,
    trade_amount_sat: int,
    bond_sat: int,
    agent_fee_ppm: int,
    payment_direction: TradePaymentDirection,
    agent_pubkey: str,
) -> ClientEscrowTrade:
    contract = TradeContract(
        title=title,
        text=contract_text,
        trade_amount_sat=trade_amount_sat,
        bond_sat=bond_sat,
        agent_fee_ppm=agent_fee_ppm,
        maker_payment_direction=payment_direction,
        payment_protocol=TradePaymentProtocol.BITCOIN_LIGHTNING,
        agent_pubkey=agent_pubkey,
    )
    fallback_address = wallet.get_unused_address() or wallet.get_receiving_address()
    return ClientEscrowTrade(
        state=TradeState.WAITING_FOR_TAKER,
        contract=contract,
        is_maker=True,
        onchain_fallback_address=fallback_address,
    )


def maker_funding_narrative(trade: ClientEscrowTrade, fmt: FormatAmount) -> str:
    """What the maker pays/receives, shown when reviewing the trade creation."""
    contract = trade.contract
    if trade.payment_direction == TradePaymentDirection.SENDING:
        return _("You send the trade payment of {}.").format(fmt(contract.trade_amount_sat))
    return _("You lock a bond of {} and will receive {} when the trade succeeds.").format(
        fmt(contract.bond_sat), fmt(contract.payout_amount_sat()))


def taker_funding_narrative(trade: ClientEscrowTrade, fmt: FormatAmount) -> str:
    """What the taker pays/receives, shown when reviewing a fetched trade."""
    contract = trade.contract
    if trade.payment_direction == TradePaymentDirection.SENDING:
        return _("You pay the trade amount of {} to the escrow agent now. The counterparty "
                 "receives it when both of you confirm the successful trade.").format(
            fmt(contract.trade_amount_sat))
    return _("You lock a bond of {} with the escrow agent now. When both of you confirm "
             "the successful trade you receive {} (trade amount minus agent fee plus "
             "bond refund).").format(fmt(contract.bond_sat), fmt(contract.payout_amount_sat()))


# ---------- confirmation questions and result messages of the trade actions ----------

def question_confirm_success() -> str:
    return _("Confirm that this trade completed successfully? "
             "Once both parties confirm, the agent pays out and "
             "this cannot be undone.")


def question_cancel(state: TradeState) -> str:
    if state == TradeState.WAITING_FOR_TAKER:
        return _("Cancel this trade and get your funding back?")
    return _("Request to cancel this trade? The trade is cancelled and everyone "
             "gets their funds back once both parties request cancellation.")


def question_request_mediation() -> str:
    return _("Put this trade into mediation? You will have to contact the "
             "escrow agent out of band so they can decide the trade outcome. "
             "Check the agent profile for contact information.")


def msg_confirmation_sent() -> str:
    return _("Confirmation sent.")


def msg_cancellation_requested() -> str:
    return _("Cancellation requested.")


def msg_mediation_requested() -> str:
    return _("Mediation requested. Contact the agent to provide your evidence.")


def msg_payout_claim_submitted() -> str:
    return _("Payout claim submitted. The agent will now try to pay your invoice.")
