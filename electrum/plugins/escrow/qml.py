import asyncio
import base64
import sys
from datetime import datetime
from typing import TYPE_CHECKING, Optional, List, Tuple, Union

from PyQt6.QtCore import (
    Qt, QObject, QAbstractListModel, QModelIndex, pyqtSignal, pyqtProperty, pyqtSlot,
)

from electrum.i18n import _
from electrum.logging import Logger
from electrum.plugin import hook
from electrum.util import UserFacingException, get_asyncio_loop
from electrum.wizard import WizardViewState
from electrum.gui.common_qt.util import QtEventListener, qt_event_listener
from electrum.gui.qml.auth import AuthMixin, auth_protect
from electrum.gui.qml.qetypes import QEAmount
from electrum.gui.qml.qewallet import QEWallet
from electrum.gui.qml.qewizard import QEAbstractWizard

from .agent import EscrowAgent, AgentEscrowTrade
from .client import EscrowClient, ClientEscrowTrade
from .common_qt import (
    fetch_url_bytes_async, format_fee_ppm, help_text, plugin_status_warning,
    get_trade_validation_error, build_new_maker_trade,
    maker_funding_narrative, taker_funding_narrative,
    question_confirm_success, question_cancel, question_request_mediation,
    msg_confirmation_sent, msg_cancellation_requested, msg_mediation_requested,
    msg_payout_claim_submitted,
)
from .constants import (
    MAX_TITLE_LEN_CHARS, MAX_CONTRACT_LEN_CHARS, MIN_TRADE_AMOUNT_SAT, MAX_AGENT_FEE_PPM,
    TradePaymentDirection, TradeState,
)
from .escrow import EscrowPlugin
from .escrow_worker import EscrowAgentProfile
from .wizard import EscrowWizard

if TYPE_CHECKING:
    from electrum.invoices import Invoice
    from electrum.wallet import Abstract_Wallet
    from electrum.gui.qml import ElectrumQmlApplication


def _format_date(timestamp) -> str:
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')


def _image_mime_type(data: bytes) -> str:
    if data.startswith(b'\x89PNG'):
        return 'image/png'
    if data.startswith(b'\xff\xd8'):
        return 'image/jpeg'
    if data.startswith(b'GIF8'):
        return 'image/gif'
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        return 'image/webp'
    return 'image/png'


class QETradeListModel(QAbstractListModel):
    _ROLE_NAMES = ('tradeid', 'title', 'date', 'amount', 'statetext', 'stateint')
    _ROLE_KEYS = range(Qt.ItemDataRole.UserRole, Qt.ItemDataRole.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))

    countChanged = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._trades = []  # type: List[dict]

    def rowCount(self, index=QModelIndex()):
        return len(self._trades)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        trade = self._trades[index.row()]
        role_index = role - Qt.ItemDataRole.UserRole
        value = trade[self._ROLE_NAMES[role_index]]
        if isinstance(value, (bool, list, int, str, QEAmount)) or value is None:
            return value
        return str(value)

    @pyqtProperty(int, notify=countChanged)
    def count(self):
        return len(self._trades)

    def set_trades(self, trades: List[Tuple[str, Union[ClientEscrowTrade, AgentEscrowTrade]]]):
        self.beginResetModel()
        self._trades = [{
            'tradeid': trade_id,
            'title': trade.contract.title,
            'date': _format_date(trade.creation_timestamp),
            'amount': QEAmount(amount_sat=trade.contract.trade_amount_sat),
            'statetext': str(trade.state),
            'stateint': int(trade.state),
        } for trade_id, trade in trades]
        self.endResetModel()
        self.countChanged.emit()


class QEEscrowTradeWizard(EscrowWizard, QEAbstractWizard):
    """Drives the QML trade wizards (create trade / take trade) with the shared
    EscrowWizard navmap. The QML components live in the plugin's qml/ directory,
    referenced relative to gui/qml/components/wizard/ (like the trustedcoin plugin)."""

    def __init__(self, plugin: 'EscrowPlugin', parent=None):
        EscrowWizard.__init__(self, plugin)
        QEAbstractWizard.__init__(self, parent)
        self.navmap_merge({
            'create_trade': {'gui': '../../../../plugins/escrow/qml/WCCreateTrade'},
            'select_escrow_agent': {'gui': '../../../../plugins/escrow/qml/WCSelectEscrowAgent'},
            'confirm_create': {'gui': '../../../../plugins/escrow/qml/WCConfirmCreate'},
            'show_postbox': {'gui': '../../../../plugins/escrow/qml/WCShowPostbox'},
            'fetch_trade': {'gui': '../../../../plugins/escrow/qml/WCFetchTrade'},
            'accept_trade': {'gui': '../../../../plugins/escrow/qml/WCAcceptTrade'},
        })

    @pyqtSlot(str, result=str)
    def startWizardFrom(self, view: str) -> str:
        self.start(WizardViewState(view, {}, {}))
        return self._current.view


class EscrowQmlBridge(AuthMixin, QObject, QtEventListener, Logger):
    """Exposes the escrow plugin to the QML GUI. The QML GUI shows a single wallet
    at a time, so the bridge tracks one current wallet, set via load()."""

    stateChanged = pyqtSignal()
    busyChanged = pyqtSignal()
    channelsUpdated = pyqtSignal()
    tradeRegistered = pyqtSignal('QVariantMap')
    tradeRegisterFailed = pyqtSignal(str)
    fundingDone = pyqtSignal()
    fundingFailed = pyqtSignal(str)
    postboxCreated = pyqtSignal(str)
    postboxFailed = pyqtSignal(str)
    tradeFetched = pyqtSignal('QVariantMap')
    tradeFetchFailed = pyqtSignal(str)
    tradeAccepted = pyqtSignal()
    tradeAcceptFailed = pyqtSignal(str)
    paymentAuthRejected = pyqtSignal()
    tradeActionDone = pyqtSignal(str, str, str, arguments=['tradeId', 'action', 'message'])
    tradeActionFailed = pyqtSignal(str, str, str, arguments=['tradeId', 'action', 'message'])
    backupRestoreDone = pyqtSignal(int, arguments=['numRestored'])
    backupRestoreFailed = pyqtSignal(str)
    avatarReceived = pyqtSignal(str, str, arguments=['url', 'dataUrl'])
    # internal: marshals coroutine results from the asyncio thread to the Qt thread
    _coroDone = pyqtSignal(object, object)

    def __init__(self, plugin: 'Plugin'):
        QObject.__init__(self)
        Logger.__init__(self)
        self._plugin = plugin
        self._app = None  # type: Optional['ElectrumQmlApplication']
        self._wallet = None  # type: Optional[QEWallet]
        self._loaded = False
        self._busy_count = 0
        # pending state of the create/take trade wizard flows. the generation
        # counter invalidates the callbacks of superseded flows, so a late
        # response can never get paired with the pending state of a newer flow
        self._pending_generation = 0
        self._pending_fut = None  # type: Optional[asyncio.Future]
        self._pending_trade = None  # type: Optional[ClientEscrowTrade]
        self._pending_trade_id = None  # type: Optional[str]
        self._pending_invoice: Optional['Invoice'] = None
        self._pending_funded = False
        self._trades_model = QETradeListModel(self)
        self._wizard = QEEscrowTradeWizard(plugin, self)
        self._coroDone.connect(self._on_coro_done)
        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())

    def set_app(self, app: 'ElectrumQmlApplication'):
        self._app = app

    def on_destroy(self):
        self.deactivate()

    def deactivate(self):
        """Detaches the bridge from events and invalidates the pending wizard flow.
        Called when the plugin gets disabled (a re-enable creates a fresh bridge)
        and on destruction. In-flight payment coroutines are deliberately NOT
        cancelled, their completion callbacks must still save the trade."""
        self.unregister_callbacks()
        self._new_pending_flow()
        self._wallet = None
        self._loaded = False

    @qt_event_listener
    def on_event_escrow_trades_updated(self, wallet):
        if self._wallet is None or wallet != self._wallet.wallet:
            return
        self._refresh()

    @qt_event_listener
    def on_event_channel(self, wallet, _channel):
        if self._wallet is None or wallet != self._wallet.wallet:
            return
        self.channelsUpdated.emit()

    # ---------- generic helpers ----------

    def _fmt(self, amount_sat: int) -> str:
        """Formats with both bitcoin and fiat amounts, like the Qt GUI."""
        text = self._plugin.config.format_amount_and_units(amount_sat)
        fx = self._app.daemon.daemon.fx if self._app else None
        fiat = fx.format_amount_and_units(amount_sat) if fx else None
        if text and fiat:
            text += f' ({fiat})'
        return text

    def _on_coro_done(self, callback, payload):
        # runs on the Qt thread (queued connection, emitted from the asyncio thread)
        callback(payload)

    def _run_coro(self, coro, *, on_success, on_error, track_busy: bool = True):
        """Runs a coroutine on the daemon asyncio loop, callbacks happen on the Qt
        thread. on_error receives an exc_info tuple. Concurrent coroutines don't
        delay each other's callbacks, and nothing cancels them behind their back
        (important for payment coroutines)."""
        if track_busy:
            self._busy_count += 1
            self.busyChanged.emit()
        def _finish(success: bool, payload):
            if track_busy:
                self._busy_count -= 1
                self.busyChanged.emit()
            (on_success if success else on_error)(payload)
        def _on_done(f):
            # runs on the asyncio thread, marshal the result to the Qt thread
            try:
                payload = f.result()
                success = True
            except BaseException:  # including CancelledError
                payload = sys.exc_info()
                success = False
            try:
                self._coroDone.emit(lambda p, s=success: _finish(s, p), payload)
            except RuntimeError:
                pass  # the bridge was deleted (app shutdown)
        fut = asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())
        fut.add_done_callback(_on_done)
        return fut

    def _abstract_wallet(self) -> Optional['Abstract_Wallet']:
        return self._wallet.wallet if self._wallet else None

    def _client_worker(self) -> EscrowClient:
        wallet = self._abstract_wallet()
        if wallet is None:
            raise UserFacingException(_("No wallet loaded in the escrow plugin."))
        return self._plugin.get_escrow_worker(wallet, worker_type=EscrowClient)

    def _agent_worker(self) -> EscrowAgent:
        wallet = self._abstract_wallet()
        if wallet is None:
            raise UserFacingException(_("No wallet loaded in the escrow plugin."))
        return self._plugin.get_escrow_worker(wallet, worker_type=EscrowAgent)

    def _refresh(self):
        wallet = self._abstract_wallet()
        worker = self._plugin.get_worker_for_wallet(wallet) if wallet else None
        trades = []
        if worker is not None:
            trades = sorted(
                worker.get_trades().items(),
                key=lambda t: t[1].creation_timestamp, reverse=True)
        self._trades_model.set_trades(trades)
        self.stateChanged.emit()

    # ---------- static properties ----------

    @pyqtProperty(str)
    def loader(self):
        return 'main.qml'

    @pyqtProperty(QObject, constant=True)
    def tradesModel(self):
        return self._trades_model

    @pyqtProperty(QObject, constant=True)
    def wizard(self):
        return self._wizard

    @pyqtProperty('qint64', constant=True)
    def minTradeAmountSat(self):
        return MIN_TRADE_AMOUNT_SAT

    @pyqtProperty(int, constant=True)
    def maxAgentFeePpm(self):
        return MAX_AGENT_FEE_PPM

    @pyqtProperty(int, constant=True)
    def titleMaxLength(self):
        return MAX_TITLE_LEN_CHARS

    @pyqtProperty(int, constant=True)
    def contractMaxLength(self):
        return MAX_CONTRACT_LEN_CHARS

    @pyqtProperty(str, constant=True)
    def helpText(self):
        return help_text()

    # ---------- wallet state properties ----------

    @pyqtProperty(bool, notify=busyChanged)
    def busy(self):
        return self._busy_count > 0

    @pyqtProperty(bool, notify=stateChanged)
    def loaded(self):
        return self._loaded

    @pyqtProperty(bool, notify=stateChanged)
    def isAgent(self):
        wallet = self._abstract_wallet()
        return self._plugin.has_agent_worker(wallet) if wallet else False

    @pyqtProperty(bool, notify=stateChanged)
    def agentModeEnabled(self):
        wallet = self._abstract_wallet()
        return self._plugin.is_escrow_agent(wallet) if wallet else False

    @pyqtProperty(bool, notify=stateChanged)
    def canTrade(self):
        wallet = self._abstract_wallet()
        return wallet.has_lightning() if wallet else False

    @pyqtProperty(str, notify=stateChanged)
    def agentPubkey(self):
        wallet = self._abstract_wallet()
        worker = self._plugin.get_worker_for_wallet(wallet) if wallet else None
        if isinstance(worker, EscrowAgent):
            return worker.get_identity_pubkey()
        return ''

    @pyqtProperty(str, notify=stateChanged)
    def notificationText(self):
        return self._compute_notification()[0]

    @pyqtProperty(bool, notify=stateChanged)
    def notificationCritical(self):
        return self._compute_notification()[1]

    def _compute_notification(self) -> Tuple[str, bool]:
        wallet = self._abstract_wallet()
        if wallet is None or not self._loaded:
            return '', False
        msg, critical = plugin_status_warning(self._plugin, wallet)
        return msg or '', critical

    # ---------- lifecycle ----------

    @pyqtSlot(QEWallet, result=bool)
    def load(self, qewallet: QEWallet) -> bool:
        """Binds the bridge to the given wallet and ensures the plugin loaded it.
        Called by the QML page before using any of the other slots."""
        if qewallet is None:
            return False
        self._wallet = qewallet
        self._plugin._load_wallet(qewallet.wallet)
        self._loaded = self._plugin.get_worker_for_wallet(qewallet.wallet) is not None
        self._refresh()
        return self._loaded

    @pyqtSlot(bool, result=str)
    def setAgentMode(self, enabled: bool) -> str:
        wallet = self._abstract_wallet()
        if wallet is None:
            return _("No wallet loaded in the escrow plugin.")
        try:
            self._plugin.set_escrow_agent_mode(enabled=enabled, wallet=wallet)
        except UserFacingException as e:
            self.stateChanged.emit()  # let the GUI revert its toggle
            return str(e)
        self._refresh()
        return ''

    # ---------- escrow agent management (client) ----------

    @pyqtSlot(result='QVariantList')
    def getAgents(self):
        try:
            worker = self._client_worker()
        except UserFacingException:
            return []
        agents = []
        infos = worker.get_escrow_agent_infos()
        for pubkey in worker.get_escrow_agents():
            info = infos.get(pubkey)
            profile = info.profile_info if info else None
            last_seen = info.last_seen_minutes() if info else None
            agents.append({
                'pubkey': pubkey,
                'name': profile.name if profile and profile.name else pubkey[:12],
                'hasInfo': bool(profile),
                'about': profile.about if profile else '',
                'website': profile.website if profile and profile.website
                           and profile.website.startswith('https://') else '',
                'feePpm': profile.service_fee_ppm if profile else 0,
                'feeText': format_fee_ppm(profile.service_fee_ppm) if profile else '',
                'inboundText': self._fmt(info.inbound_liquidity)
                               if info and info.inbound_liquidity is not None else '',
                'outboundText': self._fmt(info.outbound_liquidity)
                                if info and info.outbound_liquidity is not None else '',
                'lastSeenMinutes': last_seen if last_seen is not None else -1,
                'languagesText': ', '.join(profile.languages) if profile and profile.languages else '',
                'gpg': profile.gpg_fingerprint if profile and profile.gpg_fingerprint else '',
                'picture': profile.picture if profile and profile.picture
                           and profile.picture.startswith('https://') else '',
                'stale': last_seen is None or last_seen > 120,
            })
        return agents

    @pyqtSlot(str, result=str)
    def addAgent(self, pubkey: str) -> str:
        pubkey = pubkey.strip().lower()
        try:
            if len(pubkey) != 64:
                raise ValueError
            bytes.fromhex(pubkey)
        except ValueError:
            return _("Invalid public key")
        try:
            self._client_worker().add_escrow_agent(pubkey)
        except UserFacingException as e:
            return str(e)
        return ''

    @pyqtSlot(str)
    def deleteAgent(self, pubkey: str):
        try:
            self._client_worker().delete_escrow_agent(pubkey)
        except UserFacingException:
            pass

    @pyqtSlot(str)
    def fetchAvatar(self, url: str):
        if not url or not url.startswith('https://'):
            return
        def on_success(data):
            if not data:
                return
            mime = _image_mime_type(data)
            data_url = f"data:{mime};base64,{base64.b64encode(data).decode()}"
            self.avatarReceived.emit(url, data_url)
        def on_error(exc_info):
            self.logger.info(f"could not fetch avatar: {exc_info[1]!r}")
        self._run_coro(
            fetch_url_bytes_async(url), on_success=on_success, on_error=on_error,
            track_busy=False)

    # ---------- create trade wizard flow ----------

    def _new_pending_flow(self) -> int:
        """Invalidates the previous pending wizard flow (late callbacks check the
        generation) and cancels its in-flight register/fetch request."""
        self._pending_generation += 1
        if self._pending_fut is not None:
            self._pending_fut.cancel()
            self._pending_fut = None
        self._pending_trade = None
        self._pending_trade_id = None
        self._pending_invoice = None
        self._pending_funded = False
        return self._pending_generation

    @pyqtSlot()
    def cancelPendingFlow(self):
        """Called when a trade wizard closes: invalidates and cancels any pending
        register/fetch request. In-flight payments are NOT cancelled, their
        completion callbacks still save the trade."""
        self._new_pending_flow()

    @pyqtSlot('QVariantMap', result=str)
    def validateTradeParams(self, params) -> str:
        """Returns a warning for the create trade form, mirroring the Qt wizard
        validation. Empty string if there is nothing to complain about."""
        wallet = self._abstract_wallet()
        if wallet is None:
            return ''
        error = get_trade_validation_error(
            wallet,
            trade_amount_sat=int(params.get('trade_amount_sat') or 0),
            bond_sat=int(params.get('bond_sat') or 0),
            payment_direction=TradePaymentDirection(int(params.get('payment_direction') or 0)),
            fmt=self._fmt,
        )
        return error or ''

    @pyqtSlot('QVariantMap')
    def registerTrade(self, params):
        """Requests trade registration from the agent (first step of the maker flow)."""
        generation = self._new_pending_flow()
        try:
            wallet = self._abstract_wallet()
            worker = self._client_worker()
            trade = build_new_maker_trade(
                wallet,
                title=params['title'],
                contract_text=params['contract_text'],
                trade_amount_sat=int(params['trade_amount_sat']),
                bond_sat=int(params['bond_sat']),
                agent_fee_ppm=int(params['agent_fee_ppm']),
                payment_direction=TradePaymentDirection(int(params['payment_direction'])),
                agent_pubkey=params['escrow_agent_pubkey'],
            )
        except Exception as e:
            self.tradeRegisterFailed.emit(str(e))
            return
        self._pending_trade = trade

        def on_success(result):
            if generation != self._pending_generation:
                return  # a newer flow superseded this request
            self._pending_trade_id, self._pending_invoice = result
            self.tradeRegistered.emit(self._maker_trade_summary())
        def on_error(exc_info):
            if generation != self._pending_generation:
                return
            self.tradeRegisterFailed.emit(str(exc_info[1]))
        self._pending_fut = self._run_coro(
            worker.request_register_escrow(trade), on_success=on_success, on_error=on_error)

    def _trade_summary_base(self, trade: ClientEscrowTrade, trade_id: Optional[str]) -> dict:
        contract = trade.contract
        return {
            'tradeId': trade_id or '',
            'title': contract.title,
            'amountText': self._fmt(contract.trade_amount_sat),
            'bondText': self._fmt(contract.bond_sat),
            'feeText': f"{format_fee_ppm(contract.agent_fee_ppm)} ({self._fmt(contract.agent_fee_sat())})",
            'agentPubkey': contract.agent_pubkey,
            'contractText': contract.text,
        }

    def _maker_trade_summary(self) -> dict:
        trade = self._pending_trade
        summary = self._trade_summary_base(trade, self._pending_trade_id)
        amount_to_pay = self._pending_invoice.get_amount_sat() if self._pending_invoice else 0
        summary.update({
            'narrative': maker_funding_narrative(trade, self._fmt),
            'hasPayment': self._pending_invoice is not None,
            'amountToPayText': self._fmt(amount_to_pay) if amount_to_pay else '',
        })
        return summary

    def _taker_trade_summary(self) -> dict:
        trade = self._pending_trade
        summary = self._trade_summary_base(trade, self._pending_trade_id)
        amount_to_pay = trade.funding_amount_sat
        summary.update({
            'narrative': taker_funding_narrative(trade, self._fmt),
            'hasPayment': amount_to_pay > 0,
            'amountToPayText': self._fmt(amount_to_pay) if amount_to_pay > 0 else '',
        })
        return summary

    @pyqtSlot()
    @auth_protect(method='payment_auth', message=_('Lock the escrow trade funding?'), reject='_payment_auth_rejected')
    def lockFunding(self):
        """Pays the funding invoice of the pending registered trade and saves the trade."""
        generation = self._pending_generation
        trade, trade_id, invoice = self._pending_trade, self._pending_trade_id, self._pending_invoice
        wallet = self._abstract_wallet()
        if trade is None or trade_id is None or wallet is None:
            self.fundingFailed.emit(_("No pending trade."))
            return
        if self._pending_funded:
            self.fundingDone.emit()
            return
        try:
            worker = self._client_worker()
        except UserFacingException as e:
            self.fundingFailed.emit(str(e))
            return

        def on_payment_success():
            # the payment completed, the trade must get saved even if the
            # wizard was closed in the meantime
            worker.save_new_trade(trade_id, trade)
            if generation == self._pending_generation:
                self._pending_funded = True
                self._pending_invoice = None
                # only the flow that started the payment gets the signal, it
                # must not drive the page of an unrelated newer wizard
                self.fundingDone.emit()

        if invoice is None:
            # nothing to pay from the maker side (e.g. zero bond)
            on_payment_success()
            return

        async def pay_coro():
            wallet.save_invoice(invoice)
            payment_success, log = await wallet.lnworker.pay_invoice(invoice)
            if not payment_success:
                self.logger.debug(f"Payment {log=}")
                raise UserFacingException(_("Payment failed"))

        def on_success(_result):
            on_payment_success()
        def on_error(exc_info):
            try:
                wallet.delete_invoice(invoice.get_id())
            except Exception:
                pass
            if generation == self._pending_generation:
                self.fundingFailed.emit(str(exc_info[1]))
        # not busy-tracked: the wizard page shows its own progress, and a payment
        # surviving a closed wizard must not spin the main page indefinitely
        self._run_coro(pay_coro(), on_success=on_success, on_error=on_error, track_busy=False)

    def _payment_auth_rejected(self):
        self.paymentAuthRejected.emit()

    @pyqtSlot()
    def createPostbox(self):
        generation = self._pending_generation
        trade_id = self._pending_trade_id
        if trade_id is None:
            self.postboxFailed.emit(_("No pending trade."))
            return
        try:
            worker = self._client_worker()
        except UserFacingException as e:
            self.postboxFailed.emit(str(e))
            return

        async def create_coro():
            # run on the asyncio thread, the postbox creation writes to the wallet db
            return worker.create_trade_postbox(trade_id)

        def on_success(key):
            if generation == self._pending_generation:
                self.postboxCreated.emit(key)
        def on_error(exc_info):
            if generation == self._pending_generation:
                self.postboxFailed.emit(str(exc_info[1]))
        self._run_coro(create_coro(), on_success=on_success, on_error=on_error)

    # ---------- take trade wizard flow ----------

    @pyqtSlot(str)
    def fetchTrade(self, code: str):
        code = code.strip()
        generation = self._new_pending_flow()
        try:
            worker = self._client_worker()
        except UserFacingException as e:
            self.tradeFetchFailed.emit(str(e))
            return

        def on_success(result):
            if generation != self._pending_generation:
                return  # a newer flow superseded this request
            if not result:
                self.tradeFetchFailed.emit(_("Could not find the trade. Check the code and your nostr relays."))
                return
            self._pending_trade, self._pending_trade_id = result
            self.tradeFetched.emit(self._taker_trade_summary())
        def on_error(exc_info):
            if generation != self._pending_generation:
                return
            self.tradeFetchFailed.emit(str(exc_info[1]))
        self._pending_fut = self._run_coro(
            worker.create_trade_from_postbox(code), on_success=on_success, on_error=on_error)

    @pyqtSlot()
    @auth_protect(method='payment_auth', message=_('Accept the trade and pay the escrow funding?'), reject='_payment_auth_rejected')
    def acceptTrade(self):
        generation = self._pending_generation
        trade, trade_id = self._pending_trade, self._pending_trade_id
        wallet = self._abstract_wallet()
        if trade is None or trade_id is None or wallet is None:
            self.tradeAcceptFailed.emit(_("No pending trade."))
            return
        try:
            worker = self._client_worker()
        except UserFacingException as e:
            self.tradeAcceptFailed.emit(str(e))
            return
        amount_to_pay = trade.funding_amount_sat
        if amount_to_pay > 0:
            can_send = int(wallet.lnworker.num_sats_can_send() or 0) if wallet.has_lightning() else 0
            if can_send < amount_to_pay:
                self.tradeAcceptFailed.emit(
                    _("You cannot send the funding amount of {} with your Lightning channels. "
                      "Increase your outgoing liquidity first.").format(self._fmt(amount_to_pay)))
                return
        saved_invoice = {}  # so the error path can remove the unpaid invoice again

        async def do_accept():
            # 1. Request accept from agent
            invoice = await worker.request_accept_escrow(trade, trade_id)
            # 2. Pay the funding invoice (if there is something to pay)
            if invoice is not None:
                if generation != self._pending_generation:
                    # the wizard was closed during the agent roundtrip: abort
                    # before any money moves (the agent-side request expires)
                    raise UserFacingException(_("The wizard was closed before the funding payment started."))
                saved_invoice['invoice'] = invoice
                wallet.save_invoice(invoice)
                payment_success, log = await wallet.lnworker.pay_invoice(invoice)
                if not payment_success:
                    raise UserFacingException(_("Payment failed"))

        def on_success(_result):
            # the trade was accepted (and paid), it must get saved even if the
            # wizard was closed in the meantime
            worker.save_new_trade(trade_id, trade)
            if generation == self._pending_generation:
                self.tradeAccepted.emit()
        def on_error(exc_info):
            invoice = saved_invoice.get('invoice')
            if invoice is not None:
                try:
                    wallet.delete_invoice(invoice.get_id())
                except Exception:
                    pass
            if generation == self._pending_generation:
                self.tradeAcceptFailed.emit(str(exc_info[1]))
        # not busy-tracked: the wizard page shows its own progress, and a payment
        # surviving a closed wizard must not spin the main page indefinitely
        self._run_coro(do_accept(), on_success=on_success, on_error=on_error, track_busy=False)

    # ---------- trade details ----------

    @pyqtSlot(str, result='QVariantMap')
    def getTradeDetails(self, trade_id: str):
        wallet = self._abstract_wallet()
        worker = self._plugin.get_worker_for_wallet(wallet) if wallet else None
        trade = worker.get_trades().get(trade_id) if worker else None
        if trade is None:
            return {'found': False}
        contract = trade.contract
        state = trade.state
        details = {
            'found': True,
            'isAgent': isinstance(trade, AgentEscrowTrade),
            'tradeId': trade_id,
            'title': contract.title,
            'stateText': str(state),
            'dateText': _format_date(trade.creation_timestamp),
            'amountText': self._fmt(contract.trade_amount_sat),
            'bondText': self._fmt(contract.bond_sat),
            'feeText': f"{format_fee_ppm(contract.agent_fee_ppm)} ({self._fmt(contract.agent_fee_sat())})",
            'contractText': contract.text,
            'showResolve': False,
            'showSync': False,
            'showCopyPostbox': False,
            'showConfirm': False,
            'showCancel': False,
            'showMediate': False,
            'showClaim': False,
            'autoSync': False,
            'postboxKey': '',
        }
        if isinstance(trade, ClientEscrowTrade):
            details.update(self._client_trade_details(trade))
        elif isinstance(trade, AgentEscrowTrade):
            details.update(self._agent_trade_details(trade))
        return details

    def _client_trade_details(self, trade: ClientEscrowTrade) -> dict:
        contract = trade.contract
        state = trade.state
        payout_text = ''
        if trade.payout_due_sat:
            paid_str = _('paid') if trade.payout_paid else _('pending')
            payout_text = f"{self._fmt(trade.payout_due_sat)} ({paid_str})"
        return {
            'agentPubkey': contract.agent_pubkey,
            'roleText': _('Maker') if trade.is_maker else _('Taker'),
            'directionText': _('You send the trade amount')
                             if trade.payment_direction == TradePaymentDirection.SENDING
                             else _('You receive the trade amount'),
            'payoutText': payout_text,
            'mediationHint': state == TradeState.MEDIATION,
            'postboxKey': trade.postbox_key or '',
            'showSync': trade.private_key is not None,
            'showCopyPostbox': bool(trade.postbox_key) and state == TradeState.WAITING_FOR_TAKER,
            'showConfirm': state == TradeState.ONGOING,
            'showCancel': state in (TradeState.WAITING_FOR_TAKER, TradeState.ONGOING, TradeState.MEDIATION),
            'cancelLabel': _("Cancel Trade") if state == TradeState.WAITING_FOR_TAKER
                           else _("Request Cancellation"),
            'cancelQuestion': question_cancel(state),
            'showMediate': state == TradeState.ONGOING,
            'showClaim': state.is_final() and bool(trade.payout_due_sat) and not trade.payout_paid,
            'autoSync': trade.private_key is not None and not EscrowClient.is_trade_settled(trade),
            'confirmQuestion': question_confirm_success(),
            'mediateQuestion': question_request_mediation(),
        }

    def _agent_trade_details(self, trade: AgentEscrowTrade) -> dict:
        contract = trade.contract
        participants = trade.trade_participants
        participant_list = [{
            'roleText': _('Maker'),
            'pubkey': participants.maker.pubkey,
            'statusText': self._participant_status(participants.maker),
        }]
        if participants.taker:
            participant_list.append({
                'roleText': _('Taker'),
                'pubkey': participants.taker.pubkey,
                'statusText': self._participant_status(participants.taker),
            })
        pot = contract.pot_sat()
        maker_funding = contract.funding_amount_sat(contract.maker_payment_direction)
        maker_is_sender = contract.maker_payment_direction == TradePaymentDirection.SENDING
        return {
            'participants': participant_list,
            'showResolve': trade.state == TradeState.MEDIATION,
            'potSat': pot,
            'potText': self._fmt(pot),
            # default suggestion: everyone gets back what they paid (like a cancellation)
            'makerDefaultSat': maker_funding,
            'takerDefaultSat': pot - maker_funding,
            'makerRoleText': _('sender') if maker_is_sender else _('receiver'),
            'takerRoleText': _('receiver') if maker_is_sender else _('sender'),
        }

    def _participant_status(self, participant) -> str:
        flags = []
        if participant.confirmed:
            flags.append(_('confirmed'))
        if participant.cancel_requested:
            flags.append(_('requested cancellation'))
        if participant.payout_due_sat:
            paid_str = _('paid') if participant.payout_paid else _('pending')
            flags.append(_('payout {} ({})').format(self._fmt(participant.payout_due_sat), paid_str))
        if not flags:
            flags.append(_('no action yet'))
        return ', '.join(flags)

    # ---------- trade actions (client) ----------

    def _run_trade_action(self, action: str, trade_id: str, coro, success_message: str):
        def on_success(_result):
            self.tradeActionDone.emit(trade_id, action, success_message)
        def on_error(exc_info):
            self.tradeActionFailed.emit(trade_id, action, str(exc_info[1]))
        self._run_coro(coro, on_success=on_success, on_error=on_error)

    @pyqtSlot(str)
    def confirmTrade(self, trade_id: str):
        try:
            worker = self._client_worker()
        except UserFacingException as e:
            self.tradeActionFailed.emit(trade_id, 'confirm', str(e))
            return
        self._run_trade_action(
            'confirm', trade_id, worker.request_collaborative_confirm(trade_id),
            msg_confirmation_sent())

    @pyqtSlot(str)
    def cancelTrade(self, trade_id: str):
        try:
            worker = self._client_worker()
        except UserFacingException as e:
            self.tradeActionFailed.emit(trade_id, 'cancel', str(e))
            return
        self._run_trade_action(
            'cancel', trade_id, worker.request_collaborative_cancel(trade_id),
            msg_cancellation_requested())

    @pyqtSlot(str)
    def requestMediation(self, trade_id: str):
        try:
            worker = self._client_worker()
        except UserFacingException as e:
            self.tradeActionFailed.emit(trade_id, 'mediate', str(e))
            return
        self._run_trade_action(
            'mediate', trade_id, worker.request_mediation(trade_id), msg_mediation_requested())

    @pyqtSlot(str)
    def claimPayout(self, trade_id: str):
        try:
            worker = self._client_worker()
        except UserFacingException as e:
            self.tradeActionFailed.emit(trade_id, 'claim', str(e))
            return
        self._run_trade_action(
            'claim', trade_id, worker.request_claim_payout(trade_id), msg_payout_claim_submitted())

    @pyqtSlot(str)
    def syncTrade(self, trade_id: str):
        try:
            worker = self._client_worker()
        except UserFacingException as e:
            self.tradeActionFailed.emit(trade_id, 'sync', str(e))
            return
        def on_success(_result):
            self.tradeActionDone.emit(trade_id, 'sync', _("Trade state is up to date."))
        def on_error(exc_info):
            self.tradeActionFailed.emit(
                trade_id, 'sync', _("Could not reach the agent: {}").format(exc_info[1]))
        self._run_coro(worker.sync_trade_state(trade_id), on_success=on_success, on_error=on_error)

    # ---------- agent actions ----------

    @pyqtSlot(result='QVariantMap')
    def getProfile(self):
        try:
            worker = self._agent_worker()
        except UserFacingException:
            return {'found': False}
        profile = worker.get_profile()
        if not profile:
            return {'found': False}
        return {
            'found': True,
            'name': profile.name,
            'about': profile.about,
            'languagesText': ', '.join(profile.languages),
            'feePpm': profile.service_fee_ppm,
            'gpg': profile.gpg_fingerprint or '',
            'picture': profile.picture or '',
            'website': profile.website or '',
        }

    @pyqtSlot('QVariantMap', result=str)
    def saveProfile(self, data) -> str:
        try:
            worker = self._agent_worker()
        except UserFacingException as e:
            return str(e)
        languages = [x.strip() for x in str(data.get('languagesText') or '').split(',') if x.strip()]
        profile = EscrowAgentProfile(
            name=str(data.get('name') or '').strip(),
            about=str(data.get('about') or '').strip(),
            languages=languages,
            service_fee_ppm=int(data.get('feePpm') or 0),
            gpg_fingerprint=str(data.get('gpg') or '').strip() or None,
            picture=str(data.get('picture') or '').strip() or None,
            website=str(data.get('website') or '').strip() or None,
        )
        try:
            worker.save_profile(profile)
        except (ValueError, UserFacingException) as e:
            return _("Invalid profile: {}").format(e)
        self._refresh()
        return ''

    @pyqtSlot(str, 'qint64', 'qint64', result=str)
    def resolveMediation(self, trade_id: str, maker_payout_sat, taker_payout_sat) -> str:
        try:
            worker = self._agent_worker()
        except UserFacingException as e:
            return str(e)
        try:
            worker.resolve_mediation(
                trade_id,
                maker_payout_sat=int(maker_payout_sat),
                taker_payout_sat=int(taker_payout_sat),
            )
        except (ValueError, UserFacingException) as e:
            return str(e)
        self._refresh()
        return ''

    # ---------- nostr state backup ----------

    @pyqtSlot()
    def restoreBackup(self):
        wallet = self._abstract_wallet()
        backup_worker = self._plugin.get_backup_worker(wallet) if wallet else None
        if backup_worker is None:
            self.backupRestoreFailed.emit(_("State backups require a wallet with Lightning support."))
            return
        def on_success(num_trades):
            self._refresh()
            self.backupRestoreDone.emit(num_trades)
        def on_error(exc_info):
            self.backupRestoreFailed.emit(str(exc_info[1]))
        self._run_coro(backup_worker.restore_from_nostr(), on_success=on_success, on_error=on_error)


class Plugin(EscrowPlugin):
    def __init__(self, *args):
        EscrowPlugin.__init__(self, *args)
        self.so = EscrowQmlBridge(self)

    @hook
    def init_qml(self, app: 'ElectrumQmlApplication'):
        # the hook fires for all enabled plugins whenever any plugin gets
        # enabled at runtime, so it must be idempotent
        self.so.setParent(app)  # parent in QObject tree, protects from gc
        self.so.set_app(app)

    def on_close(self):
        """Called when the plugin gets disabled. The QML loader item and this
        bridge stay alive (QML may still reference them), but inert; a re-enable
        creates a fresh Plugin, bridge and loader."""
        EscrowPlugin.on_close(self)
        self.so.deactivate()
