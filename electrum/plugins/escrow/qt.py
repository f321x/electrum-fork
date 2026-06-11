import asyncio
import concurrent.futures
import html
from typing import TYPE_CHECKING, Optional, Union
from functools import partial
from enum import Enum
from datetime import datetime

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTreeWidget,
    QTextEdit, QSpinBox, QLineEdit, QToolButton, QGridLayout, QComboBox,
    QInputDialog, QTreeWidgetItem,
)

from electrum.i18n import _
from electrum.logging import Logger
from electrum.plugin import hook
from electrum.network import Network
from electrum.util import (
    make_aiohttp_session, UserFacingException, get_asyncio_loop,
)
from electrum.gui.qt.util import (
    WindowModalDialog, Buttons, OkButton, CancelButton, CloseButton,
    read_QIcon_from_bytes, read_QPixmap_from_bytes, read_QIcon, HelpLabel,
    icon_path, WWLabel, WaitingDialog,
)
from electrum.gui.common_qt.util import TaskThread, QtEventListener, qt_event_listener
from electrum.gui.qt.my_treeview import QMenuWithConfig
from electrum.gui.qt.amountedit import BTCAmountEdit, AmountEdit
from electrum.gui.qt.wizard.wizard import QEAbstractWizard, WizardComponent
from electrum.wizard import WizardViewState
from electrum.invoices import Invoice

from .escrow import EscrowPlugin
from .wizard import EscrowWizard
from .agent import EscrowAgent, AgentEscrowTrade
from .client import EscrowClient, ClientEscrowTrade
from .escrow_worker import TradeContract, EscrowAgentProfile
from .constants import (
    MAX_TITLE_LEN_CHARS, MAX_CONTRACT_LEN_CHARS, MIN_TRADE_AMOUNT_SAT, MAX_AGENT_FEE_PPM,
    TradePaymentProtocol, TradePaymentDirection, TradeState,
)

if TYPE_CHECKING:
    from electrum.gui.qt.main_window import ElectrumWindow
    from electrum.wallet import Abstract_Wallet

MAX_AVATAR_BYTES = 1024 * 1024  # don't fetch arbitrarily large profile pictures


def fetch_url_bytes(url: str) -> Optional[bytes]:
    network = Network.get_instance()
    if not network:
        return None
    async def get_bytes():
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
    return network.run_from_another_thread(get_bytes())


def run_coro_with_dialog(parent, message: str, coro, on_success, on_failure):
    """Runs a coroutine on the asyncio loop while showing a modal waiting dialog."""
    def task():
        fut = asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())
        return fut.result()
    WaitingDialog(parent, message, task, on_success, on_failure)


def format_fee_ppm(fee_ppm: int) -> str:
    return f"{fee_ppm / 10_000:g}%"


class EscrowType(Enum):
    MAKE = 1
    TAKE = 2


class WCCreateTrade(WizardComponent):
    def __init__(self, parent, wizard: 'EscrowWizardDialog'):
        super().__init__(parent, wizard, title=_("Create Trade"))
        self.wizard = wizard

        layout = self.layout()
        assert isinstance(layout, QVBoxLayout), type(layout)
        grid = QGridLayout()
        layout.addLayout(grid)

        # Title
        grid.addWidget(QLabel(_("Title:")), 0, 0)
        self.title_edit = QLineEdit()
        self.title_edit.setMaxLength(MAX_TITLE_LEN_CHARS)
        self.title_edit.setPlaceholderText(_("Enter a short trade description..."))
        self.title_edit.textChanged.connect(self.validate)
        grid.addWidget(self.title_edit, 0, 1, 1, 3)

        # Contract
        grid.addWidget(HelpLabel(
                _("Contract:"),
                _("Specify the conditions of the trade as detailed as possible. In case of a "
                  "conflict the escrow agent will decide the trade outcome based on this contract.")
        ), 1, 0)
        self.contract_edit = QTextEdit()
        self.contract_edit.setMaximumHeight(100)
        self.contract_edit.setPlaceholderText(_("Enter contract details (max {} characters)...").format(MAX_CONTRACT_LEN_CHARS))
        self.contract_edit.textChanged.connect(self._limit_contract_length)
        self.contract_edit.textChanged.connect(self.validate)
        grid.addWidget(self.contract_edit, 1, 1, 1, 3)

        # Trade Amount
        self.direction_cb = QComboBox()
        self.direction_cb.addItems([_("I send"), _("I receive")])
        self.direction_cb.currentIndexChanged.connect(self.validate)
        grid.addWidget(self.direction_cb, 2, 0)

        self.amount_e = BTCAmountEdit(self.wizard.main_window.get_decimal_point)
        self.amount_e.textChanged.connect(self.validate)
        grid.addWidget(self.amount_e, 2, 1)

        fiat_currency = self.wizard.main_window.fx.get_currency if self.wizard.main_window.fx else None
        self.fiat_receive_e = AmountEdit(fiat_currency)
        if not self.wizard.main_window.fx or not self.wizard.main_window.fx.is_enabled():
            self.fiat_receive_e.setVisible(False)
        else:
            self.wizard.main_window.connect_fields(self.amount_e, self.fiat_receive_e)
        grid.addWidget(self.fiat_receive_e, 2, 2)

        # Bond Amount
        grid.addWidget(HelpLabel(
            _("Bond Amount (%):"),
            _("Percentage of the trade amount that the trade participant which receives the main trade payment will lock to the escrow agent. "
              "This ensures both participants have something to lose (skin-in-the-game). "
              "The bond will get refunded in case of a successful trade.")
        ), 3, 0)
        self.bond_percentage_sb = QSpinBox()
        self.bond_percentage_sb.setRange(0, 100)
        self.bond_percentage_sb.setSuffix("%")
        self.bond_percentage_sb.setValue(3)  # default value
        self.bond_percentage_sb.valueChanged.connect(self.validate)
        grid.addWidget(self.bond_percentage_sb, 3, 1)

        grid.setColumnStretch(3, 1)
        grid.setHorizontalSpacing(15)

        self.warning_label = WWLabel('')
        self.warning_label.setStyleSheet("color: red")
        layout.addWidget(self.warning_label)

        layout.addStretch(1)

    def _limit_contract_length(self):
        text = self.contract_edit.toPlainText()
        if len(text) > MAX_CONTRACT_LEN_CHARS:
            self.contract_edit.setPlainText(text[:MAX_CONTRACT_LEN_CHARS])
            cursor = self.contract_edit.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            self.contract_edit.setTextCursor(cursor)

    @property
    def trade_payment_protocol(self) -> TradePaymentProtocol:
        # todo: with onchain support this could be decided by the user or depending on the trade amount
        return TradePaymentProtocol.BITCOIN_LIGHTNING

    @property
    def payment_direction(self) -> TradePaymentDirection:
        return TradePaymentDirection(self.direction_cb.currentIndex())

    @property
    def bond_amount_sat(self) -> int:
        trade_amount = self.amount_e.get_amount() or 0
        return (self.bond_percentage_sb.value() * trade_amount) // 100

    @property
    def total_send_amount(self) -> int:
        """What we have to pay to the agent to fund the trade."""
        if self.payment_direction == TradePaymentDirection.SENDING:
            return self.amount_e.get_amount() or 0
        else:
            return self.bond_amount_sat

    def validate(self):
        title = self.title_edit.text().strip()
        contract = self.contract_edit.toPlainText().strip()
        amount = self.amount_e.get_amount()
        error = self._get_validation_error()
        is_valid = bool(title) and bool(contract) \
            and (amount is not None and amount >= MIN_TRADE_AMOUNT_SAT) and error is None
        self.valid = is_valid
        self.warning_label.setText(error or '')

    def _get_validation_error(self) -> Optional[str]:
        amount = self.amount_e.get_amount()
        if amount and amount < MIN_TRADE_AMOUNT_SAT:
            return _("Trade amount too small. Minimal trade amount: {}").format(
                self.wizard.main_window.format_amount_and_units(MIN_TRADE_AMOUNT_SAT))
        if self.trade_payment_protocol == TradePaymentProtocol.BITCOIN_LIGHTNING:
            return self._get_lightning_liquidity_error()
        return None

    def _get_lightning_liquidity_error(self) -> Optional[str]:
        assert self.trade_payment_protocol == TradePaymentProtocol.BITCOIN_LIGHTNING
        if not self.wizard.main_window.wallet.has_lightning():
            return _("Your wallet doesn't support the Lightning Network. Please use a wallet with Lightning Network support.")
        can_send = self.wizard.main_window.wallet.lnworker.num_sats_can_send() or 0
        if can_send < self.total_send_amount:
            return _("You cannot send this amount with your Lightning channels. Please open a larger Lightning channel or "
                      "do a submarine swap in the 'Channels' tab to increase your outgoing liquidity. "
                      "You can send: {}").format(self.wizard.main_window.format_amount_and_units(can_send))
        if self.payment_direction == TradePaymentDirection.RECEIVING:
            # we will receive roughly the trade amount + bond refund as payout later
            can_receive = self.wizard.main_window.wallet.lnworker.num_sats_can_receive() or 0
            if can_receive < (self.amount_e.get_amount() or 0) + self.bond_amount_sat:
                return _("You cannot receive the trade payout with your Lightning channels. Please do a "
                      "submarine swap in the 'Channels' tab to increase your incoming liquidity. "
                      "You can receive: {}").format(self.wizard.main_window.format_amount_and_units(can_receive))
        return None

    def on_event_channel(self):
        # called by the EscrowWizardDialog callback
        self.validate()

    def apply(self):
        self.wizard_data['title'] = self.title_edit.text().strip()
        self.wizard_data['contract_text'] = self.contract_edit.toPlainText().strip()
        self.wizard_data['trade_amount_sat'] = self.amount_e.get_amount()
        self.wizard_data['bond_sat'] = self.bond_amount_sat
        self.wizard_data['payment_direction'] = self.payment_direction
        self.wizard_data['payment_protocol'] = self.trade_payment_protocol


class WCSelectEscrowAgent(WizardComponent, Logger):
    """
    Trade maker selects escrow agent for this trade from a drop-down menu. Also has the possibility
    add a new escrow agent. Gives details of the escrow agent.
    """
    def __init__(self, parent, wizard: 'EscrowWizardDialog'):
        super().__init__(parent, wizard, title=_("Escrow Agent"))
        assert isinstance(self.wizard, EscrowWizardDialog)
        Logger.__init__(self)
        self.plugin = wizard.plugin
        self.wallet = wizard.main_window.wallet
        self.thread = TaskThread(self, self.on_error)

        layout = self.layout()
        assert isinstance(layout, QVBoxLayout)
        layout.addWidget(QLabel(_("Select trusted Escrow Agent")))

        hbox = QHBoxLayout()
        self.agent_combo = QComboBox()
        self.agent_combo.currentIndexChanged.connect(self.on_agent_selected)
        hbox.addWidget(self.agent_combo, stretch=1)

        add_button = QToolButton()
        add_button.setIcon(read_QIcon("add.png"))
        add_button.setToolTip(_("Add Escrow Agent"))
        add_button.setAutoRaise(True)
        add_button.clicked.connect(self.add_agent)
        hbox.addWidget(add_button)

        del_button = QToolButton()
        del_button.setIcon(read_QIcon("delete.png"))
        del_button.setToolTip(_("Delete Escrow Agent"))
        del_button.setAutoRaise(True)
        del_button.clicked.connect(self.delete_agent)
        hbox.addWidget(del_button)

        layout.addLayout(hbox)

        info_layout = QHBoxLayout()
        self.info_label = QLabel()
        self.info_label.setWordWrap(True)
        self.info_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        info_layout.addWidget(self.info_label, stretch=1)

        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(128, 128)
        self.avatar_label.setStyleSheet("border: 1px solid gray")
        self.avatar_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.avatar_label.setVisible(False)
        info_layout.addWidget(self.avatar_label)

        layout.addLayout(info_layout)

        self.warning_label = WWLabel('')
        self.warning_label.setStyleSheet("color: red")
        layout.addWidget(self.warning_label)

        layout.addStretch(1)

        self.escrow_agent_pubkey = None  # type: Optional[str]
        self.agent_fee_ppm = None  # type: Optional[int]
        self.current_avatar_url = None
        self.valid = False

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_info)
        self.timer.start(1000)

        self.update_combo()

    def update_combo(self):
        current_pubkey = self.escrow_agent_pubkey
        self.agent_combo.blockSignals(True)
        self.agent_combo.clear()

        worker = self.plugin.get_escrow_worker(self.wallet, worker_type=EscrowClient)
        agents = worker.get_escrow_agents()
        infos = worker.get_escrow_agent_infos()

        for pubkey in agents:
            info = infos.get(pubkey)
            name = pubkey[:12]
            if info and info.profile_info and info.profile_info.name:
                name = info.profile_info.name
            self.agent_combo.addItem(name, pubkey)

        if current_pubkey:
            index = self.agent_combo.findData(current_pubkey)
            if index >= 0:
                self.agent_combo.setCurrentIndex(index)
            else:
                self.escrow_agent_pubkey = None

        self.agent_combo.blockSignals(False)

        if self.agent_combo.count() > 0 and not self.escrow_agent_pubkey:
             self.agent_combo.setCurrentIndex(0)
             self.on_agent_selected(0)
        elif self.agent_combo.count() == 0:
             self.escrow_agent_pubkey = None
             self.update_info()

    def on_agent_selected(self, index):
        if index < 0:
            self.escrow_agent_pubkey = None
        else:
            self.escrow_agent_pubkey = self.agent_combo.itemData(index)
        self.update_info()

    def add_agent(self):
        text, ok = QInputDialog.getText(self, _("Add Escrow Agent"), _("Enter Escrow Agent Public Key:"))
        if ok and text:
            pubkey = text.strip().lower()
            try:
                if len(pubkey) != 64:
                    raise ValueError
                bytes.fromhex(pubkey)
            except ValueError:
                self.wizard.show_error(_("Invalid public key"))
                return

            worker = self.plugin.get_escrow_worker(self.wallet, worker_type=EscrowClient)
            worker.add_escrow_agent(pubkey)
            self.escrow_agent_pubkey = pubkey
            self.update_combo()

    def delete_agent(self):
        pubkey = self.escrow_agent_pubkey
        if not pubkey:
            return
        worker = self.plugin.get_escrow_worker(self.wallet, worker_type=EscrowClient)
        worker.delete_escrow_agent(pubkey)
        self.escrow_agent_pubkey = None
        self.update_combo()

    def update_info(self):
        worker = self.plugin.get_escrow_worker(self.wallet, worker_type=EscrowClient)
        agents = worker.get_escrow_agents()
        infos = worker.get_escrow_agent_infos()

        # Update current item text if name changed
        current_index = self.agent_combo.currentIndex()
        if current_index >= 0:
            pubkey = self.agent_combo.itemData(current_index)
            info = infos.get(pubkey)
            if info and info.profile_info and info.profile_info.name:
                current_text = self.agent_combo.itemText(current_index)
                if current_text != info.profile_info.name:
                    self.agent_combo.setItemText(current_index, info.profile_info.name)

        if self.agent_combo.count() != len(agents):
             self.update_combo()

        pubkey = self.escrow_agent_pubkey

        def update_avatar(url):
            if url != self.current_avatar_url:
                self.current_avatar_url = url
                self.fetch_avatar(url)

        if not pubkey:
            self.info_label.setText("")
            self.warning_label.setText("")
            self.valid = False
            self.agent_fee_ppm = None
            update_avatar(None)
            return

        info = infos.get(pubkey)
        if not info or not info.profile_info:
            self.info_label.setText(_("Fetching agent information..."))
            self.warning_label.setText(_("No information available for this agent."))
            self.valid = False
            self.agent_fee_ppm = None
            update_avatar(None)
            return

        profile = info.profile_info
        lines = []
        lines.append(f"<b>{html.escape(profile.name)}</b>")
        if profile.about:
            lines.append(html.escape(profile.about))
        if profile.website and profile.website.startswith("https://"):
            lines.append(html.escape(profile.website))

        lines.append("")
        lines.append(f"<b>{_('Fee')}:</b> {format_fee_ppm(profile.service_fee_ppm)}")

        if info.inbound_liquidity is not None:
            lines.append(f"<b>{_('Inbound Liquidity')}:</b> {self.wizard.main_window.format_amount_and_units(info.inbound_liquidity)}")
        if info.outbound_liquidity is not None:
            lines.append(f"<b>{_('Outbound Liquidity')}:</b> {self.wizard.main_window.format_amount_and_units(info.outbound_liquidity)}")

        last_seen = info.last_seen_minutes()
        if last_seen is not None:
             lines.append(f"<b>{_('Last Seen')}:</b> {last_seen} {_('minutes ago')}")

        if profile.languages:
            lines.append(f"<b>{_('Languages')}:</b> {html.escape(', '.join(profile.languages))}")

        if profile.gpg_fingerprint:
            lines.append(f"<b>{_('GPG')}:</b> {html.escape(profile.gpg_fingerprint)}")

        self.info_label.setText("<br>".join(lines))
        if last_seen is None or last_seen > 120:
            self.warning_label.setText(_("This agent hasn't been seen recently, it might be offline."))
        else:
            self.warning_label.setText("")
        self.agent_fee_ppm = profile.service_fee_ppm
        self.valid = True

        update_avatar(profile.picture)

    def fetch_avatar(self, url):
        if not url or not url.startswith("https://"):
            self.avatar_label.clear()
            self.avatar_label.setVisible(False)
            return

        def do_fetch():
            return fetch_url_bytes(url)

        def on_success(data):
            if self.current_avatar_url != url:
                return
            if data:
                pixmap = read_QPixmap_from_bytes(data)
                if not pixmap.isNull():
                    self.avatar_label.setPixmap(pixmap.scaled(128, 128, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
                    self.avatar_label.setVisible(True)
                    return
            self.avatar_label.clear()
            self.avatar_label.setVisible(False)

        self.thread.add(do_fetch, on_success=on_success)

    def stop(self):
        self.thread.stop()
        self.timer.stop()
        self.logger.debug("WCSelectEscrowAgent tasks stopped")

    def on_error(self, exc_info):
        self.logger.exception("TaskThread error", exc_info=exc_info)

    def validate(self):
        # Validation state is updated in update_info
        pass

    def apply(self):
        self.wizard_data['escrow_agent_pubkey'] = self.escrow_agent_pubkey
        self.wizard_data['agent_fee_ppm'] = self.agent_fee_ppm


class WCConfirmCreate(WizardComponent, Logger):
    """
    1. Requests the escrow from agent by sending the register_escrow rpc.
       -> Wizard is set busy until we received the trade_id + invoice or error responses, or we time out.
    2. If we got an invoice, show all info to the user for review.
    3. If the user clicks 'Lock Funding', show a popup asking for confirmation.
    4. When confirming, the payment to the agent will be initiated.
    5. If the payment was successful we save the trade and the state is waiting for the counterparty.
    Now the counterparty has to accept the trade and pay their funding.
    """
    def __init__(self, parent, wizard: 'EscrowWizardDialog'):
        super().__init__(parent, wizard, title=_("Confirm Trade Creation"))
        Logger.__init__(self)
        self.wizard = wizard
        self.plugin = wizard.plugin
        self.wallet = wizard.main_window.wallet

        layout = self.layout()

        self.info_label = QLabel(_("Requesting trade creation from agent..."))
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setVisible(False)
        layout.addWidget(self.detail_text)

        layout.addStretch(1)

        self.lock_funding_button = QPushButton(_("Lock Funding"))
        self.lock_funding_button.clicked.connect(self.lock_funding)
        self.lock_funding_button.setVisible(False)
        layout.addWidget(self.lock_funding_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.warning_label = WWLabel('')
        self.warning_label.setStyleSheet("color: red")
        layout.addWidget(self.warning_label)

        layout.addStretch(1)

        self.valid = False
        self.busy = True

        self.trade: Optional[ClientEscrowTrade] = None
        self.trade_id: Optional[str] = None
        self.funding_invoice: Optional[Invoice] = None

        self.thread = TaskThread(self, self.on_error)
        self.request_future = None

    def on_ready(self):
        self.request_escrow()

    def request_escrow(self):
        data = self.wizard_data

        contract = TradeContract(
            title=data['title'],
            text=data['contract_text'],
            trade_amount_sat=data['trade_amount_sat'],
            bond_sat=data['bond_sat'],
            agent_fee_ppm=data['agent_fee_ppm'],
            maker_payment_direction=data['payment_direction'],
            payment_protocol=data['payment_protocol'],
            agent_pubkey=data['escrow_agent_pubkey'],
        )

        fallback_address = self.wallet.get_unused_address() or self.wallet.get_receiving_address()

        worker = self.plugin.get_escrow_worker(self.wallet, worker_type=EscrowClient)

        self.trade = ClientEscrowTrade(
            state=TradeState.WAITING_FOR_TAKER,
            contract=contract,
            is_maker=True,
            onchain_fallback_address=fallback_address,
        )

        coro = worker.request_register_escrow(self.trade)
        def do_request():
            self.request_future = asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())
            return self.request_future.result()

        self.thread.add(do_request, on_success=self.on_response)

    def on_response(self, result):
        self.trade_id, self.funding_invoice = result
        self.busy = False
        self.valid = False
        self.update_ui()

    def on_error(self, exc_info):
        self.busy = False
        self.valid = False
        if issubclass(exc_info[0], concurrent.futures.CancelledError):
            return
        self.info_label.setText(_("Error requesting escrow: {}").format(exc_info[1]))
        self.logger.exception("Error requesting escrow", exc_info=exc_info)

    def update_ui(self):
        contract = self.trade.contract
        fmt = self.wizard.main_window.format_amount_and_units

        details = [
            f"<b>{_('Trade ID')}:</b> {html.escape(self.trade_id)}",
            f"<b>{_('Agent')}:</b> {html.escape(contract.agent_pubkey[:16])}...",
            f"<b>{_('Trade amount')}:</b> {fmt(contract.trade_amount_sat)}",
            f"<b>{_('Bond')}:</b> {fmt(contract.bond_sat)}",
            f"<b>{_('Agent fee')}:</b> {format_fee_ppm(contract.agent_fee_ppm)} ({fmt(contract.agent_fee_sat())})",
        ]
        if self.trade.payment_direction == TradePaymentDirection.SENDING:
            details.append(_("You send the trade payment of {}.").format(fmt(contract.trade_amount_sat)))
        else:
            details.append(_("You lock a bond of {} and will receive {} when the trade succeeds.")
                           .format(fmt(contract.bond_sat), fmt(contract.payout_amount_sat())))

        if self.funding_invoice is not None:
            self.info_label.setText(
                _("Trade registered with agent. Please review and confirm to pay the funding invoice.")
            )
            details.append(f"<b>{_('Amount to pay now')}:</b> {fmt(self.funding_invoice.get_amount_sat())}")
            self.lock_funding_button.setText(_("Lock Funding"))
        else:
            self.info_label.setText(
                _("Trade registered with agent. There is nothing to pay from your side.")
            )
            self.lock_funding_button.setText(_("Create Trade"))

        self.detail_text.setHtml("<br>".join(details))
        self.detail_text.setVisible(True)
        self.lock_funding_button.setVisible(True)

    def stop(self):
        if self.request_future:
            self.request_future.cancel()
            self.request_future = None
        self.thread.stop()
        self.logger.debug("WCConfirmCreate stopped")

    def _on_trade_created(self):
        worker = self.plugin.get_escrow_worker(self.wallet, worker_type=EscrowClient)
        worker.save_new_trade(self.trade_id, self.trade)
        self.wizard.show_message(_("Trade created and funded successfully!"))
        self.valid = True
        self.lock_funding_button.setEnabled(False)
        self.lock_funding_button.setText(_("Funding Locked"))

    def lock_funding(self):
        assert self.trade_id

        if self.funding_invoice is None:
            # nothing to pay from the maker side (e.g. zero bond)
            self._on_trade_created()
            return

        invoice = self.funding_invoice
        amount_sat = invoice.get_amount_sat()
        msg = _("Do you want to pay {} to create this trade?").format(
            self.wizard.main_window.format_amount_and_units(amount_sat)
        )
        if not self.wizard.question(msg):
            return

        async def pay_coro():
            self.wallet.save_invoice(invoice)
            payment_success, log = await self.wallet.lnworker.pay_invoice(invoice)
            if not payment_success:
                self.logger.debug(f"Payment {log=}")
                raise UserFacingException(_("Payment failed"))
            return payment_success

        def on_success(_result):
            self._on_trade_created()

        def on_failure(exc_info):
            try:
                self.wallet.delete_invoice(invoice.get_id())
            except Exception:
                pass
            self.wizard.show_error(str(exc_info[1]))

        run_coro_with_dialog(self, _("Paying funding invoice..."), pay_coro(), on_success, on_failure)

    def apply(self):
        if self.trade_id:
            self.wizard_data['trade_id'] = self.trade_id


class WCShowPostbox(WizardComponent, Logger):
    def __init__(self, parent, wizard):
        super().__init__(parent, wizard, title=_("Trade Postbox"))
        Logger.__init__(self)
        self.wizard = wizard
        self.plugin = wizard.plugin
        self.wallet = wizard.main_window.wallet
        self.thread = TaskThread(self, self.on_error)

        layout = self.layout()
        assert isinstance(layout, QVBoxLayout)

        layout.addWidget(HelpLabel(
            _("Trade Postbox Key:"),
            _("Share this key with the trade taker. They need it to fetch the trade contract and accept the trade.")
        ))

        self.key_edit = QTextEdit()
        self.key_edit.setReadOnly(True)
        self.key_edit.setMaximumHeight(100)
        layout.addWidget(self.key_edit)

        self.copy_button = QPushButton(_("Copy to clipboard"))
        self.copy_button.clicked.connect(self.copy_key)
        self.copy_button.setEnabled(False)
        layout.addWidget(self.copy_button, alignment=Qt.AlignmentFlag.AlignLeft)

        self.info_label = QLabel(_("Creating postbox..."))
        layout.addWidget(self.info_label)

        layout.addWidget(WWLabel(_("Send this key to your trading partner over a secure channel. "
                                   "Anyone with this key can see the trade contract and accept the trade.")))

        layout.addStretch(1)

        self.valid = False
        self.busy = True

    def on_ready(self):
        self.create_postbox()

    def create_postbox(self):
        trade_id = self.wizard_data['trade_id']
        worker = self.plugin.get_escrow_worker(self.wallet, worker_type=EscrowClient)

        async def create_coro():
            return worker.create_trade_postbox(trade_id)

        def do_create():
            # run on the asyncio thread, the postbox creation writes to the wallet db
            fut = asyncio.run_coroutine_threadsafe(create_coro(), get_asyncio_loop())
            return fut.result()

        self.thread.add(do_create, on_success=self.on_success)

    def on_success(self, key):
        self.key_edit.setText(key)
        self.info_label.setText("")
        self.copy_button.setEnabled(True)
        self.valid = True
        self.busy = False

    def copy_key(self):
        self.wizard.main_window.do_copy(self.key_edit.toPlainText(), title=_("Postbox Key"))

    def on_error(self, exc_info):
        self.info_label.setText(_("Error creating postbox: {}").format(exc_info[1]))
        self.logger.exception("Error creating postbox", exc_info=exc_info)
        self.busy = False

    def apply(self):
        pass

    def stop(self):
        self.thread.stop()


class WCFetchTrade(WizardComponent, Logger):
    """
    1. Taker enters the postbox key of the trade they got from the maker out of band.
    2. We fetch the trade contract from nostr relays.
    3. The taker reviews the trade in the next step.
    """
    def __init__(self, parent, wizard):
        super().__init__(parent, wizard, title=_("Fetch Trade"))
        Logger.__init__(self)
        self.wizard = wizard
        self.plugin = wizard.plugin
        self.wallet = wizard.main_window.wallet

        layout = self.layout()
        assert isinstance(layout, QVBoxLayout)

        layout.addWidget(HelpLabel(
            _("Trade Code:"),
            _("Enter the trade code you received from the trade maker.")
        ))

        self.code_edit = QLineEdit()
        self.code_edit.setPlaceholderText("trade1...")
        self.code_edit.textChanged.connect(self.validate)
        layout.addWidget(self.code_edit)

        self.fetch_button = QPushButton(_("Fetch Trade Details"))
        self.fetch_button.clicked.connect(self.fetch_trade)
        self.fetch_button.setEnabled(False)
        layout.addWidget(self.fetch_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.info_label = QLabel()
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        layout.addStretch(1)
        self.valid = False
        self.trade = None
        self.trade_id = None

        self.thread = TaskThread(self, self.on_error)

    def validate(self):
        code = self.code_edit.text().strip()
        self.fetch_button.setEnabled(bool(code))

    def fetch_trade(self):
        code = self.code_edit.text().strip()
        if not code:
            return

        self.info_label.setText(_("Fetching trade details..."))
        self.fetch_button.setEnabled(False)
        self.code_edit.setEnabled(False)

        worker = self.plugin.get_escrow_worker(self.wallet, worker_type=EscrowClient)

        def do_fetch():
            coro = worker.create_trade_from_postbox(code)
            fut = asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())
            return fut.result()

        self.thread.add(do_fetch, on_success=self.on_success)

    def on_success(self, result):
        if not result:
            self.info_label.setText(_("Could not find the trade. Check the code and your nostr relays."))
            self.code_edit.setEnabled(True)
            self.fetch_button.setEnabled(True)
            return

        self.trade, self.trade_id = result
        self.info_label.setText(_("Trade found! Click Next to review the details."))
        self.valid = True

    def on_error(self, exc_info):
        self.info_label.setText(_("Error fetching trade: {}").format(exc_info[1]))
        self.code_edit.setEnabled(True)
        self.fetch_button.setEnabled(True)
        if not issubclass(exc_info[0], (UserFacingException, ValueError)):
            self.logger.exception("Error fetching trade", exc_info=exc_info)

    def apply(self):
        self.wizard_data['trade'] = self.trade
        self.wizard_data['trade_id'] = self.trade_id

    def stop(self):
        self.thread.stop()


class WCAcceptTrade(WizardComponent, Logger):
    """
    Shows the full trade contract and the agent to the taker. On accept, the taker
    registers with the agent and pays their funding (bond or trade amount).
    """
    def __init__(self, parent, wizard):
        super().__init__(parent, wizard, title=_("Accept Trade"))
        Logger.__init__(self)
        self.wizard = wizard
        self.plugin = wizard.plugin
        self.wallet = wizard.main_window.wallet
        self.valid = False
        self.trade: Optional[ClientEscrowTrade] = None
        self.trade_id: Optional[str] = None

    def on_ready(self):
        self.trade = self.wizard_data['trade']
        self.trade_id = self.wizard_data['trade_id']
        assert isinstance(self.trade, ClientEscrowTrade)
        self.init_ui()

    def init_ui(self):
        layout = self.layout()
        assert isinstance(layout, QVBoxLayout)
        contract = self.trade.contract
        fmt = self.wizard.main_window.format_amount_and_units

        details = [
            f"<b>{_('Title')}:</b> {html.escape(contract.title)}",
            f"<b>{_('Trade amount')}:</b> {fmt(contract.trade_amount_sat)}",
            f"<b>{_('Bond')}:</b> {fmt(contract.bond_sat)}",
            f"<b>{_('Agent fee')}:</b> {format_fee_ppm(contract.agent_fee_ppm)} ({fmt(contract.agent_fee_sat())})",
            f"<b>{_('Escrow agent')}:</b> {html.escape(contract.agent_pubkey)}",
            "",
            f"<b>{_('Contract')}:</b><br>{html.escape(contract.text)}",
            "",
        ]
        if self.trade.payment_direction == TradePaymentDirection.SENDING:
            details.append(_("You pay the trade amount of {} to the escrow agent now. The counterparty "
                             "receives it when both of you confirm the successful trade.")
                           .format(fmt(contract.trade_amount_sat)))
        else:
            funding = contract.bond_sat
            details.append(_("You lock a bond of {} with the escrow agent now. When both of you confirm "
                             "the successful trade you receive {} (trade amount minus agent fee plus "
                             "bond refund).").format(fmt(funding), fmt(contract.payout_amount_sat())))

        info_label = QLabel("<br>".join(details))
        info_label.setWordWrap(True)
        info_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(info_label)

        warning = WWLabel(_("The escrow agent is fully trusted and can take the locked funds. "
                            "Only accept this trade if you trust the escrow agent above."))
        warning.setStyleSheet("color: red")
        layout.addWidget(warning)

        amount_to_pay = self.trade.funding_amount_sat
        if amount_to_pay > 0:
            button_text = _("Accept and Pay {}").format(fmt(amount_to_pay))
        else:
            button_text = _("Accept Trade")
        self.accept_button = QPushButton(button_text)
        self.accept_button.clicked.connect(self.accept_trade)
        layout.addWidget(self.accept_button, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addStretch(1)

    def accept_trade(self):
        amount_to_pay = self.trade.funding_amount_sat
        if amount_to_pay > 0:
            can_send = int(self.wallet.lnworker.num_sats_can_send() or 0) if self.wallet.has_lightning() else 0
            if can_send < amount_to_pay:
                self.wizard.show_error(
                    _("You cannot send the funding amount of {} with your Lightning channels. "
                      "Increase your outgoing liquidity first.").format(
                        self.wizard.main_window.format_amount_and_units(amount_to_pay)))
                return
            msg = _("Do you want to accept this trade and pay {}?").format(
                self.wizard.main_window.format_amount_and_units(amount_to_pay))
        else:
            msg = _("Do you want to accept this trade?")
        if not self.wizard.question(msg):
            return

        self.accept_button.setEnabled(False)
        worker = self.plugin.get_escrow_worker(self.wallet, worker_type=EscrowClient)

        async def do_accept():
            # 1. Request accept from agent
            invoice = await worker.request_accept_escrow(self.trade, self.trade_id)
            # 2. Pay the funding invoice (if there is something to pay)
            if invoice is not None:
                self.wallet.save_invoice(invoice)
                payment_success, log = await self.wallet.lnworker.pay_invoice(invoice)
                if not payment_success:
                    raise UserFacingException(_("Payment failed"))
            return invoice

        def on_success(_result):
            worker.save_new_trade(self.trade_id, self.trade)
            self.wizard.show_message(_("Trade accepted and funded successfully!"))
            self.valid = True
            self.wizard.accept()

        def on_failure(exc_info):
            self.wizard.show_error(str(exc_info[1]))
            self.accept_button.setEnabled(True)

        run_coro_with_dialog(self, _("Accepting trade..."), do_accept(), on_success, on_failure)

    def apply(self):
        pass


class EscrowWizardDialog(QEAbstractWizard, QtEventListener, EscrowWizard):
    def __init__(self, window: 'ElectrumWindow', plugin: 'Plugin', escrow_type: EscrowType):
        EscrowWizard.__init__(self, plugin)

        if escrow_type == EscrowType.MAKE:
            start_view = 'create_trade'
        elif escrow_type == EscrowType.TAKE:
            start_view = 'fetch_trade'
        else:
            raise NotImplementedError(escrow_type)

        start_viewstate = WizardViewState(start_view, {}, {})

        QEAbstractWizard.__init__(self, window.config, window.app, start_viewstate=start_viewstate)
        self.main_window: 'ElectrumWindow' = window
        self.window_title = _("Escrow Wizard")
        self._set_logo()
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.register_callbacks()

        self.navmap_merge({
            'create_trade': {'gui': WCCreateTrade},
            'select_escrow_agent': {'gui': WCSelectEscrowAgent},
            'confirm_create': {'gui': WCConfirmCreate},
            'show_postbox': {'gui': WCShowPostbox},
            'fetch_trade': {'gui': WCFetchTrade},
            'accept_trade': {'gui': WCAcceptTrade},
        })

    def _set_logo(self):
        self.logo.setPixmap(
            read_QPixmap_from_bytes(
                self.plugin.read_file(self.plugin.ICON_FILE_NAME)
            ).scaledToWidth(
                60,
                mode=Qt.TransformationMode.SmoothTransformation
            )
        )
        # ugly hack to prevent QEAbstractWizard from overriding the icon
        self.icon_filename = icon_path('electrum.png')

    @qt_event_listener
    def on_event_channel(self, wallet: 'Abstract_Wallet', _channel):
        if wallet != self.main_window.wallet:
            return
        current_widget = self.main_widget.currentWidget()
        if hasattr(current_widget, 'on_event_channel'):
            current_widget.on_event_channel()

    def on_back_button_clicked(self):
        if self.can_go_back():
            w = self.main_widget.currentWidget()
            if hasattr(w, 'stop'):
                w.stop()
        super().on_back_button_clicked()

    def done(self, r):
        self.unregister_callbacks()
        for w in self.main_widget.widgets:
            if hasattr(w, 'stop'):
                w.stop()
        super().done(r)


class EscrowAgentProfileDialog(WindowModalDialog, Logger):
    def __init__(self, window: 'ElectrumWindow', plugin: 'Plugin', profile: Optional['EscrowAgentProfile']):
        WindowModalDialog.__init__(self, window, _("Escrow Agent Profile"))
        Logger.__init__(self)
        self.plugin = plugin
        self.wallet = window.wallet
        self.thread = TaskThread(self, self.on_error)

        vbox = QVBoxLayout(self)
        grid = QGridLayout()
        vbox.addLayout(grid)

        self.ok_button = OkButton(self, _("Save"))
        self.ok_button.setEnabled(False)

        # Avatar
        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(128, 128)
        self.avatar_label.setStyleSheet("border: 1px solid gray")
        self.avatar_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.avatar_label.setText(_("No Image"))
        grid.addWidget(self.avatar_label, 0, 2, 4, 1)

        # Name
        grid.addWidget(HelpLabel(
            _("Name:"),
            _("The name that will be displayed to other users.")
        ), 0, 0)
        self.name_e = QLineEdit()
        self.name_e.setPlaceholderText(_("Enter your display name"))
        self.name_e.setMaxLength(50)
        self.name_e.textChanged.connect(self.validate)
        grid.addWidget(self.name_e, 0, 1)

        # About
        grid.addWidget(HelpLabel(
            _("About:"),
            _("A description of your services, your terms, how to contact you in case of "
              "mediation, and any other relevant information.")
        ), 1, 0)
        self.about_e = QTextEdit()
        self.about_e.setPlaceholderText(_("Enter a description (max 1000 characters)..."))
        self.about_e.setMaximumHeight(100)
        self.about_e.textChanged.connect(self._limit_about_length)
        self.about_e.textChanged.connect(self.validate)
        grid.addWidget(self.about_e, 1, 1)

        # Languages
        grid.addWidget(HelpLabel(
            _("Languages:"),
            _("Comma-separated list of languages you support for dispute resolution.")
        ), 2, 0)
        self.languages_e = QLineEdit()
        self.languages_e.setPlaceholderText(_("e.g. en, es, de"))
        self.languages_e.setMaxLength(100)
        self.languages_e.textChanged.connect(self.validate)
        grid.addWidget(self.languages_e, 2, 1)

        # Service Fee
        grid.addWidget(HelpLabel(
            _("Service Fee:"),
            _("Your fee in parts per million of the trade amount. 10,000 ppm is 1%. "
              "Note: the fee is locked into each trade at creation, changing it only "
              "affects new trades.")
        ), 3, 0)
        self.fee_sb = QSpinBox()
        self.fee_sb.setRange(0, MAX_AGENT_FEE_PPM)
        self.fee_sb.setSuffix(" ppm")
        grid.addWidget(self.fee_sb, 3, 1)

        # GPG Fingerprint
        grid.addWidget(HelpLabel(
            _("GPG Fingerprint:"),
            _("Your GPG key fingerprint for identity verification.")
        ), 4, 0)
        self.gpg_e = QLineEdit()
        self.gpg_e.setPlaceholderText(_("[Optional] Enter your GPG fingerprint"))
        self.gpg_e.setMaxLength(100)
        self.gpg_e.textChanged.connect(self.validate)
        grid.addWidget(self.gpg_e, 4, 1)

        # Picture URL
        grid.addWidget(HelpLabel(
            _("Picture URL:"),
            _("A URL to your profile picture.")
        ), 5, 0)
        self.picture_e = QLineEdit()
        self.picture_e.setPlaceholderText("[Optional] https://example.com/avatar.png")
        self.picture_e.setMaxLength(200)
        self.picture_e.textChanged.connect(self.on_picture_edit)
        grid.addWidget(self.picture_e, 5, 1)

        # website
        grid.addWidget(HelpLabel(
            _("Website URL:"),
            _("A URL to your website.")
        ), 6, 0)
        self.website_e = QLineEdit()
        self.website_e.setPlaceholderText("[Optional] https://example.com/")
        self.website_e.setMaxLength(200)
        self.website_e.textChanged.connect(self.validate)
        grid.addWidget(self.website_e, 6, 1)

        self.avatar_fetch_timer = QTimer(self)
        self.avatar_fetch_timer.setSingleShot(True)
        self.avatar_fetch_timer.setInterval(800)
        self.avatar_fetch_timer.timeout.connect(self.fetch_avatar)

        if profile:
            self.name_e.setText(profile.name)
            self.about_e.setText(profile.about)
            self.languages_e.setText(", ".join(profile.languages))
            self.fee_sb.setValue(profile.service_fee_ppm)
            self.gpg_e.setText(profile.gpg_fingerprint or "")
            self.picture_e.setText(profile.picture or "")
            self.website_e.setText(profile.website or "")

        vbox.addLayout(Buttons(CancelButton(self), self.ok_button))
        self.validate()
        self.fetch_avatar()

    def _limit_about_length(self):
        text = self.about_e.toPlainText()
        max_len = 1000
        if len(text) > max_len:
            self.about_e.setPlainText(text[:max_len])
            cursor = self.about_e.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            self.about_e.setTextCursor(cursor)

    def validate(self):
        name = self.name_e.text().strip()
        about = self.about_e.toPlainText().strip()
        # Basic validation
        valid = bool(name) and bool(about)

        picture_url = self.picture_e.text().strip()
        if picture_url and not picture_url.startswith("https://"):
             valid = False

        website_url = self.website_e.text().strip()
        if website_url and not website_url.startswith("https://"):
            valid = False

        self.ok_button.setEnabled(valid)

    def get_profile(self) -> 'EscrowAgentProfile':
        languages = [x.strip() for x in self.languages_e.text().split(',') if x.strip()]
        return EscrowAgentProfile(
            name=self.name_e.text().strip(),
            about=self.about_e.toPlainText().strip(),
            languages=languages,
            service_fee_ppm=self.fee_sb.value(),
            gpg_fingerprint=self.gpg_e.text().strip() or None,
            picture=self.picture_e.text().strip() or None,
            website=self.website_e.text().strip() or None,
        )

    def on_picture_edit(self):
        self.validate()
        self.avatar_fetch_timer.start()

    def fetch_avatar(self):
        url = self.picture_e.text().strip()
        if not url or not url.startswith("https://"):
            self.avatar_label.clear()
            self.avatar_label.setText(_("No Image"))
            return

        def do_fetch():
            return fetch_url_bytes(url)

        def on_success(data):
            if data:
                pixmap = read_QPixmap_from_bytes(data)
                if not pixmap.isNull():
                    self.avatar_label.setPixmap(pixmap.scaled(128, 128, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
                    self.avatar_label.setText("")
                else:
                    self.avatar_label.clear()
                    self.avatar_label.setText(_("Invalid Image"))

        self.thread.add(do_fetch, on_success=on_success)

    def done(self, r):
        self.thread.stop()
        self.avatar_fetch_timer.stop()
        super().done(r)

    def on_error(self, exc_info):
        self.logger.exception("TaskThread error", exc_info=exc_info)


class ResolveMediationDialog(WindowModalDialog):
    """Dialog for the agent to decide the outcome of a mediated trade."""

    def __init__(self, window: 'ElectrumWindow', trade: AgentEscrowTrade):
        WindowModalDialog.__init__(self, window, _("Resolve Mediation"))
        self.window = window
        self.trade = trade
        contract = trade.contract
        pot = contract.pot_sat()
        fmt = window.format_amount_and_units

        vbox = QVBoxLayout(self)
        vbox.addWidget(WWLabel(
            _("Decide how the locked funds get distributed between the participants. "
              "Funds you don't distribute remain with you (your mediation fee).")))
        vbox.addWidget(QLabel(_("Locked funds (pot): {}").format(fmt(pot))))

        grid = QGridLayout()
        sender_str, receiver_str = _("sender"), _("receiver")
        maker_is_sender = contract.maker_payment_direction == TradePaymentDirection.SENDING
        maker_role = sender_str if maker_is_sender else receiver_str
        taker_role = receiver_str if maker_is_sender else sender_str
        grid.addWidget(QLabel(_("Maker payout ({}):").format(maker_role)), 0, 0)
        self.maker_amount_e = BTCAmountEdit(window.get_decimal_point)
        grid.addWidget(self.maker_amount_e, 0, 1)
        grid.addWidget(QLabel(_("Taker payout ({}):").format(taker_role)), 1, 0)
        self.taker_amount_e = BTCAmountEdit(window.get_decimal_point)
        grid.addWidget(self.taker_amount_e, 1, 1)
        vbox.addLayout(grid)

        # default suggestion: everyone gets back what they paid (like a cancellation)
        maker_funding = contract.funding_amount_sat(contract.maker_payment_direction)
        self.maker_amount_e.setAmount(maker_funding)
        self.taker_amount_e.setAmount(pot - maker_funding)

        self.warning_label = WWLabel('')
        self.warning_label.setStyleSheet("color: red")
        vbox.addWidget(self.warning_label)

        self.ok_button = OkButton(self, _("Resolve"))
        vbox.addLayout(Buttons(CancelButton(self), self.ok_button))

        self.maker_amount_e.textChanged.connect(self.validate)
        self.taker_amount_e.textChanged.connect(self.validate)
        self.validate()

    def validate(self):
        maker_sat, taker_sat = self.get_amounts()
        pot = self.trade.contract.pot_sat()
        if maker_sat + taker_sat > pot:
            self.warning_label.setStyleSheet("color: red")
            self.warning_label.setText(_("The payouts exceed the locked funds."))
            self.ok_button.setEnabled(False)
            return
        remaining = pot - maker_sat - taker_sat
        self.ok_button.setEnabled(True)
        if remaining > 0:
            self.warning_label.setStyleSheet("color: gray")
            self.warning_label.setText(_("You keep {} as mediation fee.").format(
                self.window.format_amount_and_units(remaining)))
        else:
            self.warning_label.setText('')

    def get_amounts(self) -> tuple[int, int]:
        return self.maker_amount_e.get_amount() or 0, self.taker_amount_e.get_amount() or 0


class TradeDetailsDialog(WindowModalDialog, Logger):
    def __init__(self, window: 'ElectrumWindow', plugin: 'Plugin',
                 trade: Union[ClientEscrowTrade, AgentEscrowTrade], trade_id: str):
        WindowModalDialog.__init__(self, window, _("Trade Details"))
        Logger.__init__(self)
        self.window = window
        self.plugin = plugin
        self.trade = trade
        self.trade_id = trade_id
        self.is_agent_view = isinstance(trade, AgentEscrowTrade)
        self.thread = TaskThread(self, self.on_error)
        self.setMinimumWidth(600)

        vbox = QVBoxLayout(self)

        self.detail_label = QLabel()
        self.detail_label.setWordWrap(True)
        self.detail_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        vbox.addWidget(self.detail_label)

        self.status_label = WWLabel('')
        self.status_label.setStyleSheet("color: gray")
        vbox.addWidget(self.status_label)

        self.buttons_layout = QHBoxLayout()

        # client actions
        self.copy_postbox_btn = QPushButton(_("Copy Postbox Key"))
        self.copy_postbox_btn.clicked.connect(self._copy_postbox)
        self.confirm_btn = QPushButton(_("Confirm Success"))
        self.confirm_btn.setToolTip(_("Signal that the trade completed successfully. "
                                      "Once both parties confirm, the agent pays out."))
        self.confirm_btn.clicked.connect(self._request_confirm)
        self.cancel_btn = QPushButton(_("Cancel Trade"))
        self.cancel_btn.clicked.connect(self._request_cancel)
        self.mediate_btn = QPushButton(_("Request Mediation"))
        self.mediate_btn.setToolTip(_("Put the trade into mediation. You then have to contact the "
                                      "agent out of band so they can decide the outcome."))
        self.mediate_btn.clicked.connect(self._request_mediation)
        self.claim_btn = QPushButton(_("Claim Payout"))
        self.claim_btn.setToolTip(_("Submit a fresh invoice to the agent to receive your payout."))
        self.claim_btn.clicked.connect(self._request_claim)
        self.sync_btn = QPushButton(_("Refresh"))
        self.sync_btn.clicked.connect(self._sync_state)

        # agent actions
        self.resolve_btn = QPushButton(_("Resolve Mediation"))
        self.resolve_btn.clicked.connect(self._resolve_mediation)

        for btn in (self.copy_postbox_btn, self.confirm_btn, self.cancel_btn, self.mediate_btn,
                    self.claim_btn, self.sync_btn, self.resolve_btn):
            self.buttons_layout.addWidget(btn)
        self.buttons_layout.addStretch(1)
        self.buttons_layout.addWidget(CloseButton(self))
        vbox.addLayout(self.buttons_layout)

        self._update_ui()

        if not self.is_agent_view and self.trade.private_key \
                and not EscrowClient.is_trade_settled(self.trade):
            self._sync_state()

    # ---------- ui ----------

    def _update_ui(self):
        self.detail_label.setText(self._build_details())
        self._update_buttons()

    def _build_details(self) -> str:
        trade = self.trade
        contract = trade.contract
        fmt = self.window.format_amount_and_units
        details = []
        details.append(f"<b>{_('Title')}:</b> {html.escape(contract.title)}")
        details.append(f"<b>{_('State')}:</b> {html.escape(str(trade.state))}")
        details.append(f"<b>{_('Date')}:</b> {datetime.fromtimestamp(trade.creation_timestamp).strftime('%Y-%m-%d %H:%M')}")
        details.append(f"<b>{_('Trade amount')}:</b> {fmt(contract.trade_amount_sat)}")
        details.append(f"<b>{_('Bond')}:</b> {fmt(contract.bond_sat)}")
        details.append(f"<b>{_('Agent fee')}:</b> {format_fee_ppm(contract.agent_fee_ppm)} ({fmt(contract.agent_fee_sat())})")
        details.append(f"<b>{_('Trade ID')}:</b> {html.escape(self.trade_id)}")

        if isinstance(trade, ClientEscrowTrade):
            details.append(f"<b>{_('Agent')}:</b> {html.escape(contract.agent_pubkey)}")
            details.append(f"<b>{_('Role')}:</b> {_('Maker') if trade.is_maker else _('Taker')}")
            if trade.payment_direction == TradePaymentDirection.SENDING:
                details.append(f"<b>{_('Direction')}:</b> {_('You send the trade amount')}")
            else:
                details.append(f"<b>{_('Direction')}:</b> {_('You receive the trade amount')}")
            if trade.payout_due_sat:
                paid_str = _('paid') if trade.payout_paid else _('pending')
                details.append(f"<b>{_('Your payout')}:</b> {fmt(trade.payout_due_sat)} ({paid_str})")
            if trade.state == TradeState.MEDIATION:
                details.append(_("The trade is in mediation. Contact the escrow agent out of band "
                                 "(see their profile) to provide your evidence."))

        elif isinstance(trade, AgentEscrowTrade):
            participants = trade.trade_participants
            details.append(f"<b>{_('Maker')}:</b> {html.escape(participants.maker.pubkey)}")
            details.append(self._participant_status_line(_('Maker'), participants.maker))
            if participants.taker:
                details.append(f"<b>{_('Taker')}:</b> {html.escape(participants.taker.pubkey)}")
                details.append(self._participant_status_line(_('Taker'), participants.taker))

        details.append(f"<b>{_('Contract')}:</b><br>{html.escape(contract.text)}")
        return "<br><br>".join(details)

    def _participant_status_line(self, role: str, participant) -> str:
        fmt = self.window.format_amount_and_units
        flags = []
        if participant.confirmed:
            flags.append(_('confirmed'))
        if participant.cancel_requested:
            flags.append(_('requested cancellation'))
        if participant.payout_due_sat:
            paid_str = _('paid') if participant.payout_paid else _('pending')
            flags.append(_('payout {} ({})').format(fmt(participant.payout_due_sat), paid_str))
        if not flags:
            flags.append(_('no action yet'))
        return f"<b>{role} {_('status')}:</b> {html.escape(', '.join(flags))}"

    def _update_buttons(self):
        trade = self.trade
        state = trade.state
        if self.is_agent_view:
            for btn in (self.copy_postbox_btn, self.confirm_btn, self.cancel_btn,
                        self.mediate_btn, self.claim_btn, self.sync_btn):
                btn.setVisible(False)
            self.resolve_btn.setVisible(state == TradeState.MEDIATION)
            return

        self.resolve_btn.setVisible(False)
        self.sync_btn.setVisible(trade.private_key is not None)
        self.copy_postbox_btn.setVisible(bool(trade.postbox_key) and state == TradeState.WAITING_FOR_TAKER)
        self.confirm_btn.setVisible(state == TradeState.ONGOING)
        self.cancel_btn.setVisible(state in (TradeState.WAITING_FOR_TAKER, TradeState.ONGOING, TradeState.MEDIATION))
        if state == TradeState.WAITING_FOR_TAKER:
            self.cancel_btn.setText(_("Cancel Trade"))
            self.cancel_btn.setToolTip(_("Cancel the trade and get your funding back. "
                                         "Possible while no taker has funded the trade."))
        else:
            self.cancel_btn.setText(_("Request Cancellation"))
            self.cancel_btn.setToolTip(_("Request to cancel the trade. The trade is cancelled and "
                                         "everyone refunded once both parties request cancellation."))
        self.mediate_btn.setVisible(state == TradeState.ONGOING)
        self.claim_btn.setVisible(
            state.is_final() and bool(trade.payout_due_sat) and not trade.payout_paid)

    # ---------- background state sync (client) ----------

    def _sync_state(self):
        if self.is_agent_view:
            return
        worker = self._client_worker()
        self.status_label.setText(_("Syncing trade state with agent..."))
        self.sync_btn.setEnabled(False)

        def do_sync():
            coro = worker.sync_trade_state(self.trade_id)
            fut = asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())
            return fut.result()

        def on_success(_result):
            self.status_label.setText(_("Trade state is up to date."))
            self.sync_btn.setEnabled(True)
            self._update_ui()

        def on_sync_error(exc_info):
            self.status_label.setText(_("Could not reach the agent: {}").format(exc_info[1]))
            self.sync_btn.setEnabled(True)

        self.thread.add(do_sync, on_success=on_success, on_error=on_sync_error)

    # ---------- client actions ----------

    def _client_worker(self) -> EscrowClient:
        return self.plugin.get_escrow_worker(self.window.wallet, worker_type=EscrowClient)

    def _copy_postbox(self):
        if self.trade.postbox_key:
            self.window.do_copy(self.trade.postbox_key, title=_("Postbox Key"))

    def _run_client_action(self, coro, waiting_msg: str, success_msg: str):
        def on_success(_result):
            self._update_ui()
            self.show_message(success_msg)

        def on_failure(exc_info):
            self._update_ui()
            self.show_error(str(exc_info[1]))

        run_coro_with_dialog(self, waiting_msg, coro, on_success, on_failure)

    def _request_confirm(self):
        if not self.question(_("Confirm that this trade completed successfully? "
                               "Once both parties confirm, the agent pays out and "
                               "this cannot be undone.")):
            return
        self._run_client_action(
            self._client_worker().request_collaborative_confirm(self.trade_id),
            _("Sending confirmation..."),
            _("Confirmation sent."))

    def _request_cancel(self):
        if self.trade.state == TradeState.WAITING_FOR_TAKER:
            msg = _("Cancel this trade and get your funding back?")
        else:
            msg = _("Request to cancel this trade? The trade is cancelled and everyone "
                    "gets their funds back once both parties request cancellation.")
        if not self.question(msg):
            return
        self._run_client_action(
            self._client_worker().request_collaborative_cancel(self.trade_id),
            _("Requesting cancellation..."),
            _("Cancellation requested."))

    def _request_mediation(self):
        if not self.question(_("Put this trade into mediation? You will have to contact the "
                               "escrow agent out of band so they can decide the trade outcome. "
                               "Check the agent profile for contact information.")):
            return
        self._run_client_action(
            self._client_worker().request_mediation(self.trade_id),
            _("Requesting mediation..."),
            _("Mediation requested. Contact the agent to provide your evidence."))

    def _request_claim(self):
        self._run_client_action(
            self._client_worker().request_claim_payout(self.trade_id),
            _("Claiming payout..."),
            _("Payout claim submitted. The agent will now try to pay your invoice."))

    # ---------- agent actions ----------

    def _resolve_mediation(self):
        worker = self.plugin.get_escrow_worker(self.window.wallet, worker_type=EscrowAgent)
        d = ResolveMediationDialog(self.window, self.trade)
        if not d.exec():
            return
        maker_sat, taker_sat = d.get_amounts()
        fmt = self.window.format_amount_and_units
        if not self.question(_("Resolve the mediation with a payout of {} to the maker and {} "
                               "to the taker?").format(fmt(maker_sat), fmt(taker_sat))):
            return
        try:
            worker.resolve_mediation(
                self.trade_id, maker_payout_sat=maker_sat, taker_payout_sat=taker_sat)
        except (ValueError, UserFacingException) as e:
            self.show_error(str(e))
            return
        self._update_ui()
        self.show_message(_("Mediation resolved. The participants have been notified and "
                            "their payouts will be paid out."))

    def on_error(self, exc_info):
        self.logger.exception("TaskThread error", exc_info=exc_info)

    def done(self, r):
        self.thread.stop()
        super().done(r)


class EscrowPluginDialog(WindowModalDialog, QtEventListener):
    def __init__(self, window: 'ElectrumWindow'):
        WindowModalDialog.__init__(self, window, _("Trade Escrow Plugin"))
        self.main_window = window
        self._plugin = None  # type: Optional['Plugin']
        self._wallet = None  # type: Optional['Abstract_Wallet']
        self._main_layout = None  # type: Optional[QHBoxLayout]
        self._content_vbox = None  # type: Optional[QVBoxLayout]
        self._new_trade_button = None
        self._accept_trade_button = None
        self._notification_label = None  # type: Optional[QLabel]
        self._configure_profile_action = None
        self._agent_mode_action = None
        self._agent_pubkey_label = None  # type: Optional[WWLabel]

    @classmethod
    def run(cls, window: 'ElectrumWindow', plugin: 'Plugin'):
        d = cls(window)
        d._plugin = plugin
        d._wallet = window.wallet
        d._main_layout = d._plugin_dialog_main_layout(d)
        d._content_vbox = d._plugin_dialog_content_vbox(window)
        d._content_vbox.addLayout(d._plugin_dialog_footer(d))
        d._main_layout.addLayout(d._content_vbox)
        d.setLayout(d._main_layout)
        d.setMinimumSize(700, 400)
        d.register_callbacks()
        d._trigger_update()
        try:
            return bool(d.exec())
        finally:
            d.unregister_callbacks()
            d._cleanup()

    @qt_event_listener
    def on_event_escrow_trades_updated(self, wallet):
        if wallet != self._wallet:
            return
        self._update_trades_list()

    def _plugin_dialog_main_layout(self, d: WindowModalDialog) -> QHBoxLayout:
        main_layout = QHBoxLayout(d)
        logo_label = QLabel()
        pixmap = read_QPixmap_from_bytes(self._plugin.read_file(self._plugin.ICON_FILE_NAME))
        logo_label.setPixmap(pixmap.scaled(50, 50))
        logo_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        main_layout.addWidget(logo_label)
        main_layout.addSpacing(16)
        return main_layout

    def _plugin_dialog_title_hbox(self, window: 'ElectrumWindow') -> QHBoxLayout:
        # title (New trade + menu + info)
        title_hbox = QHBoxLayout()
        self._new_trade_button = QPushButton(_("Create Trade"))
        self._new_trade_button.clicked.connect(self._create_trade)
        title_hbox.addWidget(self._new_trade_button)
        self._accept_trade_button = QPushButton(_("Accept Trade"))
        self._accept_trade_button.clicked.connect(self._accept_trade)
        title_hbox.addWidget(self._accept_trade_button)

        title_hbox.addStretch(1)

        # help button
        info_button = QPushButton(_("Help"))
        info = _("The Trade Escrow plugin allows you to safely trade with strangers by using a trusted escrow agent as an intermediary. "
                 "The agent takes custody of the funds until both participants are satisfied, or decides the outcome of the trade after reviewing evidence.")
        warning = _("The escrow agent is fully trusted and can take your money. Only use escrow agents "
                    "with a well-established reputation that you trust.")
        info_msg = f"{info}\n\n{warning}"
        info_button.clicked.connect(lambda: window.show_message(info_msg))
        title_hbox.addWidget(info_button)

        # tools button
        menu = QMenuWithConfig(window.wallet.config)
        self._agent_mode_action = menu.addToggle(
            text=_("Escrow Agent Mode"),
            callback=self._toggle_escrow_agent_mode,
            tooltip=_("Act as escrow agent for trades. Requires a wallet with Lightning support "
                      "that is reliably online."),
            default_state=self._plugin.is_escrow_agent(self._wallet),
        )
        self._configure_profile_action = menu.addAction(_("Configure Profile"), self._configure_profile)

        tool_button = QToolButton()
        tool_button.setText(_('Tools'))
        tool_button.setIcon(read_QIcon("preferences.png"))
        tool_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        tool_button.setMenu(menu)
        tool_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        tool_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        title_hbox.addWidget(tool_button)

        return title_hbox

    def _plugin_dialog_content_vbox(self, window: 'ElectrumWindow') -> QVBoxLayout:
        content_vbox = QVBoxLayout()
        # trades list: date, name, amount, state
        self.trades_list = QTreeWidget()
        self.trades_list.setHeaderLabels([_("Date"), _("Name"), _("Amount"), _("State")])
        header = self.trades_list.header()
        header.setMinimumSectionSize(80)
        header.setSectionResizeMode(0, header.ResizeMode.ResizeToContents)  # Date
        header.setSectionResizeMode(1, header.ResizeMode.Stretch)           # Name fills remaining space
        header.setSectionResizeMode(2, header.ResizeMode.ResizeToContents)  # Amount
        header.setSectionResizeMode(3, header.ResizeMode.ResizeToContents)  # State
        self.trades_list.itemDoubleClicked.connect(self._show_trade_details)
        content_vbox.addLayout(self._plugin_dialog_title_hbox(window))

        # notification label for urgent user infos
        self._notification_label = WWLabel()
        self._notification_label.setVisible(False)

        self._agent_pubkey_label = WWLabel()
        self._agent_pubkey_label.setToolTip(_("Share this public key with users so they use you as escrow agent"))
        self._agent_pubkey_label.setVisible(False)

        content_vbox.addWidget(self._notification_label)
        content_vbox.addWidget(self._agent_pubkey_label)
        content_vbox.addWidget(self.trades_list)
        return content_vbox

    @staticmethod
    def _plugin_dialog_footer(d: WindowModalDialog) -> Buttons:
        close_button = OkButton(d, label=_("Close"))
        footer_buttons = Buttons(
            close_button,
        )
        return footer_buttons

    def _maybe_show_warning(self):
        """
        Check if there is any issue that could cause the plugin to be unreliable and show a warning.
        """
        self.show_notification(msg=None)
        if len(self._plugin.config.get_nostr_relays()) < 3:
            self.show_notification(
                _("You have configured only a few Nostr relays. To ensure reliable operation, "
                  "you should add more Nostr relays in the network settings."),
                critical=True,
            )
            return
        if not self._wallet.has_lightning():
            self.show_notification(
                _("This wallet has no Lightning support. Trading requires a wallet "
                  "with Lightning enabled."),
                critical=True,
            )
            return
        if self._plugin.has_agent_worker(self._wallet):
            worker = self._plugin.get_escrow_worker(self._wallet, worker_type=EscrowAgent)
            if not worker.get_profile():
                self.show_notification(
                    msg=_("Configure your Escrow Agent profile to become visible to other users."),
                    critical=False,
                )

    def show_notification(self, msg: Optional[str], *, critical: bool = False):
        """
        Shows a notification in the dialog. Overrides the previous notification.
        """
        if not msg:
            self._notification_label.clear()
            self._notification_label.setVisible(False)
            return
        self._notification_label.setText(msg)
        if critical:
            self._notification_label.setStyleSheet(
                "QLabel { color: black; background-color: #e74c3c; padding: 10px; border-radius: 5px; }"
            )
        else:
            self._notification_label.setStyleSheet(
                "QLabel { color: black; background-color: #f1c40f; padding: 10px; border-radius: 5px; }"
            )
        self._notification_label.setVisible(bool(msg))

    def _cleanup(self):
        self._main_layout = None
        self._content_vbox = None
        self._plugin = None
        self._wallet = None
        self._notification_label = None
        self._agent_pubkey_label = None

    def _toggle_escrow_agent_mode(self):
        escrow_agent_enabled = self._plugin.is_escrow_agent(self._wallet)
        try:
            self._plugin.set_escrow_agent_mode(enabled=not escrow_agent_enabled, wallet=self._wallet)
        except UserFacingException as e:
            self.show_error(str(e))
            if self._agent_mode_action:
                self._agent_mode_action.setChecked(escrow_agent_enabled)
            return
        self._trigger_update()

    def _trigger_update(self):
        self._update_visibility()
        self._maybe_show_warning()
        self._update_trades_list()

    def _update_visibility(self):
        is_agent = self._plugin.has_agent_worker(self._wallet)
        can_trade = self._wallet.has_lightning()
        if self._new_trade_button:
            self._new_trade_button.setVisible(not is_agent)
            self._new_trade_button.setEnabled(can_trade)
        if self._accept_trade_button:
            self._accept_trade_button.setVisible(not is_agent)
            self._accept_trade_button.setEnabled(can_trade)
        if self._agent_mode_action:
            self._agent_mode_action.setVisible(can_trade)
        if self._configure_profile_action:
            self._configure_profile_action.setVisible(is_agent)
        if self._agent_pubkey_label:
            self._agent_pubkey_label.setVisible(is_agent)
            if is_agent:
                worker = self._plugin.get_escrow_worker(self._wallet, worker_type=EscrowAgent)
                self._agent_pubkey_label.setText(
                    _("Your public key: {}").format(worker.get_identity_pubkey()))

    def _update_trades_list(self):
        self.trades_list.clear()
        is_agent = self._plugin.has_agent_worker(self._wallet)
        if is_agent:
            worker = self._plugin.get_escrow_worker(self._wallet, worker_type=EscrowAgent)
        else:
            worker = self._plugin.get_escrow_worker(self._wallet, worker_type=EscrowClient)

        trades = list(worker.get_trades().items())
        trades.sort(key=lambda t: t[1].creation_timestamp, reverse=True)

        for trade_id, trade in trades:
            date_str = datetime.fromtimestamp(trade.creation_timestamp).strftime('%Y-%m-%d %H:%M')
            amount_str = self.main_window.format_amount_and_units(trade.contract.trade_amount_sat)
            item = QTreeWidgetItem([date_str, trade.contract.title, amount_str, str(trade.state)])
            item.setData(0, Qt.ItemDataRole.UserRole, trade_id)
            self.trades_list.addTopLevelItem(item)

    def _show_trade_details(self, item: QTreeWidgetItem, column: int):
        trade_id = item.data(0, Qt.ItemDataRole.UserRole)
        if not trade_id:
            return
        is_agent = self._plugin.has_agent_worker(self._wallet)
        if is_agent:
            worker = self._plugin.get_escrow_worker(self._wallet, worker_type=EscrowAgent)
        else:
            worker = self._plugin.get_escrow_worker(self._wallet, worker_type=EscrowClient)
        trade = worker.get_trades().get(trade_id)
        if trade is None:
            return

        d = TradeDetailsDialog(self.main_window, self._plugin, trade, trade_id)
        d.exec()
        self._update_trades_list()

    def _configure_profile(self):
        worker = self._plugin.get_escrow_worker(self._wallet, worker_type=EscrowAgent)
        profile = worker.get_profile()
        d = EscrowAgentProfileDialog(self.main_window, self._plugin, profile)
        if d.exec():
            new_profile = d.get_profile()
            worker.save_profile(new_profile)
            self._trigger_update()

    def _create_trade(self):
        d = EscrowWizardDialog(self.main_window, self._plugin, EscrowType.MAKE)
        if d.exec():
            self._trigger_update()

    def _accept_trade(self):
        d = EscrowWizardDialog(self.main_window, self._plugin, EscrowType.TAKE)
        if d.exec():
            self._trigger_update()


class Plugin(EscrowPlugin):
    def __init__(self, *args):
        EscrowPlugin.__init__(self, *args)

    @hook
    def init_menubar(self, window: 'ElectrumWindow'):
        ma = window.wallet_menu.addAction(_('Trade Escrow'), partial(self.settings_dialog, window))
        icon = read_QIcon_from_bytes(self.read_file(self.ICON_FILE_NAME))
        ma.setIcon(icon)

    def settings_dialog(self, window: 'ElectrumWindow') -> bool:
        # when enabling the plugin the daemon_wallet_loaded hook was already called, so we need to
        # load the wallet here as well to ensure the plugin knows about the wallet
        self._load_wallet(window.wallet)
        if window.wallet not in self.wallets:
            window.show_error(_("The escrow plugin could not load this wallet. "
                                "Make sure you are connected to a network."))
            return False
        return EscrowPluginDialog.run(window, self)
