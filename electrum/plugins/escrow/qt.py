from typing import TYPE_CHECKING, Optional
from functools import partial
from enum import Enum

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTreeWidget,
    QTextEdit, QSpinBox, QLineEdit, QToolButton, QGridLayout, QComboBox,
)

from electrum.i18n import _
from electrum.plugin import hook
from electrum.gui.qt.util import (
    WindowModalDialog, Buttons, OkButton,
    read_QIcon_from_bytes, read_QPixmap_from_bytes, read_QIcon, HelpLabel,
    icon_path, WWLabel
)
from electrum.gui.qt.my_treeview import QMenuWithConfig
from electrum.gui.qt.amountedit import BTCAmountEdit, AmountEdit
from electrum.gui.qt.wizard.wizard import QEAbstractWizard, WizardComponent
from electrum.wizard import WizardViewState

from .escrow import EscrowPlugin
from .wizard import EscrowWizard

if TYPE_CHECKING:
    from electrum.gui.qt.main_window import ElectrumWindow


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
        self.title_edit.setPlaceholderText(_("Enter a short trade description..."))
        self.title_edit.textChanged.connect(self.validate)
        grid.addWidget(self.title_edit, 0, 1, 1, 3)

        # Contract
        grid.addWidget(HelpLabel(
                text=_("Contract:"),
                help_text=_("Specify the conditions of the trade as detailed as possible. In case of a "
                            "conflict the escrow agent will decide the trade outcome based on this contract.")
        ), 1, 0)
        self.contract_edit = QTextEdit()
        self.contract_edit.setMaximumHeight(100)
        self.contract_edit.setPlaceholderText(_("Enter contract details (max 2000 characters)..."))
        self.contract_edit.textChanged.connect(self._limit_contract_length)
        self.contract_edit.textChanged.connect(self.validate)
        grid.addWidget(self.contract_edit, 1, 1, 1, 3)

        # Trade Amount
        self.direction_cb = QComboBox()
        self.direction_cb.addItems([_("I receive"), _("I send")])
        grid.addWidget(self.direction_cb, 2, 0)

        self.receive_amount_e = BTCAmountEdit(self.wizard.window.get_decimal_point)
        self.receive_amount_e.textChanged.connect(self.validate)
        grid.addWidget(self.receive_amount_e, 2, 1)

        fiat_currency = self.wizard.window.fx.get_currency if self.wizard.window.fx else None
        self.fiat_receive_e = AmountEdit(fiat_currency)
        if not self.wizard.window.fx or not self.wizard.window.fx.is_enabled():
            self.fiat_receive_e.setVisible(False)
        else:
            self.wizard.window.connect_fields(self.receive_amount_e, self.fiat_receive_e)
        grid.addWidget(self.fiat_receive_e, 2, 2)

        # Bond Amount
        grid.addWidget(HelpLabel(
            text=_("Bond Amount (%):"),
            help_text=_("Percentage of the trade amount that both trade participants will lock to the escrow agent. "
                        "This ensures both participants have something to lose (skin-in-the-game). "
                        "The bond will get refunded in case of a successful trade.")
        ), 3, 0)
        self.bond_percentage_sb = QSpinBox()
        self.bond_percentage_sb.setRange(0, 100)
        self.bond_percentage_sb.setSuffix("%")
        self.bond_percentage_sb.setValue(3)  # default value
        grid.addWidget(self.bond_percentage_sb, 3, 1)

        grid.setColumnStretch(3, 1)
        grid.setHorizontalSpacing(15)

        layout.addStretch(1)

    def _limit_contract_length(self):
        text = self.contract_edit.toPlainText()
        if len(text) > self.wizard.plugin.MAX_CONTRACT_LEN_CHARS:
            self.contract_edit.setPlainText(text[:self.wizard.plugin.MAX_CONTRACT_LEN_CHARS])
            cursor = self.contract_edit.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            self.contract_edit.setTextCursor(cursor)

    def validate(self):
        title = self.title_edit.text().strip()
        contract = self.contract_edit.toPlainText().strip()
        amount = self.receive_amount_e.get_amount()

        is_valid = bool(title) and bool(contract) and (amount is not None and amount > 0)
        self.valid = is_valid

    def apply(self):
        self.wizard_data['title'] = self.title_edit.text().strip()
        self.wizard_data['contract'] = self.contract_edit.toPlainText().strip()
        self.wizard_data['amount_sat'] = self.receive_amount_e.get_amount()
        self.wizard_data['bond_percent'] = self.bond_percentage_sb.value()
        self.wizard_data['is_receiving'] = self.direction_cb.currentIndex() == 0


class WCSelectEscrowAgent(WizardComponent):
    """
    Trade maker selects escrow agent for this trade from a drop-down menu. Also has the possibility
    add a new escrow agent. Gives details of the escrow agent.
    """
    def __init__(self, parent, wizard: 'EscrowWizardDialog'):
        super().__init__(parent, wizard, title=_("Escrow Agent"))
        layout = self.layout()
        layout.addWidget(QLabel(_("Select trusted Escrow Agent")))
        self.escrow_agent_pubkey = None  # type: Optional[str]
        self.valid = False
        # todo: fetch kind 0 profiles and nip 38 status of providers

    def validate(self):
        self.valid = self.escrow_agent_pubkey is not None

    def apply(self):
        self.wizard_data['escrow_agent_pubkey'] = self.escrow_agent_pubkey


class WCConfirmCreate(WizardComponent):
    def __init__(self, parent, wizard):
        super().__init__(parent, wizard, title=_("Confirm Trade Creation"))
        layout = self.layout()
        layout.addWidget(QLabel("Confirm Create (TODO)"))
        # Maker can review the trade conditions and escrow agent profile. Submitting will request the
        # escrow from the escrow agent via Nostr. The escrow agent will return a bond and trade lightning invoice.
        self.valid = True

    def apply(self):
        pass


class WCFetchTrade(WizardComponent):
    def __init__(self, parent, wizard):
        super().__init__(parent, wizard, title=_("Fetch Trade"))
        layout = self.layout()
        layout.addWidget(QLabel("Fetch Trade (TODO)"))
        # Taker enters id of the trade they got from the maker, fetches trade conditions.
        self.valid = True

    def apply(self):
        pass


class WCAcceptTrade(WizardComponent):
    def __init__(self, parent, wizard):
        super().__init__(parent, wizard, title=_("Accept Trade"))
        layout = self.layout()
        layout.addWidget(QLabel("Accept Trade (TODO)"))
        # Taker reviews the trade conditions and escrow agent profile.
        self.valid = True

    def apply(self):
        pass


class EscrowWizardDialog(EscrowWizard, QEAbstractWizard):
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
        self.window = window
        self.window_title = _("Escrow Wizard")
        self._set_logo()

        self.navmap_merge({
            'create_trade': {'gui': WCCreateTrade},
            'select_escrow_agent': {'gui': WCSelectEscrowAgent},
            'confirm_create': {'gui': WCConfirmCreate},
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


class EscrowPluginDialog(WindowModalDialog):
    def __init__(self, window: 'ElectrumWindow'):
        WindowModalDialog.__init__(self, window, _("Trade Escrow Plugin"))
        self.window = window
        self._plugin = None  # type: Optional['Plugin']
        self._wallet = None  # type: Optional['Abstract_Wallet']
        self._main_layout = None  # type: Optional[QHBoxLayout]
        self._content_vbox = None  # type: Optional[QVBoxLayout]
        self._new_trade_button = None
        self._accept_trade_button = None
        self._notification_label = None  # type: Optional[QLabel]

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
        d._maybe_show_warning()
        try:
            return bool(d.exec())
        finally:
            d._cleanup()

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

        self._update_visibility()
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
        menu.addToggle(
            text="Escrow Agent Mode",
            callback=self._toggle_escrow_agent_mode,
            tooltip="Act as escrow agent for trades",
            default_state=self._plugin.is_escrow_agent(self._wallet),
        )
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
        # trades list: date, name, state
        trades_list = QTreeWidget()
        trades_list.setHeaderLabels([_("Date"), _("Name"), _("State")])
        header = trades_list.header()
        header.setMinimumSectionSize(80)
        header.setSectionResizeMode(0, header.ResizeMode.ResizeToContents)  # Date
        header.setSectionResizeMode(1, header.ResizeMode.Stretch)           # Name fills remaining space
        header.setSectionResizeMode(2, header.ResizeMode.ResizeToContents)  # State
        content_vbox.addLayout(self._plugin_dialog_title_hbox(window))

        # notification label for urgent user infos
        self._notification_label = WWLabel()
        self._notification_label.setVisible(False)

        content_vbox.addWidget(self._notification_label)
        content_vbox.addWidget(trades_list)
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
        if len(self._plugin.config.get_nostr_relays()) < 3:
            self.show_notification(
                _("You have configured only a few Nostr relays. To ensure reliable operation, "
                  "you should add more Nostr relays in the network settings."),
                critical=True,
            )

    def show_notification(self, msg: Optional[str], *, critical: bool = False):
        """
        Shows a notification in the dialog. Overrides the previous notification.
        """
        if not msg:
            self._notification_label.clear()
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

    def _toggle_escrow_agent_mode(self):
        escrow_agent_enabled = self._plugin.is_escrow_agent(self._wallet)
        self._plugin.set_escrow_agent_mode(enabled=not escrow_agent_enabled, wallet=self._wallet)
        self._trigger_update()

    def _trigger_update(self):
        self._update_visibility()

    def _update_visibility(self):
        is_agent = self._plugin.is_escrow_agent(self._wallet)
        if self._new_trade_button:
            self._new_trade_button.setVisible(not is_agent)
        if self._accept_trade_button:
            self._accept_trade_button.setVisible(not is_agent)

    def _create_trade(self):
        d = EscrowWizardDialog(self.window, self._plugin, EscrowType.MAKE)
        if d.exec():
            self._trigger_update()

    def _accept_trade(self):
        d = EscrowWizardDialog(self.window, self._plugin, EscrowType.TAKE)
        if d.exec():
            self._trigger_update()


class Plugin(EscrowPlugin):
    def __init__(self, *args):
        EscrowPlugin.__init__(self, *args)

    @hook
    def init_menubar(self, window: 'ElectrumWindow'):
        ma = window.wallet_menu.addAction('Trade Escrow', partial(self.settings_dialog, window))
        icon = read_QIcon_from_bytes(self.read_file(self.ICON_FILE_NAME))
        ma.setIcon(icon)

    def settings_dialog(self, window: 'ElectrumWindow') -> bool:
        return EscrowPluginDialog.run(window, self)
