from typing import TYPE_CHECKING, Optional
from dataclasses import dataclass
from functools import partial

from PyQt6.QtGui import QPixmap, QImage
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTreeWidget, QTreeWidgetItem,
    QTextEdit, QApplication, QSpinBox, QSizePolicy, QComboBox, QLineEdit, QToolButton, QGridLayout,
    QWidget,
)

from electrum.i18n import _
from electrum.plugin import hook
from electrum.gui.qt.util import (
    WindowModalDialog, Buttons, OkButton, CancelButton, CloseButton,
    read_QIcon_from_bytes, read_QPixmap_from_bytes, read_QIcon, HelpLabel
)
from electrum.gui.qt.my_treeview import QMenuWithConfig
from electrum.gui.qt.amountedit import BTCAmountEdit, AmountEdit

from .escrow import EscrowPlugin
from .wizard import EscrowWizard

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from electrum.gui.qt.main_window import ElectrumWindow


class EscrowWizardDialog(WindowModalDialog):
    def __init__(self, window: 'ElectrumWindow', plugin: 'EscrowPlugin', flow_type: str):
        WindowModalDialog.__init__(self, window, _("Escrow Wizard"))
        self.wizard = EscrowWizard(plugin)
        self.electrum_window = window
        self.view_state = self.wizard.start(flow_type)

        self.vbox = QVBoxLayout(self)
        self.content_layout = QVBoxLayout()
        self.vbox.addLayout(self.content_layout)

        self.back_button = QPushButton(_("Back"))
        self.back_button.clicked.connect(self.on_back)
        self.next_button = QPushButton(_("Next"))
        self.next_button.clicked.connect(self.on_next)
        self.cancel_button = QPushButton(_("Cancel"))
        self.cancel_button.clicked.connect(self.reject)

        self.vbox.addLayout(Buttons(self.back_button, self.next_button, self.cancel_button))

        self.current_widget = None
        self.update_ui()

    def update_ui(self):
        if self.current_widget:
            self.content_layout.removeWidget(self.current_widget)
            self.current_widget.deleteLater()

        view = self.view_state.view
        self.current_widget = self.get_widget_for_view(view, self.view_state.wizard_data)
        self.content_layout.addWidget(self.current_widget)

        is_last = self.wizard.is_last_view(view, self.view_state.wizard_data)
        self.next_button.setText(_("Finish") if is_last else _("Next"))
        self.back_button.setEnabled(len(self.wizard._stack) > 0)

    def on_next(self):
        data = self.view_state.wizard_data

        if self.wizard.is_last_view(self.view_state.view, data):
            self.accept()
            return

        self.view_state = self.wizard.resolve_next(self.view_state.view, data)
        self.update_ui()

    def on_back(self):
        self.view_state = self.wizard.resolve_prev()
        self.update_ui()

    def get_widget_for_view(self, view: str, data: dict) -> QWidget:
        if view == 'create_trade':
            return self._create_trade_widget()
            # l.addWidget(QLabel(_("Enter Trade Terms:")))
            # self.terms_edit = QLineEdit(data.get('terms', ''))
            # l.addWidget(self.terms_edit)
        elif view == 'select_escrow_agent':
            return self._select_escrow_agent_widget()
        elif view == 'confirm_create':
            return self._confirm_create_widget()
            # l.addWidget(QLabel(f"Terms: {data.get('terms', 'N/A')}"))
        elif view == 'fetch_trade':
            return self._fetch_trade_widget()
        elif view == 'accept_trade':
            return self._accept_trade_widget()
        else:
            raise ValueError(f'Invalid view: {view}')

    def _create_trade_widget(self) -> QWidget:
        """
        Trade maker enters their trade conditions.
        """
        w = QWidget()
        layout = QVBoxLayout(w)
        grid = QGridLayout()
        layout.addLayout(grid)

        # Title
        grid.addWidget(QLabel(_("Title:")), 0, 0)
        self.title_edit = QLineEdit()
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
        grid.addWidget(self.contract_edit, 1, 1, 1, 3)

        # Trade Amount
        grid.addWidget(QLabel(_("Trade Amount:")), 2, 0)
        self.receive_amount_e = BTCAmountEdit(self.electrum_window.get_decimal_point)
        grid.addWidget(self.receive_amount_e, 2, 1)

        fiat_currency = self.electrum_window.fx.get_currency if self.electrum_window.fx else None
        self.fiat_receive_e = AmountEdit(fiat_currency)
        if not self.electrum_window.fx or not self.electrum_window.fx.is_enabled():
            self.fiat_receive_e.setVisible(False)
        else:
            self.electrum_window.connect_fields(self.receive_amount_e, self.fiat_receive_e)
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
        return w

    def _limit_contract_length(self):
        text = self.contract_edit.toPlainText()
        if len(text) > self.wizard.plugin.MAX_CONTRACT_LEN_CHARS:
            self.contract_edit.setPlainText(text[:self.wizard.plugin.MAX_CONTRACT_LEN_CHARS])
            cursor = self.contract_edit.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            self.contract_edit.setTextCursor(cursor)

    def _select_escrow_agent_widget(self) -> QWidget:
        """
        Trade maker selects escrow agent for this trade from a drop-down menu. Also has the possibility
        to add a new escrow agent. Gives details of the escrow agent.
        """
        w = QWidget()
        l = QVBoxLayout(w)

        return w

    def _confirm_create_widget(self) -> QWidget:
        """
        Maker can review the trade conditions and escrow agent profile. Submitting will request the
        escrow from the escrow agent via Nostr. The escrow agent will return a bond and trade lightning invoice.
        """
        w = QWidget()
        l = QVBoxLayout(w)

        return w

    def _fetch_trade_widget(self) -> QWidget:
        """
        Taker enters id of the trade they got from the maker, fetches trade conditions.
        """
        w = QWidget()
        l = QVBoxLayout(w)

        return w

    def _accept_trade_widget(self) -> QWidget:
        """
        Taker reviews the trade conditions and escrow agent profile.
        """
        w = QWidget()
        l = QVBoxLayout(w)

        return w


class EscrowPluginDialog(WindowModalDialog):
    def __init__(self, window: 'ElectrumWindow'):
        WindowModalDialog.__init__(self, window, _("Trade Escrow Plugin"))
        self.window = window
        self._plugin = None  # type: Optional['Plugin']
        self._wallet = None  # type: Optional['Abstract_Wallet']
        self._main_layout = None  # type: Optional[QHBoxLayout]
        self._content_vbox = None  # type: Optional[QVBoxLayout]
        self.new_trade_button = None
        self.accept_trade_button = None

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
        self.new_trade_button = QPushButton(_("Create Trade"))
        self.new_trade_button.clicked.connect(self.create_trade)
        title_hbox.addWidget(self.new_trade_button)
        self.accept_trade_button = QPushButton(_("Accept Trade"))
        self.accept_trade_button.clicked.connect(self.accept_trade)
        title_hbox.addWidget(self.accept_trade_button)

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
        content_vbox.addWidget(trades_list)
        return content_vbox

    @staticmethod
    def _plugin_dialog_footer(d: WindowModalDialog) -> Buttons:
        close_button = OkButton(d, label=_("Close"))
        footer_buttons = Buttons(
            close_button,
        )
        return footer_buttons

    def _cleanup(self):
        self._main_layout = None
        self._content_vbox = None
        self._plugin = None
        self._wallet = None

    def _toggle_escrow_agent_mode(self):
        escrow_agent_enabled = self._plugin.is_escrow_agent(self._wallet)
        self._plugin.set_escrow_agent_mode(enabled=not escrow_agent_enabled, wallet=self._wallet)
        self._trigger_update()

    def _trigger_update(self):
        self._update_visibility()

    def _update_visibility(self):
        is_agent = self._plugin.is_escrow_agent(self._wallet)
        if self.new_trade_button:
            self.new_trade_button.setVisible(not is_agent)
        if self.accept_trade_button:
            self.accept_trade_button.setVisible(not is_agent)

    def create_trade(self):
        d = EscrowWizardDialog(self.window, self._plugin, 'create')
        if d.exec():
            self._trigger_update()

    def accept_trade(self):
        d = EscrowWizardDialog(self.window, self._plugin, 'accept')
        if d.exec():
            self._trigger_update()


class Plugin(EscrowPlugin):
    ICON_FILE_NAME = "escrow-icon.png"

    def __init__(self, *args):
        EscrowPlugin.__init__(self, *args)

    @hook
    def init_menubar(self, window: 'ElectrumWindow'):
        ma = window.wallet_menu.addAction('Trade Escrow', partial(self.settings_dialog, window))
        icon = read_QIcon_from_bytes(self.read_file(self.ICON_FILE_NAME))
        ma.setIcon(icon)

    def settings_dialog(self, window: 'ElectrumWindow') -> bool:
        return EscrowPluginDialog.run(window, self)
