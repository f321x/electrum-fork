import asyncio
import json
from typing import TYPE_CHECKING, Optional
from functools import partial
import ssl
from concurrent.futures import Future

from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFileDialog, QToolButton, QMenu,
    QLineEdit, QPlainTextEdit
)
from PyQt6.QtCore import QObject, pyqtSignal, Qt
from electrum_aionostr.key import PrivateKey as NostrPrivateKey
from electrum_aionostr.key import PublicKey as NostrPublicKey

from electrum.plugin import BasePlugin, hook
from electrum.network import Network
from electrum.gui.qt.util import (
    WindowModalDialog, read_QIcon_from_bytes, Buttons, WWLabel, OkButton, CancelButton,
    RunCoroutineDialog, CloseButton, read_QIcon
)
from electrum.i18n import _
from electrum.crypto import sha256
from electrum.util import UserCancelled, make_aiohttp_proxy_connector, ca_path, get_asyncio_loop

from .authenticity_tool import NostrFileAuthenticityTool

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.plugin import Plugins
    from electrum.gui.qt import ElectrumWindow


class NostrVerificationSignals(QObject):
    signature_found = pyqtSignal(int)
    finished = pyqtSignal(int)
    error = pyqtSignal(str)


class Plugin(BasePlugin):
    ICON_FILENAME = 'trust_icon.png'
    MIN_SIGS = 2

    def __init__(self, parent: 'Plugins', config: 'SimpleConfig', name: str):
        BasePlugin.__init__(self, parent, config, name)
        self.config = config
        try:
            self.default_trusted_npubs = set(json.loads(self.read_file('default_trusted_pubkeys.json')))
        except Exception:
            self.logger.debug(f"couldn't load default npubs", exc_info=True)
            self.default_trusted_npubs = set()

    def is_available(self):
        network = Network.get_instance()
        return network is not None

    @hook
    def init_menubar(self, window: 'ElectrumWindow'):
        ma = window.wallet_menu.addAction('File Authenticity Tool', partial(self.plugin_dialog, window))
        icon_bytes = self.read_file(self.ICON_FILENAME)
        icon = read_QIcon_from_bytes(icon_bytes)
        ma.setIcon(icon)

    def get_trusted_signer_npubs(self, window: 'ElectrumWindow') -> set[str]:
        persisted_storage = self.get_storage(window.wallet)
        if persisted_storage and 'trusted_signer_npubs' in persisted_storage:
            return set(json.loads(persisted_storage['trusted_signer_npubs']))
        return self.default_trusted_npubs

    def set_trusted_signer_npubs(self, window: 'ElectrumWindow', npubs: set[str]):
        storage = self.get_storage(window.wallet)
        storage['trusted_signer_npubs'] = json.dumps(list(npubs))

    def plugin_dialog(self, window: 'ElectrumWindow'):
        d = WindowModalDialog(window, _("File Authenticity Tool"))
        d.setMinimumWidth(700)

        vbox = QVBoxLayout(d)

        tools_button = QToolButton()
        tools_button.setText(_("Tools"))
        tools_button.setIcon(read_QIcon("preferences.png"))
        tools_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        tools_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        tools_menu = QMenu(d)
        tools_menu.addAction(_("Configure Trusted Pubkeys"), lambda: self.configure_trusted_pubkeys_dialog(window))
        tools_menu.addAction(_("Sign File"), lambda: self.sign_file_dialog(window))
        tools_button.setMenu(tools_menu)
        hbox_menu = QHBoxLayout()
        hbox_menu.addStretch(1)
        hbox_menu.addWidget(tools_button)
        vbox.addLayout(hbox_menu)

        vbox.addWidget(WWLabel(_("Select a file you want to verify against your trusted signers.")))

        select_file_button = QPushButton(_("Select File to Verify"))
        file_label = QLabel()
        file_label.setWordWrap(True)
        status_label = QLabel()
        font = status_label.font()
        point_size = font.pointSize()
        font.setPointSize(point_size + 2 if point_size > 0 else 12)
        status_label.setFont(font)

        signals = NostrVerificationSignals()

        def on_signature_found(num_sigs: int):
            status_label.setText(_("Found {} signature(s)...").format(num_sigs))

        def on_verification_finished(num_sigs: int):
            trusted_pubkeys = self.get_trusted_signer_npubs(window)
            select_file_button.setEnabled(True)

            min_sigs = self.config.AUTHENTICITY_TOOL_MIN_SIGS  # type: ignore
            if num_sigs >= min_sigs or (trusted_pubkeys and num_sigs >= len(trusted_pubkeys)):
                status_label.setText(_("File Authentic. Found {} signatures.").format(num_sigs))
                status_label.setStyleSheet("color: green")
            else:
                status_label.setText(_("Verification failed. Couldn't find enough signatures (found {}).").format(num_sigs))
                status_label.setStyleSheet("color: red")

        def on_error(msg: str):
            status_label.setText(f"Error: {msg}")
            status_label.setStyleSheet("color: red")
            select_file_button.setEnabled(True)

        fut = None  # type: Optional[Future]
        signals.signature_found.connect(on_signature_found)
        signals.finished.connect(on_verification_finished)
        signals.error.connect(on_error)

        def select_file():
            filename, __ = QFileDialog.getOpenFileName(d, _('Select file to verify'))
            if not filename:
                return

            file_label.setText(filename)
            status_label.setText(_("Hashing file..."))
            status_label.setStyleSheet("")

            try:
                with open(filename, 'rb') as f:
                    file_content = f.read()
                file_hash = sha256(file_content)
            except Exception as e:
                on_error(str(e))
                return

            status_label.setText(_("Verifying..."))
            select_file_button.setEnabled(False)

            trusted_npubs = self.get_trusted_signer_npubs(window)
            if not trusted_npubs:
                on_error(_("No trusted pubkeys configured."))
                return
            trusted_pubkeys = set(NostrPublicKey.from_npub(npub).hex() for npub in trusted_npubs)

            async def verify_coro():
                try:
                    found_signers = set()
                    min_sigs = self.config.AUTHENTICITY_TOOL_MIN_SIGS  # type: ignore
                    if window.network.proxy and window.network.proxy.enabled:
                        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
                        proxy = make_aiohttp_proxy_connector(window.network.proxy, ssl_context)
                    else:
                        proxy = None
                    async for signer_pubkey in NostrFileAuthenticityTool.verify_hash(
                        file_hash_sha256=file_hash,
                        trusted_signing_pubkeys_hex=trusted_pubkeys,
                        timeout_sec=20,
                        nostr_relays=nostr_relays,
                        proxy=proxy,
                    ):
                        if signer_pubkey not in found_signers:
                            found_signers.add(signer_pubkey)
                            signals.signature_found.emit(len(found_signers))
                            if len(found_signers) >= min_sigs or (trusted_pubkeys and len(found_signers) >= len(trusted_pubkeys)):
                                # breaking the loop might take a bit longer if we rebroadcast,
                                # so rather signal finished inside the loop
                                signals.finished.emit(len(found_signers))
                                break
                except Exception:
                    self.logger.exception("error verifying file")
                    signals.error.emit(str(e))

            nonlocal fut
            if fut is not None and not fut.done():
                fut.cancel()
            fut = asyncio.run_coroutine_threadsafe(verify_coro(), get_asyncio_loop())

            def on_done(done_fut):
                nonlocal fut
                if done_fut == fut:
                    fut = None
                    self.logger.debug(f"verify_coro is done")
            fut.add_done_callback(on_done)

        select_file_button.clicked.connect(select_file)

        if not window.network:
            on_error("Not connected to network")
            select_file_button.setEnabled(False)
            select_file_button.setToolTip(_("Network connection is required to fetch signatures"))

        nostr_relays = set(self.config.get_nostr_relays())
        if len(nostr_relays) < 3:
            on_error(_("Not enough Nostr relays configured. Please configure at least 3 in the settings."))
            select_file_button.setEnabled(False)
            select_file_button.setToolTip(_("Nostr relays are required to fetch signatures"))

        vbox.addWidget(select_file_button)
        vbox.addWidget(file_label)
        vbox.addWidget(status_label)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(d)))

        d.exec()
        if fut is not None and not fut.done():
            self.logger.debug(f"cancelling ongoing file verification")
            fut.cancel()

    def configure_trusted_pubkeys_dialog(self, window: 'ElectrumWindow'):
        d = WindowModalDialog(window, _("Configure Trusted Pubkeys"))
        d.setMinimumWidth(600)
        vbox = QVBoxLayout(d)

        current_npubs = self.get_trusted_signer_npubs(window)

        vbox.addWidget(QLabel(_("Trusted public keys (npubs):")))
        npub_list = QPlainTextEdit()
        npub_list.setPlainText('\n'.join(sorted(list(current_npubs))))
        vbox.addWidget(npub_list)

        def restore_defaults():
            npub_list.setPlainText('\n'.join(sorted(list(self.default_trusted_npubs))))

        restore_button = QPushButton(_("Restore Defaults"))
        restore_button.clicked.connect(restore_defaults)

        def on_save():
            text = npub_list.toPlainText()
            npubs = set(text.split())
            for npub in npubs:
                try:
                    pubkey = NostrPublicKey.from_npub(npub)
                    assert pubkey
                except Exception:
                    window.show_error(f"Invalid pubkey: {npub}")
                    return
            self.set_trusted_signer_npubs(window, npubs)
            d.close()

        save_button = OkButton(d, _("Save"))
        save_button.clicked.connect(on_save)

        vbox.addLayout(Buttons(restore_button, CancelButton(d), save_button))
        d.exec()

    def sign_file_dialog(self, window: 'ElectrumWindow'):
        d = WindowModalDialog(window, _("Sign File"))
        d.setMinimumWidth(600)
        vbox = QVBoxLayout(d)

        vbox.addWidget(QLabel(_("Select file to sign:")))
        hbox_file = QHBoxLayout()
        filename_label = QLineEdit()
        filename_label.setPlaceholderText(_("File to sign"))
        hbox_file.addWidget(filename_label)
        def select_file():
            filename, __ = QFileDialog.getOpenFileName(d, _('Select file to sign'))
            if filename:
                filename_label.setText(filename)
        file_button = QPushButton(_("..."))
        file_button.clicked.connect(select_file)
        hbox_file.addWidget(file_button)
        vbox.addLayout(hbox_file)

        vbox.addWidget(QLabel(_("Nostr private key (nsec):")))
        nsec_input = QLineEdit()
        nsec_input.setEchoMode(QLineEdit.EchoMode.Password)
        vbox.addWidget(nsec_input)

        def on_sign():
            filename = filename_label.text()
            try:
                nostr_privkey = NostrPrivateKey.from_nsec(nsec_input.text())
            except Exception:
                nostr_privkey = None

            if not filename:
                window.show_error(_("No file selected."))
                return
            if not nostr_privkey:
                window.show_error(_("Invalid private key."))
                return

            try:
                with open(filename, 'rb') as f:
                    file_content = f.read()
                file_hash = sha256(file_content)
            except Exception as e:
                window.show_error(str(e))
                return

            if not window.network:
                window.show_error("Not connected")
                return

            nostr_relays = set(self.config.get_nostr_relays())
            if not nostr_relays:
                window.show_error(_("No Nostr relays configured. Please configure them in the settings."))
                return

            async def sign_coro():
                if window.network.proxy and window.network.proxy.enabled:
                    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
                    proxy = make_aiohttp_proxy_connector(window.network.proxy, ssl_context)
                else:
                    proxy = None
                await NostrFileAuthenticityTool.publish_signature(
                    file_hash_sha256=file_hash,
                    private_key=nostr_privkey.raw_secret,
                    nostr_relays=nostr_relays,
                    proxy=proxy,
                )

            try:
                RunCoroutineDialog(d, _("Signing and publishing..."), sign_coro()).run()
                window.show_message(_("Signature published successfully."))
                d.close()
            except UserCancelled:
                pass
            except Exception as e:
                self.logger.exception("error signing file")
                window.show_error(str(e))

        sign_button = OkButton(d, _("Sign and Publish"))
        sign_button.clicked.connect(on_sign)

        vbox.addLayout(Buttons(CancelButton(d), sign_button))

        d.exec()
