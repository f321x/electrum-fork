#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2025 The Electrum Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import asyncio
import concurrent
from typing import TYPE_CHECKING, List, Tuple, Optional

from PyQt6.QtCore import QObject, pyqtSignal, pyqtProperty, pyqtSlot

from electrum import util
from electrum.plugin import hook
from electrum.transaction import PartialTransaction, tx_from_any
from electrum.wallet import Multisig_Wallet
from electrum.util import EventListener, event_listener

from electrum.gui.qml.qewallet import QEWallet

from .psbt_nostr import PsbtNostrPlugin, CosignerWallet

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from electrum.gui.qml import ElectrumQmlApplication


class QReceiveSignalObject(QObject):
    def __init__(self, plugin: 'Plugin'):
        QObject.__init__(self)
        self._plugin = plugin

    cosignerReceivedPsbt = pyqtSignal(str, str, str)
    sendPsbtFailed = pyqtSignal(str, arguments=['reason'])
    sendPsbtSuccess = pyqtSignal()

    @pyqtProperty(str)
    def loader(self):
        return 'main.qml'

    @pyqtSlot(QEWallet, str)
    def sendPsbt(self, wallet: 'QEWallet', tx: str):
        cosigner_wallet = self._plugin.cosigner_wallets[wallet.wallet]
        if not cosigner_wallet:
            return
        cosigner_wallet.send_psbt(tx_from_any(tx, deserialize=True))

    @pyqtSlot(QEWallet, str)
    def acceptPsbt(self, wallet: 'QEWallet', event_id: str):
        cosigner_wallet = self._plugin.cosigner_wallets[wallet.wallet]
        if not cosigner_wallet:
            return
        cosigner_wallet.accept_psbt(event_id)


class Plugin(PsbtNostrPlugin):
    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)
        self.so = QReceiveSignalObject(self)
        self._app = None

    @hook
    def init_qml(self, app: 'ElectrumQmlApplication'):
        self._app = app
        self.so.setParent(app)  # parent in QObject tree
        # plugin enable for already open wallet
        wallet = app.daemon.currentWallet.wallet if app.daemon.currentWallet else None
        if wallet:
            self.load_wallet(wallet)

    @hook
    def load_wallet(self, wallet: 'Abstract_Wallet'):
        # remove existing, only foreground wallet active
        if len(self.cosigner_wallets):
            self.remove_cosigner_wallet(self.cosigner_wallets[0])
        if not isinstance(wallet, Multisig_Wallet):
            return
        self.add_cosigner_wallet(wallet, QmlCosignerWallet(wallet, self))


class QmlCosignerWallet(EventListener, CosignerWallet):

    def __init__(self, wallet: 'Multisig_Wallet', plugin: 'Plugin'):
        CosignerWallet.__init__(self, wallet)
        self.plugin = plugin
        self.register_callbacks()

        self.pending = None

    @event_listener
    def on_event_psbt_nostr_received(self, wallet, pubkey, event, tx: 'PartialTransaction'):
        if self.wallet == wallet:
            self.plugin.so.cosignerReceivedPsbt.emit(pubkey, event, tx.serialize())
            self.on_receive(pubkey, event, tx)

    def close(self):
        super().close()
        self.unregister_callbacks()

    def do_send(self, messages: List[Tuple[str, str]], txid: Optional[str] = None):
        if not messages:
            return
        coro = self.send_direct_messages(messages)

        loop = util.get_asyncio_loop()
        assert util.get_running_loop() != loop, 'must not be called from asyncio thread'
        self._result = None
        self._future = asyncio.run_coroutine_threadsafe(coro, loop)

        try:
            self._result = self._future.result()
            self.plugin.so.sendPsbtSuccess.emit()
        except concurrent.futures.CancelledError:
            pass
        except Exception as e:
            self.plugin.so.sendPsbtFailed.emit(str(e))

    def on_receive(self, pubkey, event_id, tx):
        self.pending = (pubkey, event_id, tx)

    def accept_psbt(self, my_event_id):
        pubkey, event_id, tx = self.pending
        if event_id == my_event_id:
            self.mark_event_rcvd(event_id)
            self.pending = None
