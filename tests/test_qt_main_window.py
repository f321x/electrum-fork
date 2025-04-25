import os.path
import asyncio
import threading
import unittest
from unittest.mock import patch, MagicMock
import sys

from PyQt6.QtCore import QObject, pyqtSignal, QTimer
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication

from build.lib.electrum import SimpleConfig
from electrum.wallet import restore_wallet_from_text, Abstract_Wallet
from electrum.gui.qt.main_window import ElectrumWindow
from electrum.plugin import Plugins
from electrum.gui.qt import ElectrumGui
from electrum import util
from . import ElectrumTestCase

from .test_daemon import DaemonTestCase
from typing import TYPE_CHECKING, Generator

if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot

class TestQtMainWindow(DaemonTestCase):

    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        super().setUp()
        self.wallet_path = os.path.join(self.electrum_path, "default_wallet")
        self.config.set_key("wallet_path", self.wallet_path)
        self.config.AUTOMATIC_CENTRALIZED_UPDATE_CHECKS = False
        self.plugins = Plugins(config=self.config, gui_name="qt")

    async def asyncSetUp(self):
        await super().asyncSetUp()
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        self.wallet = restore_wallet_from_text(text, path=self.wallet_path, gap_limit=3, config=self.config)['wallet']
        self.electrum_gui = ElectrumGui(config=self.config, daemon=self.daemon, plugins=self.plugins)
        self.daemon.gui_object = self.electrum_gui
        self.daemon._plugins = self.plugins
        # self.main_window = ElectrumWindow(self.electrum_gui, self.wallet)
        # self.main_window.show()

    def tearDown(self):
        super().tearDown()

    async def asyncTearDown(self):
        # self.electrum_gui._cleanup_before_exit()
        await super().asyncTearDown()

    async def test_main_window(self):
        self.electrum_gui.main()
        print(f"we are heere")
        await asyncio.sleep(2)
        print(f"left main")
        # QTest.qWaitForWindowExposed(self.electrum_gui.windows[0])  # type: ignore
        self.electrum_gui.stop()
        pass
