# QML GUI Python Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in, touch-friendly Python console page to the QML GUI, functionally equivalent to the desktop Qt console.

**Architecture:** A new app-scoped backend QObject (`QEConsole` in `electrum/gui/qml/qeconsole.py`, exposed as context property `PyConsole`) ports the toolkit-independent REPL logic from `electrum/gui/qt/console.py` (eval/exec, stdout capture, multiline constructs, history, completions, traceback filtering). A new `Console.qml` page provides a read-only scrollback + single-line input + on-screen buttons. A new `GUI_QML_SHOW_CONSOLE` ConfigVar gates a Preferences switch and a wallet-menu entry.

**Tech Stack:** Python 3 / PyQt6 (pyqtProperty/pyqtSlot/pyqtSignal), QtQuick Controls 2 (Material), existing Electrum QML controls (`InfoTextArea`, `FlatButton`, `ButtonContainer`), test harness `tests/qml/qt_util.py` (`QETestCase`, `@qt_test`).

Spec: `docs/superpowers/specs/2026-06-12-qml-console-design.md`

**Test runner note:** use `python3 -m unittest tests.qml.test_qml_qeconsole -v` (works without pytest; if pytest is installed, `python3 -m pytest tests/qml/test_qml_qeconsole.py -v` is equivalent). Run from the repo root `/home/user/Desktop/host_code_vibecoding/electrum-3`.

---

## File structure

- Create: `electrum/gui/qml/qeconsole.py` — backend REPL QObject (all console logic, no UI).
- Create: `electrum/gui/qml/components/Console.qml` — touch UI page.
- Create: `tests/qml/test_qml_qeconsole.py` — unit tests for the backend.
- Modify: `electrum/simple_config.py` — add `GUI_QML_SHOW_CONSOLE` ConfigVar (after line 860, `GUI_QML_PAYMENT_AUTHENTICATION`).
- Modify: `electrum/gui/qml/qeconfig.py` — add `showConsole` property (after `canToggleDebugLogs`/`enableDebugLogs` block, ~line 198).
- Modify: `electrum/gui/qml/qeapp.py` — instantiate `QEConsole`, set context property `PyConsole` (~line 552).
- Modify: `electrum/gui/qml/components/Preferences.qml` — switch row in Advanced section (~line 490) + `Component.onCompleted` sync (~line 507).
- Modify: `electrum/gui/qml/components/WalletMainView.qml` — menu item (after "Sweep key(s)" MenuItem, ~line 239).
- Modify: `tests/qml/test_qml_qeconfig.py` — test for `showConsole` property.

---

### Task 1: Config plumbing (`GUI_QML_SHOW_CONSOLE` + `Config.showConsole`)

**Files:**
- Modify: `electrum/simple_config.py` (after `GUI_QML_PAYMENT_AUTHENTICATION`, line 860)
- Modify: `electrum/gui/qml/qeconfig.py` (after the `enableDebugLogs` setter, ~line 198)
- Test: `tests/qml/test_qml_qeconfig.py`

- [ ] **Step 1: Write the failing test** — append to `tests/qml/test_qml_qeconfig.py` inside `class TestConfig`:

```python
    @qt_test
    def test_show_console(self):
        prior = self.q.showConsole
        try:
            self.q.showConsole = False
            self.assertFalse(self.q.showConsole)
            self.q.showConsole = True
            self.assertTrue(self.q.showConsole)
        finally:
            self.q.showConsole = prior
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.qml.test_qml_qeconfig.TestConfig.test_show_console -v`
Expected: FAIL/ERROR (`AttributeError: ... no attribute 'showConsole'`)

- [ ] **Step 3: Implement** — in `electrum/simple_config.py`, directly under the line
`GUI_QML_PAYMENT_AUTHENTICATION = ConfigVar('qml_payment_authentication', default=False, type_=bool)` add:

```python
    GUI_QML_SHOW_CONSOLE = ConfigVar('qml_show_console', default=False, type_=bool)
```

In `electrum/gui/qml/qeconfig.py`, after the `enableDebugLogs` setter block add:

```python
    showConsoleChanged = pyqtSignal()
    @pyqtProperty(bool, notify=showConsoleChanged)
    def showConsole(self):
        return self.config.GUI_QML_SHOW_CONSOLE

    @showConsole.setter
    def showConsole(self, enable):
        if self.config.GUI_QML_SHOW_CONSOLE != enable:
            self.config.GUI_QML_SHOW_CONSOLE = enable
            self.showConsoleChanged.emit()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.qml.test_qml_qeconfig.TestConfig.test_show_console -v`
Expected: PASS (`ok`)

- [ ] **Step 5: Commit**

```bash
git add electrum/simple_config.py electrum/gui/qml/qeconfig.py tests/qml/test_qml_qeconfig.py
git commit -m "qml: add GUI_QML_SHOW_CONSOLE config option"
```

---

### Task 2: `QEConsole` core REPL (eval/exec, stdout capture, tracebacks)

**Files:**
- Create: `electrum/gui/qml/qeconsole.py`
- Test: `tests/qml/test_qml_qeconsole.py`

- [ ] **Step 1: Write the failing tests** — create `tests/qml/test_qml_qeconsole.py`:

```python
from electrum import SimpleConfig
from electrum.gui.qml.qeconsole import QEConsole

from .qt_util import QETestCase, qt_test


class TestConsole(QETestCase):

    def _console(self):
        return QEConsole(SimpleConfig())

    @qt_test
    def test_eval_expression(self):
        c = self._console()
        c.runCommand('2 + 2')
        self.assertIn('>>> 2 + 2\n', c.output)
        self.assertIn('4\n', c.output)

    @qt_test
    def test_exec_statement_and_namespace_persistence(self):
        c = self._console()
        c.runCommand('x = 5')
        c.runCommand('x * 2')
        self.assertIn('10\n', c.output)

    @qt_test
    def test_print_capture(self):
        c = self._console()
        c.runCommand('print("hello world")')
        self.assertIn('hello world\n', c.output)

    @qt_test
    def test_traceback_shown_and_filtered(self):
        c = self._console()
        c.runCommand('1 / 0')
        self.assertIn('ZeroDivisionError', c.output)
        self.assertNotIn('qeconsole.py', c.output)

    @qt_test
    def test_system_exit_does_not_propagate(self):
        c = self._console()
        c.runCommand('raise SystemExit')  # must not kill the process
        self.assertIn('SystemExit', c.output)

    @qt_test
    def test_bare_function_name_hint(self):
        c = self._console()
        c.runCommand('f = lambda: 1')
        c.runCommand('f')
        self.assertIn("'f' is a function", c.output)
        # note: bound methods (like 'run') intentionally don't trigger the
        # hint -- same behavior as the Qt console, which checks FunctionType

    @qt_test
    def test_output_trimmed(self):
        c = self._console()
        c.runCommand('print("a" * 300000)')
        self.assertLessEqual(len(c.output), QEConsole.MAX_OUTPUT_SIZE)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.qml.test_qml_qeconsole -v`
Expected: ERROR (`ModuleNotFoundError: No module named 'electrum.gui.qml.qeconsole'`)

- [ ] **Step 3: Implement** — create `electrum/gui/qml/qeconsole.py`:

```python
import os
import re
import sys
import traceback
from typing import TYPE_CHECKING, Optional

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

import electrum
from electrum import bitcoin, commands, lnutil, util
from electrum.base_crash_reporter import taint_reports_by_console_usage
from electrum.i18n import _
from electrum.logging import get_logger

if TYPE_CHECKING:
    from electrum.daemon import Daemon
    from electrum.plugin import Plugins
    from electrum.simple_config import SimpleConfig
    from electrum.wallet import Abstract_Wallet
    from .qedaemon import QEDaemon


class QEConsole(QObject):
    """Python REPL for the QML GUI.

    Port of the toolkit-independent parts of electrum/gui/qt/console.py.
    Lives at application scope so namespace, history and scrollback survive
    page navigation.
    """
    _logger = get_logger(__name__)

    MAX_OUTPUT_SIZE = 100_000  # characters kept in the scrollback buffer
    MAX_HISTORY_SIZE = 50      # same cap as the Qt console

    outputChanged = pyqtSignal()
    promptChanged = pyqtSignal()

    def __init__(
            self,
            config: 'SimpleConfig',
            *,
            daemon: Optional['Daemon'] = None,
            qedaemon: Optional['QEDaemon'] = None,
            plugins: Optional['Plugins'] = None,
            parent=None,
    ):
        super().__init__(parent)
        self._config = config
        self._daemon = daemon
        self._qedaemon = qedaemon
        self._plugins = plugins
        self._output = ''
        self._history = []
        self._history_index = 0
        self._construct = []
        self._is_json = False
        self._namespace = {}
        self._namespace_initialized = False

    @pyqtProperty(str, notify=outputChanged)
    def output(self):
        return self._output

    @pyqtProperty(str, notify=promptChanged)
    def prompt(self):
        return '... ' if self._construct else '>>> '

    @pyqtProperty(bool, notify=promptChanged)
    def inConstruct(self):
        return bool(self._construct)

    def _append(self, text: str) -> None:
        self._output += text
        if len(self._output) > self.MAX_OUTPUT_SIZE:
            self._output = self._output[-self.MAX_OUTPUT_SIZE:]
        self.outputChanged.emit()

    def _show_message(self, message: str) -> None:
        self._append(message + '\n')

    @pyqtSlot()
    def clear(self):
        self._output = ''
        self.outputChanged.emit()

    @pyqtSlot()
    def keyboardInterrupt(self):
        """Abort a pending multiline construct (Ctrl+C equivalent)."""
        self._construct = []
        self._show_message('KeyboardInterrupt')
        self.promptChanged.emit()

    @pyqtSlot(str)
    def runCommand(self, line: str) -> None:
        command = line.rstrip()
        self._append(self.prompt + command + '\n')
        self._add_to_history(command)
        command = self._get_construct(command)
        if command:
            self._exec_command(command)
        self._is_json = False
        self.promptChanged.emit()

    def _get_construct(self, command: str) -> str:
        # multiline blocks: a line ending in ':' starts a construct,
        # an empty line terminates and returns it for execution
        if self._construct:
            self._construct.append(command)
            if not command:
                ret_val = '\n'.join(self._construct)
                self._construct = []
                return ret_val
            else:
                return ''
        else:
            if command and command[-1] == ':':
                self._construct.append(command)
                return ''
            else:
                return command

    def _add_to_history(self, command: str) -> None:
        if not self._construct and command[0:1] == ' ':
            return
        if command and (not self._history or self._history[-1] != command):
            while len(self._history) >= self.MAX_HISTORY_SIZE:
                self._history.pop(0)
            self._history.append(command)
        self._history_index = len(self._history)

    @pyqtSlot(result=str)
    def getPrevHistoryEntry(self) -> str:
        if self._history:
            self._history_index = max(0, self._history_index - 1)
            return self._history[self._history_index]
        return ''

    @pyqtSlot(result=str)
    def getNextHistoryEntry(self) -> str:
        if self._history:
            hist_len = len(self._history)
            self._history_index = min(hist_len, self._history_index + 1)
            if self._history_index < hist_len:
                return self._history[self._history_index]
        return ''

    def _get_current_wallet(self) -> Optional['Abstract_Wallet']:
        if self._qedaemon is None:
            return None
        qewallet = self._qedaemon.currentWallet
        return qewallet.wallet if qewallet else None

    def _password_getter(self):
        raise Exception(_('This wallet is encrypted. Pass the wallet password explicitly, e.g.: command(..., password="...")'))

    def _set_json(self, b: bool) -> None:
        self._is_json = b

    def _run_script(self, filename: str) -> None:
        with open(filename) as f:
            script = f.read()
        self._exec_command(script)

    def _update_namespace(self) -> None:
        if not self._namespace_initialized:
            self._namespace_initialized = True
            self._namespace.update({
                'run': self._run_script,
                'config': self._config,
                'daemon': self._daemon,
                'network': self._daemon.network if self._daemon else None,
                'plugins': self._plugins,
                'electrum': electrum,
                'util': util,
                'bitcoin': bitcoin,
                'lnutil': lnutil,
                'app': self.parent(),
            })
            c = commands.Commands(
                config=self._config,
                daemon=self._daemon,
                network=self._daemon.network if self._daemon else None,
                callback=lambda: self._set_json(True))
            def mkfunc(f, method):
                return lambda *args, **kwargs: f(
                    method,
                    args,
                    self._password_getter,
                    **{**kwargs, 'wallet': self._get_current_wallet()})
            for m in dir(c):
                if m[0] == '_' or m in ['network', 'wallet', 'config', 'daemon']:
                    continue
                self._namespace[m] = mkfunc(c._run, m)
        # refresh wallet-dependent entries so the namespace tracks the current wallet
        wallet = self._get_current_wallet()
        self._namespace.update({
            'wallet': wallet,
            'channels': list(wallet.lnworker.channels.values()) if wallet and wallet.lnworker else [],
        })

    def _exec_command(self, command: str) -> None:
        taint_reports_by_console_usage()
        self._update_namespace()

        if type(self._namespace.get(command)) == type(lambda: None):
            self._show_message(
                "'{}' is a function. Type '{}()' to use it in the Python console."
                .format(command, command))
            return

        class StdoutProxy:
            def __init__(self, write_func):
                self.write_func = write_func
            def flush(self):
                pass
            def write(self, text):
                self.write_func(text)

        tmp_stdout = sys.stdout
        sys.stdout = StdoutProxy(self._append)
        try:
            try:
                # eval is generally considered bad practice. use it wisely!
                result = eval(command, self._namespace, self._namespace)
                if result is not None:
                    if self._is_json:
                        self._show_message(util.json_encode(result))
                    else:
                        self._show_message(repr(result))
            except SyntaxError:
                # exec is generally considered bad practice. use it wisely!
                exec(command, self._namespace, self._namespace)
        except SystemExit:
            # unlike the Qt console (which closes its tab), never let
            # SystemExit propagate: it would take down the whole app
            self._show_message('SystemExit')
        except BaseException as e:
            te = traceback.TracebackException.from_exception(e)
            # rm part of traceback mentioning this file
            te.stack = traceback.StackSummary.from_list(te.stack[1:])
            tb_str = "".join(te.format())
            if not tb_str.endswith('\n'):
                tb_str += '\n'
            self._append(tb_str)
        finally:
            sys.stdout = tmp_stdout

    @pyqtSlot(str, result='QVariant')
    def getCompletions(self, cmd: str) -> dict:
        self._update_namespace()
        # note for regex: new words start after ' ' or '(' or ')'
        lastword = re.split(r'[ ()]', cmd)[-1]
        beginning = cmd[:len(cmd) - len(lastword)] if lastword else cmd

        path = lastword.split('.')
        prefix = '.'.join(path[:-1])
        prefix = (prefix + '.') if prefix else prefix
        ns = self._namespace.keys()

        if len(path) > 1:
            obj = self._namespace.get(path[0])
            try:
                for attr in path[1:-1]:
                    obj = getattr(obj, attr)
            except AttributeError:
                ns = []
            else:
                ns = dir(obj)

        completions = []
        for name in ns:
            if name[0] == '_':
                continue
            if name.startswith(path[-1]):
                completions.append(prefix + name)
        completions.sort()

        text = cmd
        candidates = []
        if not completions:
            pass
        elif len(completions) == 1:
            text = beginning + completions[0]
        else:
            p = os.path.commonprefix(completions)
            if len(p) > len(lastword):
                text = beginning + p
            else:
                candidates = completions
        return {'text': text, 'candidates': candidates, 'beginning': beginning}
```

(Note: `getCompletions` is included here so the module is complete in one writing; its tests come in Task 4. Tasks 3-4 only add tests.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.qml.test_qml_qeconsole -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add electrum/gui/qml/qeconsole.py tests/qml/test_qml_qeconsole.py
git commit -m "qml: add QEConsole REPL backend"
```

---

### Task 3: multiline constructs, history, clear, interrupt (tests)

**Files:**
- Test: `tests/qml/test_qml_qeconsole.py` (append to `TestConsole`)
- Modify (only if a test exposes a bug): `electrum/gui/qml/qeconsole.py`

- [ ] **Step 1: Write the tests** — append:

```python
    @qt_test
    def test_multiline_construct(self):
        c = self._console()
        c.runCommand('for i in range(3):')
        self.assertTrue(c.inConstruct)
        self.assertEqual(c.prompt, '... ')
        c.runCommand('    print(i)')
        self.assertTrue(c.inConstruct)
        c.runCommand('')
        self.assertFalse(c.inConstruct)
        self.assertEqual(c.prompt, '>>> ')
        self.assertIn('0\n1\n2\n', c.output)

    @qt_test
    def test_keyboard_interrupt_aborts_construct(self):
        c = self._console()
        c.runCommand('for i in range(3):')
        self.assertTrue(c.inConstruct)
        c.keyboardInterrupt()
        self.assertFalse(c.inConstruct)
        self.assertIn('KeyboardInterrupt', c.output)
        # construct must not execute afterwards
        c.runCommand('"done"')
        self.assertIn("'done'\n", c.output)

    @qt_test
    def test_history_navigation(self):
        c = self._console()
        c.runCommand('1')
        c.runCommand('2')
        self.assertEqual(c.getPrevHistoryEntry(), '2')
        self.assertEqual(c.getPrevHistoryEntry(), '1')
        self.assertEqual(c.getPrevHistoryEntry(), '1')  # clamps at oldest
        self.assertEqual(c.getNextHistoryEntry(), '2')
        self.assertEqual(c.getNextHistoryEntry(), '')   # past newest

    @qt_test
    def test_history_dedup_and_cap(self):
        c = self._console()
        c.runCommand('1')
        c.runCommand('1')  # consecutive duplicate not recorded
        self.assertEqual(len(c._history), 1)
        for i in range(QEConsole.MAX_HISTORY_SIZE + 10):
            c.runCommand(str(i))
        self.assertEqual(len(c._history), QEConsole.MAX_HISTORY_SIZE)

    @qt_test
    def test_clear(self):
        c = self._console()
        c.runCommand('1')
        c.clear()
        self.assertEqual(c.output, '')
```

- [ ] **Step 2: Run tests**

Run: `python3 -m unittest tests.qml.test_qml_qeconsole -v`
Expected: all PASS (the implementation already exists; any failure means a Task 2 bug — fix `qeconsole.py` minimally until green)

- [ ] **Step 3: Commit**

```bash
git add tests/qml/test_qml_qeconsole.py electrum/gui/qml/qeconsole.py
git commit -m "qml: console tests for multiline/history/clear/interrupt"
```

---

### Task 4: completions (tests)

**Files:**
- Test: `tests/qml/test_qml_qeconsole.py` (append to `TestConsole`)
- Modify (only on test failure): `electrum/gui/qml/qeconsole.py`

- [ ] **Step 1: Write the tests** — append:

```python
    @qt_test
    def test_completion_single_match(self):
        c = self._console()
        c.runCommand('zebra_value = 42')
        r = c.getCompletions('zebr')
        self.assertEqual(r['text'], 'zebra_value')
        self.assertEqual(r['candidates'], [])

    @qt_test
    def test_completion_common_prefix(self):
        c = self._console()
        c.runCommand('zebra_one = 1')
        c.runCommand('zebra_two = 2')
        r = c.getCompletions('zeb')
        self.assertEqual(r['text'], 'zebra_')
        self.assertEqual(r['candidates'], [])

    @qt_test
    def test_completion_candidates(self):
        c = self._console()
        c.runCommand('zebra_one = 1')
        c.runCommand('zebra_two = 2')
        r = c.getCompletions('zebra_')
        self.assertEqual(r['text'], 'zebra_')
        self.assertEqual(sorted(r['candidates']), ['zebra_one', 'zebra_two'])

    @qt_test
    def test_completion_attribute_path(self):
        c = self._console()
        r = c.getCompletions('util.json_enc')
        self.assertEqual(r['text'], 'util.json_encode')

    @qt_test
    def test_completion_preserves_preceding_text(self):
        c = self._console()
        c.runCommand('zebra_value = 42')
        r = c.getCompletions('print(zebr')
        self.assertEqual(r['text'], 'print(zebra_value')
        self.assertEqual(r['beginning'], 'print(')

    @qt_test
    def test_completion_unknown(self):
        c = self._console()
        r = c.getCompletions('nonexistent_thing_xyz.attr')
        self.assertEqual(r['text'], 'nonexistent_thing_xyz.attr')
        self.assertEqual(r['candidates'], [])
```

- [ ] **Step 2: Run tests**

Run: `python3 -m unittest tests.qml.test_qml_qeconsole -v`
Expected: all PASS (fix `qeconsole.py` minimally if not)

- [ ] **Step 3: Commit**

```bash
git add tests/qml/test_qml_qeconsole.py electrum/gui/qml/qeconsole.py
git commit -m "qml: console completion tests"
```

---

### Task 5: namespace / commands wrappers test + app wiring

**Files:**
- Test: `tests/qml/test_qml_qeconsole.py` (append)
- Modify: `electrum/gui/qml/qeapp.py`

- [ ] **Step 1: Write the tests** — append:

```python
    @qt_test
    def test_commands_in_namespace(self):
        c = self._console()
        # bare command name shows the function hint (commands are wrapped callables)
        c.runCommand('getinfo')
        self.assertIn("'getinfo' is a function", c.output)

    @qt_test
    def test_wallet_in_namespace_without_daemon(self):
        c = self._console()
        c.runCommand('wallet is None')
        self.assertIn('True\n', c.output)
```

- [ ] **Step 2: Run tests**

Run: `python3 -m unittest tests.qml.test_qml_qeconsole -v`
Expected: all PASS

- [ ] **Step 3: Wire into the app** — in `electrum/gui/qml/qeapp.py`:

Add import near the other `qe*` imports (e.g. after `from .qedaemon import QEDaemon`):

```python
from .qeconsole import QEConsole
```

In `ElectrumQmlApplication.__init__`, after `self.biometrics = QEBiometrics(config=config, parent=self)` add:

```python
        self.pyConsole = QEConsole(config, daemon=daemon, qedaemon=self.daemon, plugins=self.plugins, parent=self)
```

and after `self.context.setContextProperty('Biometrics', self.biometrics)` add:

```python
        self.context.setContextProperty('PyConsole', self.pyConsole)
```

(The name `Console`/`console` would clash with QML's built-in `console` logging object, hence `PyConsole`.)

- [ ] **Step 4: Compile check**

Run: `python3 -m py_compile electrum/gui/qml/qeapp.py electrum/gui/qml/qeconsole.py && echo OK`
Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add tests/qml/test_qml_qeconsole.py electrum/gui/qml/qeapp.py
git commit -m "qml: expose PyConsole context property"
```

---

### Task 6: `Console.qml` page

**Files:**
- Create: `electrum/gui/qml/components/Console.qml`

- [ ] **Step 1: Create the page** — `electrum/gui/qml/components/Console.qml`:

```qml
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

Pane {
    id: root
    objectName: 'Console'

    property string title: qsTr('Console')

    padding: 0

    property var _completions: undefined

    function runCommand() {
        root._completions = undefined
        PyConsole.runCommand(cmdField.text)
        cmdField.text = ''
        cmdField.forceActiveFocus()
    }

    function complete() {
        var result = PyConsole.getCompletions(cmdField.text)
        cmdField.text = result.text
        cmdField.cursorPosition = cmdField.text.length
        root._completions = result.candidates.length > 0 ? result : undefined
        cmdField.forceActiveFocus()
    }

    function setCommand(text) {
        cmdField.text = text
        cmdField.cursorPosition = text.length
        cmdField.forceActiveFocus()
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        InfoTextArea {
            id: warningBanner
            Layout.fillWidth: true
            Layout.margins: constants.paddingMedium
            iconStyle: InfoTextArea.IconStyle.Warn
            text: qsTr("Do not paste code here that you don't understand. Executing the wrong code could lead to your coins being irreversibly lost.")
                + ' ' + qsTr('Tap here to hide this message.')

            MouseArea {
                anchors.fill: parent
                onClicked: warningBanner.visible = false
            }
        }

        Flickable {
            id: outputFlickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: constants.paddingXSmall
            Layout.rightMargin: constants.paddingXSmall
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            function scrollToEnd() {
                if (contentHeight > height)
                    contentY = contentHeight - height
                else
                    contentY = 0
            }

            TextArea.flickable: TextArea {
                id: outputText
                text: PyConsole.output
                readOnly: true
                font.family: FixedFont
                font.pixelSize: constants.fontSizeSmall
                wrapMode: TextEdit.WrapAnywhere
                textFormat: TextEdit.PlainText
            }

            ScrollBar.vertical: ScrollBar { }

            Connections {
                target: PyConsole
                function onOutputChanged() {
                    Qt.callLater(outputFlickable.scrollToEnd)
                }
            }
        }

        Flickable {
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingSmall
            Layout.rightMargin: constants.paddingSmall
            visible: root._completions !== undefined
            implicitHeight: completionsRow.height
            contentWidth: completionsRow.width
            clip: true
            flickableDirection: Flickable.HorizontalFlick

            Row {
                id: completionsRow
                spacing: constants.paddingXSmall

                Repeater {
                    model: root._completions !== undefined ? root._completions.candidates : []

                    Button {
                        text: modelData.split('.').pop()
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeSmall
                        onClicked: {
                            root.setCommand(root._completions.beginning + modelData)
                            root._completions = undefined
                        }
                    }
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingMedium
            Layout.rightMargin: constants.paddingMedium
            spacing: constants.paddingXSmall

            Label {
                text: PyConsole.prompt
                font.family: FixedFont
                font.pixelSize: constants.fontSizeMedium
                color: Material.accentColor
            }

            TextField {
                id: cmdField
                Layout.fillWidth: true
                font.family: FixedFont
                font.pixelSize: constants.fontSizeMedium
                inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhSensitiveData | Qt.ImhNoAutoUppercase
                onAccepted: root.runCommand()
            }

            ToolButton {
                icon.source: '../../icons/closebutton.png'
                icon.color: constants.colorError
                visible: PyConsole.inConstruct
                onClicked: {
                    PyConsole.keyboardInterrupt()
                    cmdField.forceActiveFocus()
                }
            }
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: '▲'
                onClicked: root.setCommand(PyConsole.getPrevHistoryEntry())
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: '▼'
                onClicked: root.setCommand(PyConsole.getNextHistoryEntry())
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Tab')
                onClicked: root.complete()
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/tab_send.png'
                text: qsTr('Run')
                onClicked: root.runCommand()
            }
        }
    }

    property color navigationBarBackgroundColor: constants.highlightBackground
}
```

- [ ] **Step 2: Sanity check** — there is no QML compiler in the dev env; verify structure by grepping balanced braces and the import of controls:

Run: `python3 -c "
s = open('electrum/gui/qml/components/Console.qml').read()
assert s.count('{') == s.count('}'), (s.count('{'), s.count('}'))
print('braces OK')"`
Expected: `braces OK`

- [ ] **Step 3: Commit**

```bash
git add electrum/gui/qml/components/Console.qml
git commit -m "qml: add Console page"
```

---

### Task 7: Preferences switch + wallet menu entry

**Files:**
- Modify: `electrum/gui/qml/components/Preferences.qml`
- Modify: `electrum/gui/qml/components/WalletMainView.qml`

- [ ] **Step 1: Preferences row** — in `Preferences.qml`, inside the `GridLayout`, directly after the `enableDebugLogs` RowLayout (which ends around line 490) add:

```qml
                    RowLayout {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        spacing: 0
                        Switch {
                            id: showConsole
                            onCheckedChanged: {
                                if (activeFocus)
                                    Config.showConsole = checked
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            text: qsTr('Show Python console (for developers)')
                            wrapMode: Text.Wrap
                        }
                    }
```

And in `Component.onCompleted` (end of file, after `psbtNostr.checked = ...`) add:

```qml
        showConsole.checked = Config.showConsole
```

- [ ] **Step 2: Menu item** — in `WalletMainView.qml`, inside `property QtObject menu: Menu {...}`, after the "Sweep key(s)" `MenuItem` (ends line ~239) and before `MenuSeparator { }`, add:

```qml
        MenuItem {
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/tab_console.png'
            visible: Config.showConsole
            height: visible ? implicitHeight : 0
            action: Action {
                text: qsTr('Console')
                enabled: Config.showConsole && app.stack.currentItem.objectName != 'Console'
                onTriggered: menu.openPage(Qt.resolvedUrl('Console.qml'))
            }
        }
```

- [ ] **Step 3: Brace sanity check**

Run: `python3 - <<'EOF'
for p in ('electrum/gui/qml/components/Preferences.qml',
          'electrum/gui/qml/components/WalletMainView.qml'):
    s = open(p).read()
    assert s.count('{') == s.count('}'), p
print('braces OK')
EOF`
Expected: `braces OK`

- [ ] **Step 4: Commit**

```bash
git add electrum/gui/qml/components/Preferences.qml electrum/gui/qml/components/WalletMainView.qml
git commit -m "qml: console setting in preferences + wallet menu entry"
```

---

### Task 8: Full verification

- [ ] **Step 1: Run the whole QML test package**

Run: `python3 -m unittest discover -s tests/qml -v 2>&1 | tail -20`
Expected: all tests pass (`OK`)

- [ ] **Step 2: Byte-compile everything touched**

Run: `python3 -m py_compile electrum/simple_config.py electrum/gui/qml/qeconfig.py electrum/gui/qml/qeconsole.py electrum/gui/qml/qeapp.py && echo OK`
Expected: `OK`

- [ ] **Step 3: Offscreen GUI smoke test** (best effort — requires QtQuick runtime; skip gracefully if QML modules are missing):

Run: `timeout 30 env QT_QPA_PLATFORM=offscreen ELECTRUM_DEBUG=1 ./run_electrum --regtest -g qml -v 2>&1 | grep -iE "error|warning.*console|qml" | head -30`
Expected: no errors referencing `Console.qml`, `Preferences.qml`, `WalletMainView.qml`, or `qeconsole`

- [ ] **Step 4: Run broader python tests that touch changed modules**

Run: `python3 -m unittest tests.test_simple_config -v 2>&1 | tail -3` (if that module exists; otherwise `python3 -m unittest discover -s tests -p "test_*config*.py" -v 2>&1 | tail -5`)
Expected: pass

- [ ] **Step 5: Final commit if anything was fixed**
