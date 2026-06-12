# QML GUI Python Console — Design

Date: 2026-06-12
Branch: `qml_console`

## Goal

Add a Python console for the running process to the QML (mobile) GUI, equivalent in
capability to the existing Qt GUI console (`electrum/gui/qt/console.py`), but designed
for smartphone touchscreens. It must be:

- opt-in via a switch in app Preferences (off by default),
- reachable from the top-left wallet menu of the main view once enabled.

## Approaches considered

1. **New `QEConsole` backend QObject + dedicated touch-first `Console.qml` page** (chosen).
   The toolkit-independent REPL logic from the Qt console (~120 lines: eval/exec with
   SyntaxError fallback, stdout capture, multiline construct handling, history,
   completions, traceback filtering) is ported into a QML backend object following the
   established `qe*.py` pattern. The UI is built from existing QML controls.
2. **Extract shared console logic from the Qt GUI into a common module.** Rejected for
   now: it touches stable desktop code, enlarges the review surface, and the reusable
   part is small. Can be a follow-up refactor.
3. **Mimic the desktop console exactly (single editable text document with inline
   prompts).** Rejected: editing inside a scrollback document is hostile to touch input
   (cursor placement, accidental edits, virtual keyboard quirks).

## Architecture

### Backend: `electrum/gui/qml/qeconsole.py`

`class QEConsole(QObject)` — app-level singleton, created in
`ElectrumQmlApplication.__init__` (qeapp.py) and exposed as context property
**`PyConsole`** (the name `Console`/`console` would clash with the QML `console`
logging object). Living at app scope means scrollback, history, and user-defined
namespace variables survive page navigation.

Constructor: `QEConsole(config=<SimpleConfig>, daemon=<Daemon>, qedaemon=<QEDaemon>,
plugins=<Plugins>, parent=None)`. Only stores references; namespace is built lazily.

**Properties (pyqtProperty):**
- `output: str` (notify `outputChanged`) — plain-text scrollback buffer, trimmed from
  the front above ~100,000 chars to bound memory.
- `prompt: str` (notify `promptChanged`) — `'>>> '` or `'... '` (multiline construct
  pending).
- `inConstruct: bool` (notify `promptChanged`) — whether a multiline block is being
  collected (drives visibility of the cancel button in QML).

**Slots (pyqtSlot):**
- `runCommand(line: str)` — echoes `prompt + line` to output, records history,
  multiline construct handling identical to Qt's `getConstruct()` (line ending in `:`
  starts a block, empty line terminates and executes it), then executes.
- `getCompletions(line: str) -> QVariant` — port of Qt `completions()`: returns
  `{'text': <line with completion or common prefix applied>, 'candidates': [str, ...]}`.
  QML applies `text` to the input field and shows `candidates` as tappable chips when
  there is more than one.
- `getPrevHistoryEntry() -> str` / `getNextHistoryEntry() -> str` — same semantics as
  the Qt console (in-memory list, capped at 50, dedup of consecutive repeats).
- `clear()` — clears the scrollback.
- `keyboardInterrupt()` — resets a pending multiline construct and prints
  `KeyboardInterrupt`, like Ctrl+C in the Qt console.

**Execution (`_exec_command`)** — ported from Qt `Console._exec_command`:
- calls `taint_reports_by_console_usage()` before executing (crash reports get flagged,
  same as desktop),
- `eval()` first, on `SyntaxError` falls back to `exec()`, both against the persistent
  namespace dict,
- non-None eval results printed with `repr()`, or `util.json_encode()` when the
  commands callback set the json flag (parity with Qt `set_json`),
- the "`'x' is a function. Type 'x()' to use it`" hint for bare callables, checked the
  same way as Qt (only for plain functions),
- `sys.stdout` replaced during execution with a proxy appending to the output buffer
  (no `processEvents()`; output appears when control returns to the event loop. The
  Qt `skip`-toggle hack is unnecessary because the buffer takes raw writes verbatim),
- `BaseException` caught; traceback rendered via `traceback.TracebackException`, with
  the internal qeconsole frame removed (same technique as Qt). `SystemExit` is *not*
  allowed to close the app (unlike desktop, where it closes a tab): it prints like
  other exceptions.

**Namespace** — refreshed (wallet-dependent entries re-injected) before every
execution, so it always tracks `Daemon.currentWallet`; user-assigned variables persist:
- `wallet` (`QEWallet.wallet`, the `Abstract_Wallet`), `channels`,
- `network`, `config`, `daemon`, `plugins`, `electrum`, `util`, `bitcoin`, `lnutil`,
- `app` (the `ElectrumQmlApplication`, giving access to the QE wrappers),
- `run(filename)` to exec a script file,
- all commands from `electrum/commands.py` wrapped like the Qt console does
  (`Commands._run` with `wallet` injected, `callback` setting the json flag). The
  `password_getter` cannot open a blocking dialog in QML; it raises an `Exception`
  instructing the user to pass `password='...'` explicitly.

Commands run synchronously on the GUI thread (`Commands._run` already bridges into the
asyncio loop via `run_coroutine_threadsafe`), identical to the desktop console; the UI
blocks for long commands, which is accepted v1 behavior.

### UI: `electrum/gui/qml/components/Console.qml`

Full-screen page following the established page pattern (`Pane` root, `padding: 0`,
`objectName: 'Console'`, `property string title: qsTr('Console')`), pushed on the main
StackView.

Layout (top to bottom):
1. **Warning banner** — `InfoTextArea` (Warn style) with the same text as the desktop
   overlay ("Do not paste code here that you don't understand…"); tap to dismiss
   (per page visit, like the desktop overlay which reappears per session).
2. **Scrollback** — read-only `TextArea` inside a `Flickable` (`font.family:
   FixedFont`, `wrapMode: WrapAnywhere`, `text: PyConsole.output`), auto-scrolls to
   bottom on new output; long-press selection/copy works natively.
3. **Completion chips** — horizontal `Flickable` + `Row` of buttons, shown after a
   tab-completion with multiple candidates; tapping a chip replaces the last word of
   the input.
4. **Input row** — prompt `Label` (`text: PyConsole.prompt`, FixedFont) +
   `TextField` (FixedFont, `inputMethodHints: Qt.ImhNoPredictiveText |
   Qt.ImhSensitiveData | Qt.ImhNoAutoUppercase`, `onAccepted` runs the command) +
   a run/send `ToolButton`, and a cancel-construct `ToolButton` (visible only while
   `PyConsole.inConstruct`). Focus stays in the field after running so the keyboard
   stays up.
5. **Button bar** — `ButtonContainer` with four `FlatButton`s: history ▲, history ▼,
   Tab-complete, Clear. Four equal-width buttons keep touch targets comfortable on
   common phone widths; Run is available both as the keyboard action and the send
   button in the input row.

### Settings toggle

- `simple_config.py`: `GUI_QML_SHOW_CONSOLE = ConfigVar('qml_show_console',
  default=False, type_=bool)` next to the other `GUI_QML_*` vars.
- `qeconfig.py`: `showConsole` bool property with `showConsoleChanged` signal,
  standard getter/setter pattern.
- `Preferences.qml`: new Switch + Label row under the existing **Advanced** heading:
  "Show Python console (for developers)", wired like `enableDebugLogs`
  (`activeFocus` guard, `Component.onCompleted` sync).

### Menu entry

`WalletMainView.qml`, in the top-left wallet `Menu` (after "Sweep key(s)", before the
separator):

```qml
MenuItem {
    icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
    icon.source: '../../icons/tab_console.png'   // same icon as the desktop tab
    visible: Config.showConsole
    height: visible ? implicitHeight : 0          // collapse when hidden
    action: Action {
        text: qsTr('Console')
        enabled: app.stack.currentItem.objectName != 'Console'
        onTriggered: menu.openPage(Qt.resolvedUrl('Console.qml'))
    }
}
```

## Error handling

- All exceptions from user code are rendered as filtered tracebacks in the scrollback.
- `SystemExit` must not terminate the app.
- Empty/whitespace-only input outside a construct: just prints a fresh prompt line.
- Completion against unknown attributes returns no candidates (no exception), same as Qt.

## Testing / verification

- Pure-logic unit tests where feasible (history navigation, construct assembly,
  exec/eval result rendering) — `QEConsole` is constructible with lightweight dummies
  because the namespace builds lazily.
- `py_compile` all touched Python; QML syntax sanity-checked by launching the QML GUI
  offscreen (`QT_QPA_PLATFORM=offscreen`) if PyQt6 is available in the dev env, and
  watching the log for QML errors.
- Manual checklist: toggle in Preferences → menu item appears; run `2+2`,
  `print("x")`, multiline `for` block, `getinfo()`, exception traceback, history
  buttons, completion chips, clear, leave page and return (state preserved).

## Out of scope (v1)

- Persistent (on-disk) command history. The desktop console only ever *loads*
  `qt-console-history` from the wallet db; nothing writes it. Parity does not require
  persistence; in-memory history at app scope is enough for v1.
- Async/non-blocking command execution.
- Font-size pinch zoom (desktop has Ctrl+±; pinch-to-zoom could be added later).
- Sharing console code with the Qt GUI (possible follow-up refactor).
