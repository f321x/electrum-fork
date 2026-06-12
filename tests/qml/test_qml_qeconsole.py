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
