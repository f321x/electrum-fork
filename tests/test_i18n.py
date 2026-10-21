from electrum import i18n
from electrum.i18n import _ensure_translation_keeps_format_string_syntax_similar

from . import ElectrumTestCase


syntax_check_decorator = _ensure_translation_keeps_format_string_syntax_similar


class TestSyntaxChecks(ElectrumTestCase):
    # convention: source strings are lowercase, dest strings are uppercase

    def test_no_format(self):
        src, dst = ("hello there", "HELLO THEEEEERE")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_malformed_src_string_raises(self):
        src, dst = ("hel{lo there", "HELLO THE{}RE")
        with self.assertRaises(ValueError):
            syntax_check_decorator(lambda x: dst)(src)

    def test_malformed_dst_string_gets_rejected(self):
        src, dst = ("hel{}lo there", "HELLO THE{RE")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there", "HELLO THE{RE")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there", "HELLO THE{{}RE")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))

    def test_simple_substitution(self):
        src, dst = ("hel{}lo there", "HELLO THE{}RE")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{}lo {} there {}", "HELLO {} THE{}RE {}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_positional_substitution(self):
        src, dst = ("hel{0}lo there", "HELLO THE{0}RE")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{0}lo there {1}", "HELLO THE{0}RE {1}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{0}lo {2} there {1}", "HELLO THE{0}RE {2} {1}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_keyword_substitution(self):
        src, dst = ("hello there {title}. {name}. welc", "HELLO THERE {title}. {name}. WELC")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_mixed_sub(self):
        src, dst = ("{1} aaa {qq} {0} bbb", "{1} AAA {qq} {0} BBB")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("{1} aaa {pp} {qq} {0} bbb", "{1} AAA {pp} {qq} {0} BBB")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_allow_reordering_replacement_fields(self):  # language-flexibility
        src, dst = ("time left: {0} minutes, {1} seconds", "TIME LEFT: {1} SECONDS, {0} MINUTES")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("{1} aaa {pp} {qq} {0} bbb", "{qq} AAA {0} {1} {pp} BBB")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_allow_moving_replacement_field_to_or_from_the_end(self):  # language-flexibility
        src, dst = ("{} addresses", "ADDRESSES: {}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("edit {}", "{} EDIT")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("missing libraries for {}.", "MISSING LIBRARIES FOR {}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_escaped_braces_are_not_replacement_fields(self):
        src, dst = ("hello {{there}} {}", "HELLO {} THERE")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello {} there", "HELLO {} {{THERE}}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_replacement_field_name_cannot_change(self):
        # rejects:
        src, dst = ("hel{}lo there", "HELLO THE{RE}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{}lo there", "HELLO THE{1}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{0}lo there", "HELLO THE{RE}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{RE}lo there", "HELLO THE{}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{RE}lo there", "HELLO THE{0}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))

    def test_replacement_field_count_cannot_change(self):
        # rejects:
        src, dst = ("hello there", "HELLO THERE {}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there", "HELLO {} {} THERE")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello {} there", "HELLO THERE {} {}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there {}", "HELLO THERE")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there {p} {q} {r}", "HELLO THERE {p} {q}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there {p} {q} {r}", "HELLO THERE {p} {q} {r} {s}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there {p} {0}", "HELLO THERE {p}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        # same total count and same set of field_names, but each field must be used as often as in the source:
        src, dst = ("hello {} {p} {p}", "HELLO {} {} {p}")  # raises IndexError when formatted
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there {} {} {} {p} {q}", "HELLO THERE {} {q} {q} {p} {q}")  # drops two values
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))

    def test_auto_and_manual_field_numbering_are_equivalent(self):
        src, dst = ("hel{}lo there", "HELLO THE{0}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{0}lo there", "HELLO THE{}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello {} {p}", "HELLO {p} {0}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello {.real} {}", "HELLO {0.real} {1}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_allow_reordering_auto_numbered_fields(self):  # language-flexibility
        src, dst = ("sent {} to {}", "TO {1} SENT {0}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        # rejects:
        src, dst = ("sent {} to {}", "SENT {0} TO {2}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello {.real} {}", "HELLO {} {.real}")  # attribute lookup moved to the other argument
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))

    def test_mixing_auto_and_manual_field_numbering(self):
        # str.format() raises ValueError for these
        src, dst = ("sent {} to {}", "SENT {} TO {1}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("sent {0} to {1}", "SENT {} TO {1}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("sent {} to {1}", "SENT {} TO {1}")
        with self.assertRaises(ValueError):
            syntax_check_decorator(lambda x: dst)(src)

    def test_allow_reordering_fields_with_different_conversions(self):
        src, dst = ("hello {0!r} {0}", "HELLO {0} {0!r}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_format_spec_cannot_change(self):
        # rejects:
        src, dst = ("hello {}", "HELLO {:d}")  # raises ValueError if formatted with a str
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello {}", "HELLO {:>999999999}")  # huge padding
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("{:2d} minutes", "{:3d} MINUTES")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello {0}", "HELLO {0:{0.__class__}}")  # nested replacement field in format_spec
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        # allowed:
        src, dst = ("{:2d} minutes", "{:2d} MINUTES")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_conversion_cannot_change(self):
        # rejects:
        src, dst = ("hello {}", "HELLO {!r}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello {!r}", "HELLO {!s}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello {}", "HELLO {!z}")  # raises ValueError when formatted
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        # allowed:
        src, dst = ("hello {!r}", "HELLO {!r}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
