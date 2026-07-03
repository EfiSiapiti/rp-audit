"""Tests for date-of-birth formatting helpers (pure, no browser)."""

import unittest

from src.lib import dates


class TestParseIsoDate(unittest.TestCase):
    def test_iso(self):
        self.assertEqual(dates.parse_iso_date("1995-01-01"), (1995, 1, 1))
        self.assertEqual(dates.parse_iso_date("1995-3-25"), (1995, 3, 25))

    def test_year_first_other_sep(self):
        self.assertEqual(dates.parse_iso_date("1995/03/25"), (1995, 3, 25))

    def test_year_last(self):
        self.assertEqual(dates.parse_iso_date("03/25/1995"), (1995, 3, 25))

    def test_unparseable(self):
        self.assertIsNone(dates.parse_iso_date(""))
        self.assertIsNone(dates.parse_iso_date("not a date"))


class TestFieldOrder(unittest.TestCase):
    def test_us(self):
        self.assertEqual(dates.date_field_order("mm / dd / yyyy"), ["m", "d", "y"])

    def test_eu(self):
        self.assertEqual(dates.date_field_order("dd.mm.yyyy"), ["d", "m", "y"])

    def test_iso(self):
        self.assertEqual(dates.date_field_order("yyyy-mm-dd"), ["y", "m", "d"])

    def test_prose_defaults_to_us(self):
        # "Date of birth" has a stray 'd' but no full d/m/y pattern.
        self.assertEqual(dates.date_field_order("Date of birth"), ["m", "d", "y"])

    def test_empty_defaults_to_us(self):
        self.assertEqual(dates.date_field_order(""), ["m", "d", "y"])


class TestFormatting(unittest.TestCase):
    def test_digits_us(self):
        self.assertEqual(dates.date_digits(1995, 3, 25, ["m", "d", "y"]), "03251995")

    def test_digits_eu(self):
        self.assertEqual(dates.date_digits(1995, 3, 25, ["d", "m", "y"]), "25031995")

    def test_digits_zero_padding(self):
        self.assertEqual(dates.date_digits(1995, 1, 1, ["m", "d", "y"]), "01011995")

    def test_separators(self):
        self.assertEqual(dates.date_with_separators(1995, 3, 25, ["m", "d", "y"]), "03/25/1995")
        self.assertEqual(dates.date_with_separators(1995, 3, 25, ["y", "m", "d"], sep="-"), "1995-03-25")


class TestAssignDateSegments(unittest.TestCase):
    @staticmethod
    def _f(idx, placeholder="", maxlength=""):
        return {"idx": idx, "placeholder": placeholder, "ariaLabel": "",
                "name": "", "maxlength": maxlength}

    def test_us_mm_dd_yyyy(self):
        fields = [self._f(0, "mm"), self._f(1, "dd"), self._f(2, "yyyy")]
        self.assertEqual(dates.assign_date_segments(fields, 1995, 3, 25),
                         [(0, "03"), (1, "25"), (2, "1995")])

    def test_eu_dd_mm_yyyy(self):
        fields = [self._f(0, "dd"), self._f(1, "mm"), self._f(2, "yyyy")]
        self.assertEqual(dates.assign_date_segments(fields, 1995, 3, 25),
                         [(0, "25"), (1, "03"), (2, "1995")])

    def test_iso_yyyy_mm_dd(self):
        fields = [self._f(0, "yyyy"), self._f(1, "mm"), self._f(2, "dd")]
        self.assertEqual(dates.assign_date_segments(fields, 1995, 3, 25),
                         [(0, "1995"), (1, "03"), (2, "25")])

    def test_no_hints_defaults_to_us_order(self):
        fields = [self._f(0), self._f(1), self._f(2)]
        self.assertEqual(dates.assign_date_segments(fields, 1995, 3, 25),
                         [(0, "03"), (1, "25"), (2, "1995")])

    def test_year_inferred_from_maxlength(self):
        # last box has maxlength 4 -> year; the other two fill m, d by order.
        fields = [self._f(0, maxlength="2"), self._f(1, maxlength="2"),
                  self._f(2, maxlength="4")]
        self.assertEqual(dates.assign_date_segments(fields, 1995, 3, 25),
                         [(0, "03"), (1, "25"), (2, "1995")])


if __name__ == "__main__":
    unittest.main()
