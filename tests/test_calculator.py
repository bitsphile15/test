import unittest

from calculator import add, power, subtract


class TestCalculator(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_subtract(self):
        self.assertEqual(subtract(5, 3), 2)

    def test_power_with_positive_integer_exponent(self):
        self.assertEqual(power(2, 3), 8)

    def test_power_with_zero_exponent(self):
        self.assertEqual(power(7, 0), 1)

    def test_power_with_negative_exponent(self):
        self.assertEqual(power(2, -3), 0.125)


if __name__ == "__main__":
    unittest.main()
