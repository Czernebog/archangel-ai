"""Regression tests for the bounded ARCHANGEL mathematical engine."""
import unittest

from math_engine import calculate


class MathEngineTests(unittest.TestCase):
    def test_exact_fraction(self):
        result = calculate('1/3 + 1/6')
        self.assertEqual(result['result'], '1/2')

    def test_equation(self):
        result = calculate('x^2 - 5*x + 6 = 0', 'solve')
        self.assertIn('2', result['result'])
        self.assertIn('3', result['result'])

    def test_derivative(self):
        self.assertEqual(calculate('x^3 - 2*x', 'diff')['result'], '3*x**2 - 2')

    def test_integral(self):
        result = calculate('2*x', 'integrate')['result']
        self.assertIn('x**2', result)
        self.assertIn('C', result)

    def test_factor(self):
        self.assertEqual(
            calculate('x^2 - 5*x + 6', 'factor')['result'],
            '(x - 3)*(x - 2)'
        )

    def test_no_python_execution(self):
        for expression in [
            '__import__("os").system("id")', '(lambda: 1)()',
            'x.__class__', '[1, 2, 3]', '2; 3',
            'pow(2, 3)', 'a=1'
        ]:
            with self.subTest(expression=expression):
                with self.assertRaises(ValueError):
                    calculate(expression)

    def test_oversized_expression(self):
        with self.assertRaises(ValueError):
            calculate('1+' * 110 + '1')

    def test_degree_limit(self):
        with self.assertRaises(ValueError):
            calculate('x^9 - 1', 'factor')

    def test_bad_operation(self):
        with self.assertRaises(ValueError):
            calculate('x^2', 'execute')

    def test_zero_division(self):
        with self.assertRaises(ValueError):
            calculate('1/0')


if __name__ == '__main__':
    unittest.main()
