from fractions import Fraction
def check(a, b):
    x = Fraction(a)
    return x / Fraction(b) == 1
