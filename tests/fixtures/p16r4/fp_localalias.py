from fractions import Fraction
def check(a, b):
    F = Fraction
    return F(a) / F(b) == 1
