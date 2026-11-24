def deco(f):
    return f
@deco
def check(s, d):
    return s + d == 4
