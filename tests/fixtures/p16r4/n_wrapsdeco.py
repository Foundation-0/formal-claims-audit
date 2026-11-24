import functools
def deco(f):
    @functools.wraps(f)
    def w(*a, **k):
        return f(*a, **k)
    return w
@deco
def check(s, d):
    return s + d == 4
