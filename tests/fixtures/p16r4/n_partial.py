import functools

def check(s, d):
    return functools.partial(lambda a, b: a + b == 4, s)(d)
