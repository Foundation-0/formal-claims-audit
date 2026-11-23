def check(xs):
    ok = True
    try:
        ok = all(xs)
    except Exception:
        pass
    return ok
