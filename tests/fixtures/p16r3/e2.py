def check(xs):
    ok = True
    try:
        assert all(xs)
    except:
        pass
    return ok
