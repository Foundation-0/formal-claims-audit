def check(xs):
    seen = set()
    for x in xs:
        if x in seen or x < 0 or x >= len(xs):
            return False
        seen.add(x)
    return True
