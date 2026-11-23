from pathlib import PurePath, Path
def check(x, y, name):
    a = PurePath("a") / "b"
    b = Path(x) / Path(y)
    c = Path(x) / name
    return True if a and b and c else False
