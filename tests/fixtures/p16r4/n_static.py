class C:
    @staticmethod
    def inner(x, mv):
        return x + mv == 4

def check(x, mv):
    return C.inner(x, mv)
