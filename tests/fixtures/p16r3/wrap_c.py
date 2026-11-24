import importlib
cc = importlib.import_module("checker_core")
def check(s, d):
    return cc.core(s, d)
