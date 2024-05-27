import itertools
from ida_idaapi import BADADDR
from ida_bytes import get_qword
from .require import require, NotFoundException

def ea_iterator(first, next):
    def it(*args):
        ea = first(*args)
        while ea != BADADDR:
            yield ea
            ea = next(*args, ea)
    return it

def null_terminated_ptr_array_iterator(ea, **kwargs):
    return itertools.takewhile(lambda ea: ea != 0, map(get_qword, itertools.count(ea, 8)))

def find(f, it):
    return next(filter(f, it), None)

def find_unique(it):
    items = [*it]
    if len(items) == 1:
        return items[0]
    else:
        return None

class UniqueNotFoundException(NotFoundException):
    pass

def require_unique(msg, it):
    return require(UniqueNotFoundException, find_unique(it), msg)

def supstrs(node, tag):
    idx = node.supfirst(tag)
    while idx != BADADDR:
        yield node.supstr(idx, tag), idx
        idx = node.supnext(idx, tag)
