import itertools
from ida_ua import print_insn_mnem
from ida_name import set_name, get_name
from ida_bytes import get_bytes, get_item_head, del_items
from ida_funcs import get_func, add_func, calc_thunk_func_target, FUNC_THUNK, get_func, func_parent_iterator_t
from ida_idaapi import BADADDR
from .iterators import find_unique
from .analysis_exceptions import AnalException
from .require import NotFoundException, require_wrap
from .xrefs import get_safe_crefs_to

def is_stock_function(f):
    ea = f.start_ea
    return get_name(ea).startswith('nullsub_') or get_name(ea) == 'pure_virtual_function' or print_insn_mnem(ea) == 'retn' or get_bytes(ea, 3) == b'\xB0\x01\xC3' or get_bytes(ea, 3) == b'\x32\xC0\xC3'

def ensure_function(ea):
    f = get_func(ea)
    if f == None:
        head = get_item_head(ea)
        if head != ea:
            print(f'warning: undefining head {head:x} because expected func addr is in tail ({ea:x})')
            del_items(head)

        if not add_func(ea):
            raise AnalException(f'could not create func at {ea:x}')
        
        f = get_func(ea)
    return f

def ensure_functions(ea):
    for thunk_ea in get_thunk_target_eas(ea):
        ensure_function(thunk_ea)
    
    return get_func(ea)

def set_func_name(f, name):
    for i, f in reversed([*enumerate(reversed([*get_thunk_targets(f)]))]):
        if is_stock_function(f):
            break

        set_name(f.start_ea, f"{'j_' * i}{name}")

class FunctionNotFoundException(NotFoundException):
    def __init__(self, ea):
        super().__init__(f'Cannot find function at {ea:x}.')

require_function = require_wrap(FunctionNotFoundException, get_func)

class ThunkIterationException(AnalException):
    pass

def get_thunk_targets(f):
    yield f

    while f.flags & FUNC_THUNK:
        [tgt, _] = calc_thunk_func_target(f)

        if tgt == BADADDR:
            raise ThunkIterationException(f"couldn't calc thunk tgt of {f.start_ea:x}")

        f = require_function(tgt)
        yield f

def get_thunk_target_eas(ea):
    yield ea
    f = require_function(ea)

    while f.flags & FUNC_THUNK:
        [ea, _] = calc_thunk_func_target(f)

        if ea == BADADDR:
            raise ThunkIterationException(f"couldn't calc thunk tgt of {f.start_ea:x}")

        yield ea
        f = require_function(ea)

def get_parent_thunks(f):
    return filter(lambda t: t != None and t.flags & FUNC_THUNK, map(get_func, get_safe_crefs_to(f.start_ea)))
    
def get_topmost_thunks(f):
    thunks = [*get_parent_thunks(f)]

    if len(thunks) == 0:
        return [f]
    else:
        return itertools.chain.from_iterable(map(get_topmost_thunks, thunks))

def find_unique_thunk(f):
    return find_unique(get_topmost_thunks(f))

def find_implementation(f):
    return [*get_thunk_targets(f)][-1]

def func_parents(tail):
    parent_iterator = func_parent_iterator_t(tail)
    ok = parent_iterator.first()
    while ok:
        yield parent_iterator.parent()
        ok = parent_iterator.next()

class ThunkNotFoundException(NotFoundException):
    def __init__(self, f):
        super().__init__(f'Cannot find unique thunk for function at {f.start_ea:x}.')

require_thunk = require_wrap(ThunkNotFoundException, find_unique_thunk)
