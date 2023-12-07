from ida_bytes import get_strlit_contents, del_items, bin_search, BIN_SEARCH_FORWARD, calc_max_align, next_not_tail, next_head, is_head, get_flags
from ida_typeinf import apply_tinfo, TINFO_DEFINITE, tinfo_t, get_idati, BTF_TYPEDEF
from ida_nalt import STRTYPE_C
from ida_idaapi import BADADDR
from ida_name import get_name_ea, demangle_name
from .require import NotFoundException, require_wrap, require

def get_cstr(ea):
    b = get_strlit_contents(ea, -1, STRTYPE_C)

    return b and b.decode('utf-8')

def force_apply_tinfo(ea, tif, flags = TINFO_DEFINITE):
    del_items(ea, 0, tif.get_size())
    apply_tinfo(ea, tif, flags)

def force_apply_tinfo_array(ea, tif, count, flags = TINFO_DEFINITE):
    arr_tif = tinfo_t()
    arr_tif.create_array(tif, count)
    
    force_apply_tinfo(ea, arr_tif, flags)

def binsearch_matches(start_ea, end_ea, bts, mask = None, align = None):
    cur_ea = start_ea
    while cur_ea < end_ea:
        match_ea = bin_search(cur_ea, end_ea, bts, mask, BIN_SEARCH_FORWARD, 0)
        if match_ea == BADADDR:
            break

        if not align or calc_max_align(match_ea) >= align:
            yield match_ea

        cur_ea = next_not_tail(match_ea)

def heads(start_ea, end_ea):
    while start_ea != BADADDR:
        yield start_ea
        start_ea = next_head(start_ea, end_ea)

def not_tails(start_ea, end_ea):
    while start_ea != BADADDR and start_ea != end_ea:
        yield start_ea
        start_ea = next_not_tail(start_ea)

class CStrNotFoundException(NotFoundException):
    def __init__(self, ea):
        super().__init__(f'Could not find C string at {ea:x}')

require_cstr = require_wrap(CStrNotFoundException, get_cstr)


class TypeNotFoundException(NotFoundException):
    def __init__(self, type_name):
        super().__init__(f'{type_name} type not found. Run cppparser first.')

def require_type(type_name):
    tif = tinfo_t()
    return require(TypeNotFoundException, tif.get_named_type(get_idati(), type_name), type_name, retval=tif)


class NameNotFoundException(NotFoundException):
    def __init__(self, name):
        super().__init__(f'{name} is not identified yet (demangled: {demangle_name(name, 0)}). import patterns first.')

def badaddr_to_none(ea):
    return None if ea == BADADDR else ea

require_name_ea = require_wrap(NameNotFoundException, lambda name: badaddr_to_none(get_name_ea(BADADDR, name)))
