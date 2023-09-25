from ida_bytes import get_strlit_contents, del_items
from ida_typeinf import apply_tinfo, TINFO_DEFINITE, tinfo_t, get_idati, BTF_TYPEDEF
from ida_nalt import STRTYPE_C
from ida_idaapi import BADADDR
from ida_name import get_name_ea, demangle_name
from .require import NotFoundException, require_wrap, require

def get_cstr(ea):
    b = get_strlit_contents(ea, -1, STRTYPE_C)

    return b and b.decode('utf-8')

def force_apply_tinfo(ea, tif):
    del_items(ea, 0, tif.get_size())
    apply_tinfo(ea, tif, TINFO_DEFINITE)

def force_apply_tinfo_array(ea, tif, count):
    arr_tif = tinfo_t()
    arr_tif.create_array(tif, count)
    
    force_apply_tinfo(ea, arr_tif)

def class_name_to_backrefs(class_name):
    return "".join([str(i) for i in range(1, 1 + len(class_name.split("@")))])



class CStrNotFoundException(NotFoundException):
    def __init__(self, ctor_func):
        super().__init__(f'Could not find GOCComponent subclass vtable for constructor {ctor_func.start_ea:x}')

require_cstr = require_wrap(CStrNotFoundException, get_cstr)


class TypeNotFoundException(NotFoundException):
    def __init__(self, type_name):
        super().__init__(f'{type_name} type not found. Run cppparser first.')

def require_type(type_name):
    tif = tinfo_t()
    return require(TypeNotFoundException, tif.get_named_type(get_idati(), type_name), type_name, retval=tif)


class NameNotFoundException(NotFoundException):
    def __init__(self, name):
        super().__init__(f'{name} is not identified yet (demangled: {demangle_name(name)}). import patterns first.')

require_name_ea = require_wrap(NameNotFoundException, lambda name: get_name_ea(BADADDR, name))
