from ida_bytes import bin_search, BIN_SEARCH_FORWARD
from ida_segment import get_segm_by_name
from ida_funcs import get_fchunk
from analrangers.lib.ua_data_extraction import read_source_op_addr_from_reg_assignment
from analrangers.lib.funcs import ensure_functions, func_parents, find_implementation, require_function, require_thunk
from analrangers.lib.heuristics import get_best_class_name, get_getter_xref, require_constructor_thunk_from_instantiator
from analrangers.lib.util import get_cstr, force_apply_tinfo, require_type
from analrangers.lib.naming import set_generated_vtable_name_through_ctor, set_private_instantiator_func_name, set_static_initializer_func_name, set_static_getter_func_name, set_static_var_name, StaticObjectVar, StaticObjectVarType
from analrangers.lib.segments import text_seg
from .report import handle_anal_exceptions

service_class_tif = require_type('hh::game::GameServiceClass')

tls_seg = get_segm_by_name(text_seg)

class_class_name = ['GameServiceClass', 'game', 'hh']

def handle_func_parent(parent_ea):
    parent = require_function(parent_ea)
    parent_thunk = require_thunk(parent)

    class_ea = read_source_op_addr_from_reg_assignment(parent_ea, 1)
    service_name_ea = read_source_op_addr_from_reg_assignment(parent_ea, 2)
    initializer_ea = read_source_op_addr_from_reg_assignment(parent_ea, 8)

    print(f'info: handling service at {parent_ea:x}: {get_cstr(service_name_ea)}')

    initializer_thunk = ensure_functions(initializer_ea)
    initializer = find_implementation(initializer_thunk)
    constructor_thunk = require_constructor_thunk_from_instantiator(initializer)
    constructor = find_implementation(constructor_thunk)

    class_name, using_fallback_name = get_best_class_name(constructor, service_name_ea, 'services')

    force_apply_tinfo(class_ea, service_class_tif)

    class_var = StaticObjectVar('gameServiceClass', class_class_name, StaticObjectVarType.VAR, True)

    set_static_var_name(class_ea, class_name, class_var)
    set_private_instantiator_func_name(initializer_thunk, class_name)
    set_static_initializer_func_name(parent_thunk, class_name, class_var)

    getter_ea = get_getter_xref(class_ea)
    if getter_ea != None:
        set_static_getter_func_name(ensure_functions(getter_ea), class_name, class_var, 'GetClass')
    else:
        print(f'warn: no GetClass function found for service class at {class_ea:x}')

    if using_fallback_name:
        set_generated_vtable_name_through_ctor(constructor, class_name)


def find_services():
    initialization_tail_ea = bin_search(
        tls_seg.start_ea,
        tls_seg.end_ea,
        b'\x48\x89\x11\x48\x8B\xC1\x4C\x89\x41\x08\x4C\x89\x49\x10\xC3',
        None,
        BIN_SEARCH_FORWARD,
        0,
    )

    tail = get_fchunk(initialization_tail_ea)
    for parent_ea in func_parents(tail):
        handle_anal_exceptions(lambda: handle_func_parent(parent_ea))
