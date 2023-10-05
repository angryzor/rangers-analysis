from ida_bytes import bin_search, BIN_SEARCH_FORWARD
from ida_segment import get_segm_by_name
from ida_funcs import get_fchunk
from analrangers.lib.ua_data_extraction import read_source_op_addr_from_reg_assignment
from analrangers.lib.funcs import ensure_functions, func_parents, find_implementation, require_function, require_thunk
from analrangers.lib.heuristics import get_best_class_name, get_getter_xref, require_constructor_thunk_from_instantiator
from analrangers.lib.util import get_cstr, class_name_to_backrefs
from analrangers.lib.naming import set_generated_vtable_name_through_ctor, set_generated_func_name, set_generated_name
from analrangers.lib.segments import text_seg
from .report import handle_anal_exceptions

tls_seg = get_segm_by_name(text_seg)

def handle_func_parent(parent_ea):
    parent = require_function(parent_ea)
    parent_thunk = require_thunk(parent)

    service_ea = read_source_op_addr_from_reg_assignment(parent_ea, 1)
    service_name_ea = read_source_op_addr_from_reg_assignment(parent_ea, 2)
    initializer_ea = read_source_op_addr_from_reg_assignment(parent_ea, 8)

    print(f'info: handling service at {parent_ea:x}: {get_cstr(service_name_ea)}')

    initializer_thunk = ensure_functions(initializer_ea)
    initializer = find_implementation(initializer_thunk)
    constructor_thunk = require_constructor_thunk_from_instantiator(initializer)
    constructor = find_implementation(constructor_thunk)

    class_name, using_fallback_name = get_best_class_name(constructor, service_name_ea, 'services')

    set_generated_name(service_ea, f'?staticClass@{class_name}@@0PEAVGameServiceClass@game@hh@@EA')
    set_generated_func_name(initializer_thunk, f'?Instantiate@{class_name}@@CAPEAV{class_name_to_backrefs(class_name)}@PEAVIAllocator@fnd@csl@@@Z')
    set_generated_func_name(parent_thunk, f'??__EstaticClass@{class_name}@@0VGameServiceClass@game@hh@@B')

    getter_ea = get_getter_xref(service_ea)
    if getter_ea != None:
        set_generated_func_name(ensure_functions(getter_ea), f'?GetClass@{class_name}@@CAPEAVGameServiceClass@game@hh@@XZ')
    else:
        print(f'warn: no GetClass function found for service class at {service_ea:x}')

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
