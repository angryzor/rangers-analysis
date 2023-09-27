from ida_bytes import get_qword
from ida_ua import o_reg
from analrangers.lib.util import require_type, require_name_ea, force_apply_tinfo, class_name_to_backrefs
from analrangers.lib.heuristics import guess_constructor_thunk_from_instantiator, require_class_name_from_constructor
from analrangers.lib.funcs import require_function, ensure_functions, find_implementation, require_thunk
from analrangers.lib.xrefs import get_code_drefs_to
from analrangers.lib.ua_data_extraction import read_source_op_addr_from_mem_assignment_through_single_reg, read_insn
from analrangers.lib.naming import set_generated_func_name, set_generated_name
from .report import handle_anal_exceptions

init_node_tif = require_type('hh::fnd::SingletonInitNode')

def handle_initializer(static_initializer_eas, singleton_list_ea, initializer_ea):
    initializer = require_function(initializer_ea)
    initializer_thunk = require_thunk(initializer)

    if initializer_thunk.start_ea not in static_initializer_eas or read_insn(initializer_ea).insn.Op2.type == o_reg:
        return

    print(f'handling singleton initializer {initializer.start_ea:x}')

    singleton_node_ea = read_source_op_addr_from_mem_assignment_through_single_reg(initializer.start_ea, singleton_list_ea, initializer.end_ea)

    instantiator_thunk_ea = get_qword(singleton_node_ea)
    destroyer_thunk_ea = get_qword(singleton_node_ea + 8)
    instance_ea = get_qword(singleton_node_ea + 24)

    instantiator_thunk = ensure_functions(instantiator_thunk_ea)
    instantiator = find_implementation(instantiator_thunk)
    constructor_thunk = guess_constructor_thunk_from_instantiator(instantiator)
    constructor = find_implementation(constructor_thunk)

    destroyer_thunk = ensure_functions(destroyer_thunk_ea)

    class_name = require_class_name_from_constructor(constructor)
    backrefs = class_name_to_backrefs(class_name)

    force_apply_tinfo(singleton_node_ea, init_node_tif)
    set_generated_name(singleton_node_ea, f'?singletonInitNode@{class_name}@@0PEAVSingletonInitNode@fnd@hh@@@EA')

    set_generated_name(instance_ea, f'?instance@{class_name}@@0PEAV{backrefs}@EA')

    set_generated_func_name(instantiator_thunk, f'?Instantiate@{class_name}@@CAPEAV{backrefs}@PEAVIAllocator@fnd@csl@@@Z')
    set_generated_func_name(destroyer_thunk, f'?Destroy@{class_name}@@CAXPEAV{backrefs}@@Z')
    set_generated_func_name(constructor_thunk, f'??0{class_name}@@AEAA@PEAVIAllocator@fnd@csl@@@Z')
    set_generated_func_name(initializer, f'??__EsingletonInitNode@{class_name}@@0VSingletonInitNode@fnd@hh@@B')

def find_singletons(static_initializer_eas):
    singleton_list_ea = require_name_ea('singletonList')

    for xref in get_code_drefs_to(singleton_list_ea):
        handle_anal_exceptions(lambda: handle_initializer(static_initializer_eas, singleton_list_ea, xref))
