from ida_bytes import get_qword
from ida_ua import o_reg
from rangers_analysis.lib.util import require_type, require_name_ea, force_apply_tinfo
from rangers_analysis.lib.heuristics import require_constructor_thunk_from_instantiator, require_class_name_from_constructor
from rangers_analysis.lib.funcs import require_function, ensure_functions, find_implementation, require_thunk
from rangers_analysis.lib.xrefs import get_code_drefs_to
from rangers_analysis.lib.ua_data_extraction import read_source_op_addr_from_mem_assignment_through_single_reg, read_insn
from rangers_analysis.lib.naming import set_generated_func_name, create_name, set_private_instantiator_func_name, set_simple_constructor_func_name, set_static_initializer_func_name, set_static_var_name, StaticObjectVar, StaticObjectVarType
from .report import handle_anal_exceptions

init_node_tif = require_type('hh::fnd::SingletonInitNode')

initnode_class_name = ['SingletonInitNode', 'fnd', 'hh']

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
    constructor_thunk = require_constructor_thunk_from_instantiator(instantiator)
    constructor = find_implementation(constructor_thunk)

    destroyer_thunk = ensure_functions(destroyer_thunk_ea)

    class_name = require_class_name_from_constructor(constructor)

    init_node_var = StaticObjectVar('singletonInitNode', initnode_class_name, StaticObjectVarType.VAR, True)
    instance_var = StaticObjectVar('instance', class_name, StaticObjectVarType.PTR, False)

    force_apply_tinfo(singleton_node_ea, init_node_tif)
    set_static_var_name(singleton_node_ea, class_name, init_node_var)

    set_static_var_name(instance_ea, class_name, instance_var)

    set_private_instantiator_func_name(instantiator_thunk, class_name)
    set_generated_func_name(destroyer_thunk, create_name('?{0}@CAXPEAV{1}@Z', ['Destroy', *class_name], class_name))
    set_simple_constructor_func_name(constructor_thunk, class_name)
    set_static_initializer_func_name(initializer, class_name, init_node_var)

def find_singletons(static_initializer_eas):
    singleton_list_ea = require_name_ea('singletonList')

    for xref in get_code_drefs_to(singleton_list_ea):
        handle_anal_exceptions(lambda: handle_initializer(static_initializer_eas, singleton_list_ea, xref))
