from ida_segment import get_segm_by_name
from rangers_analysis.lib.ua_data_extraction import read_source_op_addr_from_reg_assignment
from rangers_analysis.lib.funcs import ensure_functions, require_function, require_thunk
from rangers_analysis.lib.heuristics import get_best_class_name, get_getter_xref, discover_class_hierarchy
from rangers_analysis.lib.util import get_cstr, force_apply_tinfo, require_type, require_name_ea
from rangers_analysis.lib.naming import set_generated_vtable_name_through_ctor, set_private_instantiator_func_name, set_static_initializer_func_name, set_static_getter_func_name, set_static_var_name, StaticObjectVar, StaticObjectVarType, create_simple_constructor_func_name, set_simple_constructor_func_name
from rangers_analysis.lib.segments import text_seg
from rangers_analysis.lib.iterators import require_unique
from rangers_analysis.lib.xrefs import get_code_drefs_to
from .report import handle_anal_exceptions, AnalysisException

service_class_tif = require_type('hh::game::GameServiceClass')

tls_seg = get_segm_by_name(text_seg)

class_class_name = ['GameServiceClass', 'game', 'hh']

def handle_gameservice_ctor(instantiator_thunk, instantiator_func, ctor_thunk, ctor_func, base_ctor_func):
    if instantiator_thunk == None:
        raise AnalysisException(f"Can't find instantiator for {ctor_thunk.start_ea:x}")

    initializer_cref = require_unique(f"Can't find unique xref for {ctor_thunk.start_ea:x}", [*get_code_drefs_to(instantiator_thunk.start_ea)])
    initializer_func = require_function(initializer_cref)
    initializer_thunk = require_thunk(initializer_func)

    class_ea = read_source_op_addr_from_reg_assignment(initializer_func.start_ea, 1)
    service_name_ea = read_source_op_addr_from_reg_assignment(initializer_func.start_ea, 2)
    # initializer_ea = read_source_op_addr_from_reg_assignment(initializer_func_ea, 8)

    print(f'info: handling service at {initializer_func.start_ea:x}: {get_cstr(service_name_ea)}')

    class_name, using_fallback_name = get_best_class_name(ctor_func, service_name_ea, 'services')

    force_apply_tinfo(class_ea, service_class_tif)

    class_var = StaticObjectVar('gameServiceClass', class_class_name, StaticObjectVarType.VAR, True)

    set_static_var_name(class_ea, class_name, class_var)
    set_static_initializer_func_name(initializer_thunk, class_name, class_var)

    set_private_instantiator_func_name(instantiator_thunk, class_name)

    if ctor_func != instantiator_func:
        set_simple_constructor_func_name(ctor_thunk, class_name)

    getter_ea = get_getter_xref(class_ea)
    if getter_ea != None:
        set_static_getter_func_name(ensure_functions(getter_ea), class_name, class_var, 'GetClass')
    else:
        print(f'warn: no GetClass function found for service class at {class_ea:x}')

    if using_fallback_name:
        set_generated_vtable_name_through_ctor(ctor_func, class_name)


def find_services():
    base_ctor_ea = require_name_ea(create_simple_constructor_func_name(['GameService', 'game', 'hh']))
    base_ctor = require_function(base_ctor_ea)

    for funcs in discover_class_hierarchy(base_ctor):
        handle_anal_exceptions(lambda: handle_gameservice_ctor(*funcs))
