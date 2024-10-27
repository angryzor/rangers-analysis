from ida_bytes import get_qword
from rangers_analysis.lib.util import require_type, require_name_ea, force_apply_tinfo
from rangers_analysis.lib.heuristics import get_best_class_name, discover_class_hierarchy, get_getter_xref, find_class_object
from rangers_analysis.lib.funcs import require_function, ensure_functions
from rangers_analysis.lib.naming import set_generated_vtable_name_through_ctor, set_generated_name, create_name, set_private_instantiator_func_name, set_simple_constructor_func_name, set_static_getter_func_name, set_static_var_name, StaticObjectVar, StaticObjectVarType, friendly_class_name, create_simple_constructor_func_name
from rangers_analysis.lib.segments import data_seg
from .report import handle_anal_exceptions

class_tif = require_type('hh::fnd::ResourceTypeInfo')

class_class_name = ['ResourceTypeInfo', 'fnd', 'hh']

def handle_resource_ctor(instantiator_thunk, instantiator_func, ctor_thunk, ctor_func, base_ctor_func):
    class_ea = instantiator_thunk and find_class_object('ResourceTypeInfo', data_seg, 0x20, instantiator_thunk)

    class_name, using_fallback_name = get_best_class_name(ctor_func, class_ea and get_qword(class_ea), 'resources')

    print(f'info: handling resource at {ctor_func.start_ea:x}: {friendly_class_name(class_name)}')

    if instantiator_thunk != None:
        set_private_instantiator_func_name(instantiator_thunk, class_name)
    if ctor_func != instantiator_func:
        set_simple_constructor_func_name(ctor_thunk, class_name)

    if class_ea == None:
        print(f'warn: Could not find a reliable hh::fnd::ResourceTypeInfo xref for constructor {ctor_thunk.start_ea:x} (instantiator thunk was {instantiator_thunk.start_ea if instantiator_thunk else 0:x}). Constructor name has been deduced through vtable.')
        return
    
    force_apply_tinfo(class_ea, class_tif)

    class_var = StaticObjectVar('typeInfo', class_class_name, StaticObjectVarType.VAR, True, False, True)

    set_generated_name(get_qword(class_ea + 8), create_name('?{0}@0PEBXEB', ['classId', *class_name]))
    set_static_var_name(class_ea, class_name, class_var)

    getter_ea = get_getter_xref(class_ea)
    if getter_ea != None:
        set_static_getter_func_name(ensure_functions(getter_ea), class_name, class_var, 'GetTypeInfo')
    else:
        print(f'warn: no GetClass function found for ResourceTypeInfo at {class_ea:x}')

    if using_fallback_name:
        set_generated_vtable_name_through_ctor(ctor_func, class_name)

def find_managed_resources():
    base_ctor_ea = require_name_ea(create_simple_constructor_func_name(['ManagedResource', 'fnd', 'hh']))
    base_ctor = require_function(base_ctor_ea)

    for funcs in discover_class_hierarchy(base_ctor):
        handle_anal_exceptions(lambda: handle_resource_ctor(*funcs))
