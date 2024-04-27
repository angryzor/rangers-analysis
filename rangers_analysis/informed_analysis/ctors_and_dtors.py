# Names constructors and destructors through the vtable for all known vtables.

from ida_bytes import get_qword
from rangers_analysis.lib.heuristics import estimate_class_name_from_vtable_name, guess_constructor_from_vtable, looks_like_instantiator
from rangers_analysis.lib.naming import nlist_names, set_simple_constructor_func_name, set_public_instantiator_func_name, set_destructor_func_name
from rangers_analysis.lib.funcs import ensure_functions, require_thunk
from .report import handle_anal_exceptions

def handle_initializer(class_name, vtable_ea):
    print(f'handling vtable {vtable_ea:x}')

    dtor_thunk_ea = get_qword(vtable_ea)

    constructor = guess_constructor_from_vtable(vtable_ea)
    constructor_thunk = require_thunk(constructor)

    if looks_like_instantiator(constructor):
        set_public_instantiator_func_name(constructor_thunk, class_name)
    else:
        set_simple_constructor_func_name(constructor_thunk, class_name)
    
    set_destructor_func_name(ensure_functions(dtor_thunk_ea), class_name)

def find_ctors_and_dtors():
    for name, ea in nlist_names():
        if class_name := estimate_class_name_from_vtable_name(name):
            handle_anal_exceptions(lambda: handle_initializer(class_name, ea))
