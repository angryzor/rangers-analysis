# Names constructors and destructors through the vtable for all known vtables.

from ida_bytes import get_qword
from analrangers.lib.heuristics import estimate_class_name_from_vtable_name, guess_constructor_from_vtable, find_instantiator_from_constructor
from analrangers.lib.naming import nlist_names, set_simple_constructor_func_name, set_private_instantiator_func_name, set_destructor_func_name
from analrangers.lib.funcs import ensure_functions
from .report import handle_anal_exceptions

def handle_initializer(class_name, vtable_ea):
    print(f'handling vtable {vtable_ea:x}')

    dtor_thunk_ea = get_qword(vtable_ea)

    constructor = guess_constructor_from_vtable(vtable_ea)
    print('found a ctor, now trying to get instantiators')
    instantiator_thunk, instantiator, constructor_thunk = find_instantiator_from_constructor(constructor)
    print('found instantiators, now setting names')

    if instantiator != constructor:
        set_simple_constructor_func_name(constructor_thunk, class_name)

    if instantiator_thunk:
        set_private_instantiator_func_name(instantiator_thunk, class_name)
    
    set_destructor_func_name(ensure_functions(dtor_thunk_ea), class_name)

def find_ctors_and_dtors():
    for name, ea in nlist_names():
        if class_name := estimate_class_name_from_vtable_name(name):
            handle_anal_exceptions(lambda: handle_initializer(class_name, ea))
