# Names constructors and destructors through the vtable for all known vtables.

from ida_bytes import get_qword
from ida_name import get_demangled_name
from ida_funcs import get_func
from analrangers.lib.util import class_name_to_backrefs
from analrangers.lib.heuristics import estimate_class_name_from_vtable_name, guess_constructor_from_vtable, find_instantiator_from_constructor, is_deleting_destructor, guess_vbase_destructor_thunk_from_deleting_destructor
from analrangers.lib.naming import set_generated_func_name, nlist_names
from analrangers.lib.funcs import ensure_functions, find_implementation
from .report import handle_anal_exceptions

def handle_initializer(class_name, vtable_ea):
    print(f'handling vtable {vtable_ea:x}')

    dtor_thunk_ea = get_qword(vtable_ea)

    constructor = guess_constructor_from_vtable(vtable_ea)
    print('found a ctor, now trying to get instantiators')
    instantiator_thunk, instantiator, constructor_thunk = find_instantiator_from_constructor(constructor)
    print('found instantiators, now setting names')

    if instantiator != constructor:
        set_generated_func_name(constructor_thunk, f'??0{class_name}@@QEAA@PEAVIAllocator@fnd@csl@@@Z')

    if instantiator_thunk:
        set_generated_func_name(instantiator_thunk, f'?Instantiate@{class_name}@@CAPEAV{class_name_to_backrefs(class_name)}@PEAVIAllocator@fnd@csl@@@Z')
    
    dtor_thunk = ensure_functions(dtor_thunk_ea)
    dtor = find_implementation(dtor_thunk)

    if is_deleting_destructor(dtor):
        set_generated_func_name(dtor_thunk, f'??_G{class_name}@@QEAAXXZ')
        
        if base_dtor_thunk := guess_vbase_destructor_thunk_from_deleting_destructor(dtor):
            set_generated_func_name(base_dtor_thunk, f'??_D{class_name}@@QEAAXXZ')
    else:
        set_generated_func_name(dtor_thunk, f'??_D{class_name}@@QEAAXXZ')

def find_ctors_and_dtors():
    for name, ea in nlist_names():
        if class_name := estimate_class_name_from_vtable_name(name):
            handle_anal_exceptions(lambda: handle_initializer(class_name, ea))
