from ida_name import set_name
from .heuristics import require_vtable, is_rtti_identified_vtable

def set_generated_vtable_name_through_ctor(ctor_func, class_name):
    vtable_ea = require_vtable(ctor_func)

    if not is_rtti_identified_vtable(vtable_ea): # shouldn't happen, but let's just add an extra check to be sure
        set_name(vtable_ea, f'??_7{class_name}@@6B@')
