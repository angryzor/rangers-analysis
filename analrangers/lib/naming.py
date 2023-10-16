from ida_name import set_name, SN_AUTO, get_nlist_size, get_nlist_name, get_nlist_ea
from ida_bytes import get_flags, has_user_name
from .heuristics import require_vtable, is_rtti_identified_vtable
from .funcs import get_thunk_targets, is_stock_function

def create_name(fmt, *identifiers):
    backrefs = []
    processed_class_names = []

    for identifier in identifiers:
        mangled_class_name = ''

        for fragment in identifier:
            if p := next(filter(lambda p: p[1] == fragment, enumerate(backrefs)), None):
                mangled_class_name += str(p[0])
            else:
                mangled_class_name += f'{fragment}@'
                backrefs.append(fragment)

        processed_class_names.append(mangled_class_name)

    return fmt.format(*processed_class_names)

def nlist_names():
    for i in range(0, get_nlist_size()):
        yield get_nlist_name(i), get_nlist_ea(i)

def set_generated_vtable_name_through_ctor(ctor_func, class_name):
    vtable_ea = require_vtable(ctor_func)

    if not is_rtti_identified_vtable(vtable_ea): # shouldn't happen, but let's just add an extra check to be sure
        set_generated_name(vtable_ea, f'??_7{class_name}@@6B@')

def set_generated_name(ea, name):
    if not has_user_name(get_flags(ea)):
        set_name(ea, name, SN_AUTO)
    else:
        print(f'warn: Not updating name at {ea:x} to {name} as the existing name is user specified.')

def set_generated_func_name(f, name):
    for i, f in reversed([*enumerate(reversed([*get_thunk_targets(f)]))]):
        if is_stock_function(f):
            break

        set_generated_name(f.start_ea, f"{'j_' * i}{name}")
