from enum import Enum
from ida_name import set_name, SN_AUTO, get_nlist_size, get_nlist_name, get_nlist_ea
from ida_bytes import get_flags, has_user_name
from .heuristics import require_vtable, is_rtti_identified_vtable, is_deleting_destructor, guess_vbase_destructor_thunk_from_deleting_destructor
from .funcs import get_thunk_targets, is_stock_function, find_implementation
from rangers_analysis.config import rangers_analysis_config

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

class StaticObjectVarType(Enum):
    VAR = 0
    ARRAY = 1
    PTR = 2
    CONST_PTR = 3

class StaticObjectVar:
    def __init__(self, name, class_name, type, const = False, public = False, struct = False):
        self.name = name
        self.class_name = class_name
        self.type = type
        self.const = const
        self.public = public
        self.struct = struct

    def get_mangling_format(self):
        qual = 'B' if self.const else 'A'
        acc = '2' if self.public else '0'
        strtyp = 'U' if self.struct else 'V'
        match self.type:
            case StaticObjectVarType.VAR: return '{0}@' + acc + strtyp + '{1}@' + qual
            case StaticObjectVarType.ARRAY: return '{0}@' + acc + 'Q' + qual + strtyp + '{1}@' + qual
            case StaticObjectVarType.PTR: return '{0}@' + acc + 'PE' + qual + strtyp + '{1}@E' + qual
            case StaticObjectVarType.CONST_PTR: return '{0}@' + acc + 'QE' + qual + strtyp + '{1}@E' + qual
            case _: raise Exception('unknown var type')

def nlist_names():
    for i in range(0, get_nlist_size()):
        yield get_nlist_name(i), get_nlist_ea(i)

def set_generated_vtable_name_through_ctor(ctor_func, class_name):
    vtable_ea = require_vtable(ctor_func)

    if not is_rtti_identified_vtable(vtable_ea):     # shouldn't happen, but let's just add an extra check to be sure
        set_generated_name(vtable_ea, create_name('??_7{0}@6B@', class_name))

def set_generated_name(ea, name, is_certain = False):
    if is_certain:
        set_name(ea, name)
    elif not has_user_name(get_flags(ea)):
        set_name(ea, name, SN_AUTO)
    else:
        print(f'warn: Not updating name at {ea:x} to {name} as the existing name is user specified and the new name is not certain.')

def set_generated_func_name(f, name, is_certain = False):
    for i, f in reversed([*enumerate(reversed([*get_thunk_targets(f)]))]):
        if is_stock_function(f):
            break

        set_generated_name(f.start_ea, f"{'j_' * i}{name}", is_certain)

def create_private_instantiator_func_name(class_name, func_name = 'Create'):
    if rangers_analysis_config['pass_allocator']:
        return create_name('?{0}@CAPEAV{1}@PEAV{2}@@Z', [func_name, *class_name], class_name, ['IAllocator', 'fnd', 'csl'])
    else:
        return create_name('?{0}@CAPEAV{1}@XZ', [func_name, *class_name], class_name)

def create_public_instantiator_func_name(class_name, func_name = 'Create'):
    if rangers_analysis_config['pass_allocator']:
        return create_name('?{0}@SAPEAV{1}@PEAV{2}@@Z', [func_name, *class_name], class_name, ['IAllocator', 'fnd', 'csl'])
    else:
        return create_name('?{0}@SAPEAV{1}@XZ', [func_name, *class_name], class_name)

def create_simple_constructor_func_name(class_name):
    if rangers_analysis_config['pass_allocator']:
        return create_name('??0{0}@QEAA@PEAV{1}@@Z', class_name, ['IAllocator', 'fnd', 'csl'])
    else:
        return create_name('??0{0}@QEAA@XZ', class_name)

def set_private_instantiator_func_name(f, class_name, is_certain = False, func_name = 'Create'):
    set_generated_func_name(f, create_private_instantiator_func_name(class_name, func_name), is_certain)

def set_public_instantiator_func_name(f, class_name, is_certain = False, func_name = 'Create'):
    set_generated_func_name(f, create_public_instantiator_func_name(class_name, func_name), is_certain)

def set_simple_constructor_func_name(f, class_name, is_certain = False):
    set_generated_func_name(f, create_simple_constructor_func_name(class_name), is_certain)

def set_destructor_func_name(dtor_thunk, class_name, is_certain = False):
    dtor = find_implementation(dtor_thunk)

    if is_deleting_destructor(dtor):
        set_generated_func_name(dtor_thunk, create_name('??_G{0}@QEAAXXZ', class_name), is_certain)
        
        if base_dtor_thunk := guess_vbase_destructor_thunk_from_deleting_destructor(dtor):
            set_generated_func_name(base_dtor_thunk, create_name('??_D{0}@QEAAXXZ', class_name), is_certain)
    else:
        set_generated_func_name(dtor_thunk, create_name('??_D{0}@QEAAXXZ', class_name), is_certain)

def set_static_getter_func_name(f, class_name, object_var, getter_name, is_certain = False):
    qual = 'B' if object_var.const else 'A'
    strtyp = 'U' if object_var.struct else 'V'
    set_generated_func_name(f, create_name('?{0}@SAPE' + qual + strtyp + '{1}@XZ', [getter_name, *class_name], object_var.class_name), is_certain)

def set_static_initializer_func_name(f, class_name, object_var, is_certain = False):
    set_generated_func_name(f, create_name(f'??__E{object_var.get_mangling_format()}', [object_var.name, *class_name], object_var.class_name), is_certain)

def set_static_atexit_dtor_func_name(f, class_name, object_var, is_certain = False):
    set_generated_func_name(f, create_name(f'??__F{object_var.get_mangling_format()}', [object_var.name, *class_name], object_var.class_name), is_certain)

def set_static_var_name(ea, class_name, object_var, is_certain = False):
    set_generated_name(ea, create_name(f'?{object_var.get_mangling_format()}', [object_var.name, *class_name], object_var.class_name), is_certain)

def friendly_class_name(class_name):
    return "::".join(reversed(class_name))
