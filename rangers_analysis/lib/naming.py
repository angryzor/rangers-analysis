from enum import Enum
from ida_name import get_name, set_name, SN_AUTO, get_nlist_size, get_nlist_name, get_nlist_ea, get_name_ea
from ida_bytes import get_flags, has_user_name
from ida_netnode import netnode, BADNODE
from .heuristics import require_vtable, is_rtti_identified_vtable, is_deleting_destructor, guess_vbase_destructor_thunk_from_deleting_destructor
from .funcs import get_thunk_targets, is_stock_function, find_implementation
from .iterators import supstrs, hashvals
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

itag = 'I'
backref_node = '$ alias backrefs'
netnode(backref_node).create(backref_node)

def get_all_aliases():
    return hashvals(netnode(backref_node))

def set_alias_ea(alias, ea):
    netnode(backref_node).hashset_idx(alias, ea)

def del_alias_ea(alias):
    netnode(backref_node).hashdel(alias)

def get_aliases(ea):
    return supstrs(netnode(ea), itag)

def add_alias(ea, alias, steal = False):
    if backref := get_alias_ea(alias):
        if ea == backref:
            return
        
        if not steal:
            print(f"warn: can't add alias '{alias}' to byte {ea:x} because the name is already used in the program at {backref:x}.")
            return
        
        remove_alias(backref, alias)

    n = netnode(ea)
    idx = n.suplast(itag)
    n.supset(0 if idx == BADNODE else idx + 1, alias, itag)
    set_alias_ea(alias, ea)

def remove_alias(ea, alias):
    for a, i in get_aliases(ea):
        if a == alias:
            netnode(ea).supdel(i, itag)
    del_alias_ea(alias)

def get_alias_ea(alias):
    b = netnode(backref_node)
    backref = b.hashval_long(alias)

    return None if backref == 0 else backref

def set_main_name(ea, name, steal = False, **kwargs):
    if steal:
        prev_ea = get_name_ea(name)
        if prev_ea != BADADDR and prev_ea != ea:
            set_name(prev_ea, "")
    set_name(ea, name, **kwargs)

def remove_other_aliases(ea, name):
    for alias, i in [*get_aliases(ea)]:
        if alias != name:
            remove_alias(ea, alias)

def set_generated_name(ea, name, certain = False, steal = False, unique = False):
    if certain:
        if unique:
            remove_other_aliases(ea, name)
        set_name(ea, name)
        add_alias(ea, name, steal)
    elif not has_user_name(get_flags(ea)):
        if unique:
            remove_other_aliases(ea, name)
        set_name(ea, name, SN_AUTO)
        add_alias(ea, name, steal)
    else:
        print(f'warn: Not updating name at {ea:x} to {name} as the existing name is user specified and the new name is not certain.')
        add_alias(ea, get_name(ea))

def set_generated_func_name(f, name, **kwargs):
    for i, f in reversed([*enumerate(reversed([*get_thunk_targets(f)]))]):
        if is_stock_function(f):
            break

        set_generated_name(f.start_ea, f"{'j_' * i}{name}", **kwargs)

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

def set_private_instantiator_func_name(f, class_name, func_name = 'Create', **kwargs):
    set_generated_func_name(f, create_private_instantiator_func_name(class_name, func_name), **kwargs)

def set_public_instantiator_func_name(f, class_name, func_name = 'Create', **kwargs):
    set_generated_func_name(f, create_public_instantiator_func_name(class_name, func_name), **kwargs)

def set_simple_constructor_func_name(f, class_name, **kwargs):
    set_generated_func_name(f, create_simple_constructor_func_name(class_name), **kwargs)

def set_destructor_func_name(dtor_thunk, class_name, **kwargs):
    dtor = find_implementation(dtor_thunk)

    if is_deleting_destructor(dtor):
        set_generated_func_name(dtor_thunk, create_name('??_G{0}@QEAAXXZ', class_name), **kwargs)
        
        if base_dtor_thunk := guess_vbase_destructor_thunk_from_deleting_destructor(dtor):
            set_generated_func_name(base_dtor_thunk, create_name('??_D{0}@QEAAXXZ', class_name), **kwargs)
    else:
        set_generated_func_name(dtor_thunk, create_name('??_D{0}@QEAAXXZ', class_name), **kwargs)

def set_static_getter_func_name(f, class_name, object_var, getter_name, **kwargs):
    qual = 'B' if object_var.const else 'A'
    strtyp = 'U' if object_var.struct else 'V'
    set_generated_func_name(f, create_name('?{0}@SAPE' + qual + strtyp + '{1}@XZ', [getter_name, *class_name], object_var.class_name), **kwargs)

def set_static_initializer_func_name(f, class_name, object_var, **kwargs):
    set_generated_func_name(f, create_name(f'??__E{object_var.get_mangling_format()}', [object_var.name, *class_name], object_var.class_name), **kwargs)

def set_static_atexit_dtor_func_name(f, class_name, object_var, **kwargs):
    set_generated_func_name(f, create_name(f'??__F{object_var.get_mangling_format()}', [object_var.name, *class_name], object_var.class_name), **kwargs)

def set_static_var_name(ea, class_name, object_var, **kwargs):
    set_generated_name(ea, create_name(f'?{object_var.get_mangling_format()}', [object_var.name, *class_name], object_var.class_name), **kwargs)

def friendly_class_name(class_name):
    return "::".join(reversed(class_name))
