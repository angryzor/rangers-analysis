from copyreg import constructor
import re
from functools import reduce
from clang.cindex import Index, CursorKind, TypeKind, BaseEnumeration, conf, TranslationUnit, _CXString, Cursor, register_function
try:
    import idaapi
    import ida_name
    import ida_ua
    import ida_funcs
    import ida_kernwin
    from ida_bytes import *
    from ida_typeinf import *
    from idc import *
except:
    pass
from ctypes import Structure, POINTER, c_uint, byref
import os

conf.set_library_file(os.path.join(os.path.dirname(__file__), 'libclang.dll'))

known_mangled_names = []

# class _CXStringForSet(_CXString):
#     def __del__(self):
#         pass

# class _CXStringSet(Structure):
#     _fields_ = [("strings", POINTER(_CXStringForSet)), ("count", c_uint)]

#     def __del__(self):
#         conf.lib.clang_disposeStringSet(byref(self))
    
#     def __len__(self):
#         return self.count
    
#     def __getitem__(self, idx):
#         if idx < 0 or idx >= self.count:
#             raise IndexError()

#         return self.strings[idx]

#     @staticmethod
#     def from_result(res, fn=None, args=None):
#         if not res:
#             return []

#         string_set = res.contents
#         assert isinstance(string_set, _CXStringSet)
#         return [_CXStringForSet.from_result(s) for s in string_set]

# register_function(conf.lib, ('clang_Cursor_getCXXManglings', [Cursor], POINTER(_CXStringSet), _CXStringSet.from_result), False)

# @property
# def cxx_manglings(self):
#     return conf.lib.clang_Cursor_getCXXManglings(self)

# Cursor.cxx_manglings = cxx_manglings

register_function(conf.lib, ('clang_Cursor_getMicrosoftVFTableMangling', [Cursor, POINTER(Cursor), c_uint], _CXString, _CXString.from_result), False)

def get_mangled_vtable_name(self, base_path = []):
    base_path_size = len(base_path)
    base_path_arr = (Cursor * base_path_size)(*base_path)
    return conf.lib.clang_Cursor_getMicrosoftVFTableMangling(self, base_path_arr, base_path_size)

Cursor.get_mangled_vtable_name = get_mangled_vtable_name

def parse_usr(usr):
    initial_usr = usr
    substitutions = []

    def expect(m):
        if m:
            return m
        else:
            raise Exception(f'parse error: {usr} in USR {initial_usr}')
        
    def parse_re(regexp):
        nonlocal usr
        
        m = re.match(regexp, usr)
        
        if m:
            usr = usr[len(m.group(0)):]
            return m.group(0)
        else:
            return None
        
    def parse_ident():
        return parse_re(r'[a-zA-Z0-9_]+')
    
    def parse_template_argument():
        expect(parse_re(r'#'))

        if parse_re(f'V'):
            parse_type()
            val = parse_re('[0-9]+')
            return val

        return parse_type()
    
    def parse_template_parameter_list():
        header = parse_re(r'>[0-9]+')
        if header:
            size = int(header[1:])
            args = []

            for _ in range(0, size):
                args.append(parse_template_argument())
            
            expect(parse_re(r'<'))

            return f'<{", ".join(args)}>'
        
    def parse_template_argument_list():
        if parse_re(r'>'):
            args = []

            while not parse_re(r'<'):
                args.append(parse_template_argument())

            return f'<{", ".join(args)}>'
        
        
    def parse_builtin_type():
        if parse_re(r'v'): return 'void'
        if parse_re(r'b'): return 'bool'
        if parse_re(r'c'): return 'unsigned char'
        if parse_re(r'u'): return 'char8_t'
        if parse_re(r'q'): return 'char16_t'
        if parse_re(r'w'): return 'char32_t'
        if parse_re(r's'): return 'unsigned short'
        if parse_re(r'i'): return 'unsigned int'
        if parse_re(r'l'): return 'unsigned long'
        if parse_re(r'k'): return 'unsigned long long'
        if parse_re(r'j'): return 'unsigned __int128'
        if parse_re(r'C'): return 'char'
        if parse_re(r'r'): return 'signed char'
        if parse_re(r'W'): return 'wchar_t'
        if parse_re(r'S'): return 'short'
        if parse_re(r'I'): return 'int'
        if parse_re(r'L'): return 'long'
        if parse_re(r'K'): return 'long long'
        if parse_re(r'J'): return '__int128'
        if parse_re(r'h'): return '__fp16'
        if parse_re(r'f'): return 'float'
        if parse_re(r'd'): return 'double'
        if parse_re(r'D'): return 'long double'
        if parse_re(r'Q'): return '__float128'
        if parse_re(r'n'): return 'nullptr'

    def parse_non_builtin_type():
        nonlocal usr

        if parse_re(r'@N@|@S@|@E@'):
            name = expect(parse_ident())
            args = parse_template_argument_list()
            qualifier = f'{name}{args if args else ""}'

            rest = parse_type()

            return f'{qualifier}::{rest}' if rest else qualifier
        # Add qualifiers for namespaces and structs
        if parse_re(r'@ST'):
            name = expect(parse_ident())
            args = expect(parse_template_parameter_list())
            qualifier = f'{name}{args}'

            expect(parse_re(r'@'))

            rest = parse_type()

            return f'{qualifier}::{rest}' if rest else qualifier
        if parse_re(r'\$'):
            return parse_type()
        if parse_re(r'@T@'):
            return parse_ident()
        if parse_re(r'\*'):
            return f'{parse_type()}*'
        if parse_re(f'&&'):
            return f'{parse_type()}&&'
        if parse_re(f'&'):
            return f'{parse_type()}&'
        if parse_re(r'%'):
            class_type = expect(parse_type())
            func_type = expect(parse_type())
            first_space_index = func_type.index(' ')
            return f'{func_type[:first_space_index]} ({class_type}::*){func_type[first_space_index + 1:]}'
        if parse_re(r'F'):
            return_type = expect(parse_type())
            args = []

            expect(parse_re('\('))
            while not parse_re('\)'):
                expect(parse_re('#'))
                args.append(expect(parse_type()))

            return f'{return_type} ({", ".join(args)})'

    def parse_type():
        if mods := parse_re(r'[1-7]'):
            modflags = int(mods)
            m = ''
            if modflags & 1:
                m += 'const '
            if modflags & 2:
                m += 'volatile '
            if modflags & 4:
                m += 'restrict '
            return f'{m}{parse_type()}'
        if substExpr := parse_re(r'S[0-9]+_'):
            substIdx = int(substExpr[1:-1])
            return substitutions[substIdx]
        if res := parse_builtin_type():
            return res
        if res := parse_non_builtin_type():
            substitutions.append(res)
            return res

    
    def parse_decl():
        typ = parse_type()
        args = parse_template_argument_list()
        
        return f'{typ}{args if args else ""}'

    expect(parse_re(r'c:'))
    parse_re(r'[^@]*')
    return parse_decl()

def get_decl_name(decl):
    usr = decl.get_usr()
    parsed = parse_usr(usr)
    return parsed

class CallingConv(BaseEnumeration):
    _kinds = []
    _name_map = None
    pass


CallingConv.Default = CallingConv(0)
CallingConv.C = CallingConv(1)
CallingConv.X86StdCall = CallingConv(2)
CallingConv.X86FastCall = CallingConv(3)

CallingConv.X86ThisCall = CallingConv(4)
CallingConv.X86Pascal = CallingConv(5)
CallingConv.AAPCS = CallingConv(6)
CallingConv.AAPCS_VFP = CallingConv(7)

CallingConv.X86RegCall = CallingConv(8)
CallingConv.IntelOclBicc = CallingConv(9)
CallingConv.Win64 = CallingConv(10)
CallingConv.X86_64Win64 = CallingConv.Win64

CallingConv.X86_64SysV = CallingConv(11)
CallingConv.X86VectorCall = CallingConv(12)
CallingConv.Swift = CallingConv(13)
CallingConv.PreserveMost = CallingConv(14)

CallingConv.PreserveAll = CallingConv(15)
CallingConv.AArch64VectorCall = CallingConv(16)
CallingConv.Invalid = CallingConv(100)
CallingConv.Unexposed = CallingConv(200)
cursor_handlers = {}
type_handlers = {}
idati = idaapi.get_idati()
# idati = idaapi.til_t()


if idaapi.BADADDR == 2 ** 64 - 1:
    FF_POINTER = FF_QWORD
    POINTER_SIZE = 8

else:
    FF_POINTER = FF_DWORD
    POINTER_SIZE = 4

simple_types = {
    TypeKind.BOOL: BTF_BOOL,
    TypeKind.FLOAT: BTF_FLOAT,
    TypeKind.DOUBLE: BTF_DOUBLE,
    TypeKind.LONGDOUBLE: BTF_LDOUBLE,
    TypeKind.CHAR_S: BTF_CHAR,
    TypeKind.CHAR_U: BTF_UCHAR,
    TypeKind.SCHAR: BTF_CHAR,
    TypeKind.UCHAR: BTF_UCHAR,
    TypeKind.WCHAR: BT_INT16 | BTMT_CHAR,
    TypeKind.CHAR16: BT_INT16 | BTMT_CHAR,
    TypeKind.CHAR32: BT_INT32 | BTMT_CHAR,
    TypeKind.SHORT: BTF_INT16,
    TypeKind.USHORT: BTF_UINT16,
    TypeKind.INT: BTF_INT32,
    TypeKind.LONG: BTF_INT32,
    TypeKind.LONGLONG: BTF_INT64,
    TypeKind.UINT: BTF_UINT32,
    TypeKind.ULONG: BTF_UINT32,
    TypeKind.ULONGLONG: BTF_UINT64,
    TypeKind.INT128: BTF_INT128,
    TypeKind.UINT128: BTF_UINT128,
    TypeKind.VOID: BTF_VOID,
    TypeKind.INVALID: BTF_VOID,
}

def get_stock_type_id(type):
    match type.kind:
        case TypeKind.POINTER:
            pointee = type.get_pointee()

            match pointee.kind:
                case TypeKind.SCHAR:
                    return STI_PCCHAR if pointee.is_const_qualified() else STI_PCHAR
                case TypeKind.UCHAR:
                    return STI_PCUCHAR if pointee.is_const_qualified() else STI_PUCHAR
                case TypeKind.INT:
                    return None if pointee.is_const_qualified() else STI_PINT
                case TypeKind.UINT:
                    return None if pointee.is_const_qualified() else STI_PUINT 
                case TypeKind.VOID | TypeKind.INVALID:
                    return STI_PCVOID if pointee.is_const_qualified() else STI_PVOID
                case TypeKind.POINTER:
                    if pointee.is_const_qualified():
                        return None

                    pointee2 = pointee.get_pointee()

                    match pointee2.kind:
                        case TypeKind.VOID | TypeKind.INVALID:
                            return None if pointee2.is_const_qualified() else STI_PPVOID
        case TypeKind.VARIABLEARRAY | TypeKind.INCOMPLETEARRAY:
            element = type.get_array_element_type()

            match element.kind:
                case TypeKind.SCHAR:
                    return STI_ACCHAR if element.is_const_qualified() else STI_ACHAR
                case TypeKind.UCHAR:
                    return STI_ACUCHAR if element.is_const_qualified() else STI_AUCHAR
        
        case TypeKind.ELABORATED | TypeKind.TYPEDEF:
            match type.spelling:
                case 'size_t':
                    return STI_SIZE_T
                case 'ssize_t':
                    return STI_SSIZE_T

def handle_stock_type(type):
    stock_type_id = get_stock_type_id(type)
    
    if stock_type_id != None:
        return tinfo_t.get_stock(stock_type_id)

class KnownMangledName:
    def __init__(self, name, tif):
        self.name = name
        self.tif = tif

# There's a lot of rfl classes and the large number of merged COMDAT nullsubs cause a ton of spam.
# Also these template classes are heavily inlined so to list them all isn't very useful.
excluded_type_application_patterns = r'@rfl@app@|\?\$HashMap@|\?\$Array@|\?\$FixedArray@|\?\$MoveArray@|\?\$Handle@|\?\$Delegate@|\?\$StringMap@|\?\$Bitset@'

def attempt_applying_type_to_name(mangled_name, type):
    address = get_name_ea_simple(mangled_name)
    if address != idaapi.BADADDR:
        print(f'setting {address:x} with name {mangled_name} to {type}')
        idaapi.apply_tinfo(address, type, idaapi.TINFO_DELAYFUNC | idaapi.TINFO_DEFINITE)

        thunk_name = 'j_' + mangled_name
        if get_name_ea_simple(thunk_name) != idaapi.BADADDR:
            attempt_applying_type_to_name(thunk_name, type)
    else: #if not re.search(excluded_type_application_patterns, mangled_name):
        known_mangled_names.append(KnownMangledName(mangled_name, type))
        print(f'Unmatched name: {mangled_name}, cannot apply type.')

def set_func_ea_name(ea, name):
    if ida_ua.print_insn_mnem(ea) == 'retn':
        return

    f = ida_funcs.get_func(ea)
    if f == None:
        print(f"ea {ea:x} is not a function and cannot be renamed to {name}")
        return

    if f.flags & ida_funcs.FUNC_THUNK:
        [tgt, _] = ida_funcs.calc_thunk_func_target(f)

        if tgt == BADADDR:
            print(f"couldn't calc thunk tgt of {ea:x}")
            return
    
        tgt_name = set_func_ea_name(tgt, name)

        if tgt_name == None:
            return
        
        name = f'j_{tgt_name}'

    ida_name.set_name(ea, name)

    return name

callingconv_map = {
    CallingConv.C: idaapi.CM_CC_CDECL,
    CallingConv.X86FastCall: idaapi.CM_CC_FASTCALL,
    CallingConv.X86ThisCall: idaapi.CM_CC_THISCALL,
    CallingConv.X86StdCall: idaapi.CM_CC_STDCALL,
    CallingConv.X86Pascal: idaapi.CM_CC_PASCAL,
}

visited = dict()
vtable_infos = dict()
saved = set()

class VTableInfo:
    def __init__(self, base_path, members, offset):
        self.base_path = base_path
        self.members = [*members]
        self.offset = offset

# class ImportedType:
#     def __init__(self, tif):
#         self.tif = tif

#     def get_tif(self):
#         return self.tif

# class ImportedRecordType(ImportedType):
#     def __init__(self, tif, vtable_infos):
#         super(self, tif)
#         self.vtable_infos = vtable_infos

def save_tinfo(tif, decl_name):
    gc_marker = type_attr_t()
    gc_marker.key = 'imported'
    gc_marker.value = b''
    tif.set_attr(gc_marker)
    
    tif.set_named_type(idati, decl_name, idaapi.NTF_REPLACE)
    saved.add(decl_name)

def garbage_collect():
    next_name = first_named_type(idati, NTF_TYPE)

    while next_name != None:
        cur_name = next_name
        next_name = next_named_type(idati, cur_name, NTF_TYPE)
        
        tif = tinfo_t()
        tif.get_named_type(idati, cur_name)

        if tif.get_attr('imported') != None and not cur_name in saved:
            del_named_type(idati, cur_name, NTF_TYPE)

def CursorHandler(kind):
    def decorator(f):
        cursor_handlers[kind] = f
        return f
    return decorator

def TypeHandler(kind):
    def decorator(f):
        type_handlers[kind] = f
        return f
    return decorator

def resolve_function(type, flags=0, class_tif=None, decl=None):
    decl = decl or type.get_declaration()
    tif = idaapi.tinfo_t()
    data = idaapi.func_type_data_t()
    data.flags = flags
    data.stkargs = 0
    data.spoiled.clear()
    data.clear()
    # ida only supports cdecl + ellipsis when varargs exists
    if type.is_function_variadic():
        data.cc = idaapi.CM_CC_ELLIPSIS
    else:
        # you can use one of these
        # data.cc = idaapi.CM_CC_THISCALL
        data.cc = idaapi.CM_CC_FASTCALL
    if class_tif:
        thistype = idaapi.tinfo_t()
        thistype.create_ptr(class_tif)
        funcarg = idaapi.funcarg_t()
        funcarg.name = 'this'
        funcarg.type = thistype
        funcarg.flags = FAI_HIDDEN
        data.push_back(funcarg)

    data.rettype = thistype if decl.kind == CursorKind.CONSTRUCTOR else get_ida_type(type.get_result())

    if decl.kind != CursorKind.NO_DECL_FOUND:
        for argument in decl.get_arguments():
            funcarg = idaapi.funcarg_t()
            funcarg.name = argument.spelling
            funcarg.type = get_ida_type(argument.type)
            data.push_back(funcarg)
    else:
        for argument in type.argument_types():
            funcarg = idaapi.funcarg_t()
            funcarg.type = get_ida_type(argument)
            data.push_back(funcarg)
    
    if decl.kind == CursorKind.DESTRUCTOR:
        flags_tif = idaapi.tinfo_t()
        flags_tif.create_simple_type(BTF_UINT32)

        funcarg = idaapi.funcarg_t()
        funcarg.name = 'flags'
        funcarg.type = flags_tif
        data.push_back(funcarg)

    tif.create_func(data)
    tif.get_func_details(data) # TODO: what?
    return tif


def _create_forward_declaration(decl):
    declname = get_decl_name(decl)
    tif = idaapi.tinfo_t()
    
    if not tif.get_named_type(idati, declname):
        tif.create_forward_decl(idati, BTF_STRUCT, declname)

    visited[decl.hash] = tif
    return tif

def get_ida_type(type):
    decl = type.get_declaration()

    # print(f'GET: {type.kind}, spelling: {type.spelling}')

    # If we don't have a declaration, we don't have a hash and can't cache the result.
    if decl.kind == CursorKind.NO_DECL_FOUND:
        found = get_stock_or_build_ida_type(type)
    else:
        found = visited.get(decl.hash) or define_ida_type(decl)

    # print(f'Type has declaration. kind: {decl.kind}, hash: {cursor_hash}, displayname: {decl.displayname}, usr: {decl.get_usr()}, typename: {get_decl_name(decl)}')
    # for member in decl.get_children():
    #     print('M:', member.kind, member.spelling)

    # if found:
    #     # print(f'cache hit: {found} (hash was {decl.hash})')
    # else:
    #     # print(f'cache miss (hash was {decl.hash})')
    
    if type.is_const_qualified():
        found = found.copy()
        found.set_const()
    
    return found

def define_ida_type(decl):
    # print('DEFINE', decl.displayname, decl.type.is_const_qualified())
    tif = get_stock_or_build_ida_type(decl.type)
    visited[decl.hash] = tif
    return tif

def get_stock_or_build_ida_type(type):
    stock_type = handle_stock_type(type)

    # print(f'stock results: {stock_type}')

    return stock_type if stock_type != None else build_ida_type(type)

def build_ida_type(type):
    # print(f'building type')

    tif = type_handlers[type.kind](type)

    # print(f'built: {tif}, name is {tif.get_type_name()}')
    
    return tif

@TypeHandler(TypeKind.UNEXPOSED)
@TypeHandler(TypeKind.AUTO)
def handle_unexposed(type):
    can = type.get_canonical()
    if can != type:
        return get_ida_type(can)
    else:
        tif = idaapi.tinfo_t()
        tif.create_simple_type(BTF_VOID)
        return tif

@TypeHandler(TypeKind.ELABORATED)
def handle_elaborated(type):
    return get_ida_type(type.get_named_type())

@TypeHandler(TypeKind.VARIABLEARRAY)
@TypeHandler(TypeKind.CONSTANTARRAY)
@TypeHandler(TypeKind.VECTOR)
@TypeHandler(TypeKind.INCOMPLETEARRAY)
def handle_array(type):
    count = 0 if type.kind in (TypeKind.VARIABLEARRAY, TypeKind.INCOMPLETEARRAY) else type.element_count
    tif = idaapi.tinfo_t()
    tif.create_array(get_ida_type(type.element_type), count)
    return tif

@TypeHandler(TypeKind.BOOL)
@TypeHandler(TypeKind.FLOAT)
@TypeHandler(TypeKind.DOUBLE)
@TypeHandler(TypeKind.LONGDOUBLE)
@TypeHandler(TypeKind.CHAR_S)
@TypeHandler(TypeKind.CHAR_U)
@TypeHandler(TypeKind.SCHAR)
@TypeHandler(TypeKind.UCHAR)
@TypeHandler(TypeKind.WCHAR)
@TypeHandler(TypeKind.CHAR16)
@TypeHandler(TypeKind.CHAR32)
@TypeHandler(TypeKind.SHORT)
@TypeHandler(TypeKind.USHORT)
@TypeHandler(TypeKind.INT)
@TypeHandler(TypeKind.LONG)
@TypeHandler(TypeKind.LONGLONG)
@TypeHandler(TypeKind.UINT)
@TypeHandler(TypeKind.ULONG)
@TypeHandler(TypeKind.ULONGLONG)
@TypeHandler(TypeKind.INT128)
@TypeHandler(TypeKind.UINT128)
@TypeHandler(TypeKind.VOID)
@TypeHandler(TypeKind.INVALID)
def handle_simple_type(type):
    tif = idaapi.tinfo_t()
    tif.create_simple_type(simple_types[type.kind])
    return tif

@TypeHandler(TypeKind.FUNCTIONPROTO)
def handle_function_proto(type):
    return resolve_function(type)

@TypeHandler(TypeKind.POINTER)
@TypeHandler(TypeKind.LVALUEREFERENCE)
@TypeHandler(TypeKind.RVALUEREFERENCE)
def handle_pointer(type):
    pointee = type.get_pointee()
    pointee_type = get_ida_type(pointee)

    tif = idaapi.tinfo_t()
    tif.create_ptr(pointee_type)
    return tif

def is_multi_inherited_class(decl):
    base_decls = [member for member in decl.get_children() if member.kind == CursorKind.CXX_BASE_SPECIFIER]
    if len(base_decls) == 0: return False
    if len(base_decls) > 1: return True
    return is_multi_inherited_class(base_decls[0])

@TypeHandler(TypeKind.MEMBERPOINTER)
def handle_member_pointer(type):
    class_type = type.get_class_type()
    ptr_tif = handle_pointer(type)
    
    if not is_multi_inherited_class(class_type.get_canonical().get_declaration()):
        return ptr_tif
    
    udt = idaapi.udt_type_data_t()

    ptr_member_udt = idaapi.udt_member_t()
    ptr_member_udt.name = 'ptr'
    ptr_member_udt.offset = 0
    ptr_member_udt.type = ptr_tif
    udt.push_back(ptr_member_udt)

    adjustor_tif = idaapi.tinfo_t()
    adjustor_tif.create_simple_type(BTF_INT32)

    adjustor_member_udt = idaapi.udt_member_t()
    adjustor_member_udt.name = 'adjustor'
    adjustor_member_udt.offset = 0
    adjustor_member_udt.type = adjustor_tif
    udt.push_back(adjustor_member_udt)

    udt.sda = 4
    udt.taudt_bits |= TAUDT_CPPOBJ

    tif = idaapi.tinfo_t()
    tif.create_udt(udt, BTF_STRUCT)
    return tif

@TypeHandler(TypeKind.TYPEDEF)
def handle_typedef(type):
    decl = type.get_declaration()
    origin_tif = get_ida_type(decl.underlying_typedef_type)
    existing_type_name = origin_tif.get_type_name()

    if existing_type_name == None:
        save_tinfo(origin_tif, get_decl_name(decl))
        return origin_tif
    else:
        tif = idaapi.tinfo_t()
        tif.create_typedef(idati, existing_type_name)
        save_tinfo(tif, get_decl_name(decl))
        return tif

def is_stock_function(ea):
    return ida_name.get_name(ea).startswith('nullsub_') or ida_name.get_name(ea) == 'pure_virtual_function' or ida_bytes.get_bytes(ea, 3) == b'\xB0\x01\xC3' or ida_bytes.get_bytes(ea, 3) == b'\x32\xC0\xC3'

class VFunc:
    def __init__(self, class_tif):
        self.class_tif = class_tif
    
    def overrides(self, that):
        return (self.is_dtor() and that.is_dtor()) or (self.get_name() == that.get_name() and [t.get_canonical() for t in self.get_arguments()] == [t.get_canonical() for t in that.get_arguments()])

class DeclVFunc(VFunc):
    def __init__(self, decl, class_tif):
        super().__init__(class_tif)
        self.decl = decl
    
    def is_dtor(self):
        return self.decl.kind == CursorKind.DESTRUCTOR
    
    def get_name(self):
        return self.decl.spelling
    
    def get_mangled_name(self):
        return self.decl.mangled_name
    
    def get_arguments(self):
        return self.decl.type.argument_types()
    
    def get_tif(self):
        return resolve_function(self.decl.type, 0, self.class_tif, self.decl)
    
class DefaultDtorVFunc(VFunc):
    def __init__(self, class_decl, class_tif):
        super().__init__(class_tif)
        self.class_decl = class_decl
    
    def is_dtor(self):
        return True
    
    def get_name(self):
        return f'~{self.class_decl.spelling}'
    
    def get_mangled_name(self):
        mangled_vtable_name = self.class_decl.get_mangled_vtable_name([])
        mangled_class_name = mangled_vtable_name[4:-4]
        return f'??_D{mangled_class_name}@QEAAXXZ'

    def get_tif(self):
        data = idaapi.func_type_data_t()
        data.stkargs = 0
        data.cc = idaapi.CM_CC_FASTCALL

        ret_type = idaapi.tinfo_t()
        ret_type.create_simple_type(BTF_VOID)
        data.rettype = ret_type

        this_type = idaapi.tinfo_t()
        this_type.create_ptr(self.class_tif)

        this_funcarg = idaapi.funcarg_t()
        this_funcarg.name = 'this'
        this_funcarg.type = this_type
        this_funcarg.flags = FAI_HIDDEN
        data.push_back(this_funcarg)

        flags_tif = idaapi.tinfo_t()
        flags_tif.create_simple_type(BTF_UINT32)

        flags_funcarg = idaapi.funcarg_t()
        flags_funcarg.name = 'flags'
        flags_funcarg.type = flags_tif
        data.push_back(flags_funcarg)

        tif = idaapi.tinfo_t()
        tif.create_func(data)
        tif.get_func_details(data) # TODO: what?

        return tif

@TypeHandler(TypeKind.RECORD)
def handle_record(type):
    decl = type.get_declaration()
    decl_name = get_decl_name(decl)
    forward_tif = _create_forward_declaration(decl)

    process_cursor(decl)

    align = type.get_align()
    udt = idaapi.udt_type_data_t()
    if align > 1:
        # print(f'align: {align}, ida_align: {calc_min_align(align)}')
        udt.sda = calc_min_align(align)

    vtbl_infos = []
    is_root = False

    def create_vfunc(member):
        nonlocal is_root

        f = DeclVFunc(member, forward_tif)

        if len(vtbl_infos) == 0:
            is_root = True
            vtbl_infos.append(VTableInfo([], [], 0))

        for vtbl_info in vtbl_infos:
            for i, vtbl_member in enumerate(vtbl_info.members):
                if f.overrides(vtbl_member):
                    vtbl_info.members[i] = f
                    return
            
        vtbl_infos[0].members.append(f)

    def create_bases():
        delayed_base_udts = []
        offset = 0
        
        for member in decl.get_children():
            if member.kind == CursorKind.CXX_BASE_SPECIFIER:
                member_type = get_ida_type(member.type)
                member_decl = member.type.get_declaration()
                base_vtbl_infos = vtable_infos[member_decl.hash]

                member_udt = idaapi.udt_member_t()
                member_udt.name = member.spelling
                member_udt.type = member_type
                member_udt.set_baseclass()
            
                if len(base_vtbl_infos) == 0:
                    delayed_base_udts.append(member_udt)
                else:
                    for vtbl_info in base_vtbl_infos:
                        vtbl_infos.append(VTableInfo(vtbl_info.base_path if offset == 0 else [member_decl, *vtbl_info.base_path], vtbl_info.members, vtbl_info.offset + offset))
                    
                    offset += member_type.get_size()

                    udt.push_back(member_udt)
        
        for base_udt in delayed_base_udts:
            udt.push_back(base_udt)

    def create_fields():
        for member in type.get_fields():
            member_udt = idaapi.udt_member_t()
            member_udt.name = member.spelling
            member_udt.offset = member.get_field_offsetof()
            member_udt.type = get_ida_type(member.type)
            udt.push_back(member_udt)

    def create_vtables():
        for member in decl.get_children():
            if member.kind in (CursorKind.CXX_METHOD, CursorKind.DESTRUCTOR) and member.is_virtual_method():
                create_vfunc(member)
        
        # Create a default destructor if none was specified and we have vtables.
        if len(vtbl_infos) > 0 and not any(map(lambda member: member.kind == CursorKind.DESTRUCTOR and member.is_virtual_method(), decl.get_children())):
            vf = DefaultDtorVFunc(decl, forward_tif)
            if is_root:
                vtbl_infos[0].members.insert(0, vf)
            else:
                vtbl_infos[0].members[0] = vf

        for vtbl_info in vtbl_infos:
            vtbl_udt = idaapi.udt_type_data_t()
            vtbl_udt.taudt_bits |= TAUDT_VFTABLE

            for member in vtbl_info.members:
                method_ptr_tif = idaapi.tinfo_t()
                method_ptr_tif.create_ptr(member.get_tif())

                member_udt = idaapi.udt_member_t()
                member_udt.name = member.get_name()
                member_udt.type = method_ptr_tif

                vtbl_udt.push_back(member_udt)

            vtbl_tif = idaapi.tinfo_t()
            vtbl_tif.create_udt(vtbl_udt, BTF_STRUCT)
            vtbl_name = f'{decl_name}_vtbl' if vtbl_info.offset == 0 else f'{decl_name}_{vtbl_info.offset:04x}_vtbl'
            save_tinfo(vtbl_tif, vtbl_name)

            mangled_vtable_name = decl.get_mangled_vtable_name(vtbl_info.base_path)
            attempt_applying_type_to_name(mangled_vtable_name, vtbl_tif)

            vtbl_ea = ida_name.get_name_ea(BADADDR, mangled_vtable_name)
            print(f'trying to set vtable {mangled_vtable_name} at {vtbl_ea or 0:x}')
            if vtbl_ea != BADADDR:
                for i, member in enumerate(vtbl_info.members):
                    vfunc_ea = ida_bytes.get_qword(vtbl_ea + 8 * i)

                    if not is_stock_function(vfunc_ea):
                        mangled_member_name = member.get_mangled_name()
                        set_func_ea_name(vfunc_ea, mangled_member_name)
                        attempt_applying_type_to_name(mangled_member_name, member.get_tif())

            if is_root:
                vtbl_ptr_tif = idaapi.tinfo_t()
                vtbl_ptr_tif.create_ptr(vtbl_tif)

                vtbl_member_udt = idaapi.udt_member_t()
                vtbl_member_udt.name = '__vftable'
                vtbl_member_udt.set_vftable()
                vtbl_member_udt.type = vtbl_ptr_tif

                udt.insert(udt.begin(), vtbl_member_udt)
    
    def create_nonvirtual_methods():
        for member in decl.get_children():
            if member.kind in (CursorKind.CXX_METHOD, CursorKind.CONSTRUCTOR, CursorKind.DESTRUCTOR) and not member.is_virtual_method():
                attempt_applying_type_to_name(member.mangled_name, resolve_function(member.type, 0, None if member.is_static_method() else forward_tif, member))

    # if not type.is_pod():
    udt.taudt_bits |= TAUDT_CPPOBJ

    create_bases()
    create_fields()

    vtable_infos[decl.hash] = vtbl_infos

    create_vtables()

    tif = idaapi.tinfo_t()
    tif.create_udt(udt, BTF_STRUCT)
    save_tinfo(tif, decl_name)

    create_nonvirtual_methods()

    return tif

@TypeHandler(TypeKind.ENUM)
def handle_enum(type):
    decl = type.get_declaration()
    decl_name = get_decl_name(decl)
    is_scoped = decl.is_scoped_enum()

    etd = enum_type_data_t(BTE_ALWAYS | (BTE_SIZE_MASK & (1 << type.get_size() - 1)))

    for member in decl.get_children():
        if member.kind == CursorKind.ENUM_CONSTANT_DECL:
            emt = enum_member_t()
            emt.name = f'{decl_name}::{member.spelling}' if is_scoped else member.spelling
            emt.value = member.enum_value

            etd.push_back(emt)

    tif = idaapi.tinfo_t()
    tif.create_enum(etd)
    save_tinfo(tif, decl_name)

    return tif


@CursorHandler(CursorKind.TYPEDEF_DECL)
@CursorHandler(CursorKind.TYPE_ALIAS_DECL)
def handle_typedef_cursor(item):
    define_ida_type(item)

@CursorHandler(CursorKind.CLASS_DECL)
# @CursorHandler(CursorKind.CLASS_TEMPLATE)
@CursorHandler(CursorKind.STRUCT_DECL)
@CursorHandler(CursorKind.UNION_DECL)
@CursorHandler(CursorKind.ENUM_DECL)
def handle_struct(item):
    if item.is_definition():
        define_ida_type(item)
    elif definition := item.get_definition():
        _create_forward_declaration(definition)

@CursorHandler(CursorKind.FUNCTION_DECL)
@CursorHandler(CursorKind.VAR_DECL)
def typedefs(item):
    type = get_ida_type(item.type)

    attempt_applying_type_to_name(item.mangled_name, type)


@CursorHandler(CursorKind.NAMESPACE)
@CursorHandler(CursorKind.LINKAGE_SPEC)
@CursorHandler(CursorKind.UNEXPOSED_DECL)
def linkage(item):
    process_cursor(item)

# @CursorHandler(CursorKind.ENUM_DECL)
# def handle_enum(item):
#     members = []
#     for member in item.get_children():
#         members.append((member.spelling, member.enum_value))
#     enum_id = add_enum(idaapi.BADADDR, get_decl_name(item), 0)
#     for name, value in members:
#         add_enum_member(enum_id, name, value, -1)


def parse_file(path, args=[]):
    index = Index.create()
    tx = index.parse(path, args, None, TranslationUnit.PARSE_SKIP_FUNCTION_BODIES | TranslationUnit.PARSE_INCOMPLETE)

    if len(tx.diagnostics) != 0:
        for diagnostic in tx.diagnostics:
            print(f'diag: {diagnostic}')
    else:
        known_mangled_names.clear()
        process_cursor(tx.cursor)
        # garbage_collect()

def process_cursor(cursor):
    for item in cursor.get_children():
        if item.kind in cursor_handlers:
            # print(item.kind, item.spelling, item.mangled_name, item.hash, item.displayname, item.canonical.mangled_name, item.get_usr())
            cursor_handlers[item.kind](item)
        else:
            # print('unhandled', item.location.file.name, item.location.line, item.kind, item.spelling, item.mangled_name, item.hash, item.displayname, item.canonical.mangled_name, item.get_usr())
            continue

def run_sync():
    parse_file('C:\\Users\\Ruben Tytgat\\Documents\\rangers-api\\rangers-api\\rangers-api.cpp', ['--std=c++17'])

class ChooseSDKName(ida_kernwin.Choose):
    def __init__(self, names):
        self.names = names
        super().__init__('Known names in SDK', [['Name', ida_kernwin.Choose.CHCOL_PLAIN]], ida_kernwin.Choose.CH_MODAL)

    def OnGetSize(self):
        return len(self.names)

    def OnGetLine(self, n):
        name = self.names[n].name
        demangled_name = ida_name.demangle_name(name, 0)
        return [demangled_name or name]
    
class ApplySDKNameActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, cpp_parser):
        super().__init__()
        self.cpp_parser = cpp_parser

    def activate(self, ctx):
        names = [*known_mangled_names] # intentional copy to remain consistent even if the known mangled names somehow change
        choice = ida_kernwin.choose_choose(ChooseSDKName(names))

        if choice != -1:
            known = names[choice]

            ida_name.set_name(ctx.cur_ea, known.name, 0)
            attempt_applying_type_to_name(known.name, known.tif)

        ida_kernwin.update_action_state('cppparser:apply-sdk-name', ida_kernwin.AST_ENABLE_ALWAYS)
        return 0

class SyncHandler(ida_kernwin.action_handler_t):
    def __init__(self, cpp_parser):
        super().__init__()
        self.cpp_parser = cpp_parser

    def activate(self, ctx):
        run_sync()
        ida_kernwin.update_action_state('cppparser:sync', ida_kernwin.AST_ENABLE_ALWAYS)
        return 0

class CPPParserUIHooks(ida_kernwin.UI_Hooks):
    def populating_widget_popup(self, widget, popup_handle, ctx):
        ida_kernwin.attach_action_to_popup(widget, popup_handle, 'cppparser:apply-sdk-name')

class CPPParser:
    def __init__(self):
        sync_action = ida_kernwin.action_desc_t('cppparser:sync', 'Load SDK types', SyncHandler(self))
        ida_kernwin.register_action(sync_action)
        ida_kernwin.update_action_state('cppparser:sync', ida_kernwin.AST_ENABLE_ALWAYS)

        apply_sdk_name_action = ida_kernwin.action_desc_t('cppparser:apply-sdk-name', 'Apply SDK name', ApplySDKNameActionHandler(self))
        ida_kernwin.register_action(apply_sdk_name_action)
        ida_kernwin.update_action_state('cppparser:apply-sdk-name', ida_kernwin.AST_ENABLE_ALWAYS)

        ida_kernwin.create_toolbar('cppparser', 'CPP Parser')

        ida_kernwin.attach_action_to_toolbar('cppparser', 'cppparser:sync')

        self.ui_hooks = CPPParserUIHooks()
        self.ui_hooks.hook()
        # global apply_sdk_name_hk
        # apply_sdk_name_hk = ida_kernwin.add_hotkey('Shift+N', apply_sdk_name)

    def dispose(self):
        self.ui_hooks.unhook()
        # ida_kernwin.del_hotkey(apply_sdk_name_hk)

        ida_kernwin.detach_action_from_toolbar('cppparser', 'cppparser:sync')

        ida_kernwin.delete_toolbar('cppparser')

        ida_kernwin.unregister_action('cppparser:apply-sdk-name')
        ida_kernwin.unregister_action('cppparser:sync')

try:
    cppparser
    try:
        cppparser.dispose()
        del cppparser
        print('cpp parser unregistered')
    except Exception as err:
        print(str(err))
except:
    cppparser = CPPParser()
    print('cpp parser installed')