import ida_bytes
import ida_name
import ida_nalt
from datetime import datetime
import os
from itertools import takewhile, dropwhile
import re

image_base = ida_nalt.get_imagebase()

basedir = f'rangers-{int(datetime.now().timestamp())}'

def get_shortest_qualifier(namespace1, namespace2):
    depth = 0

    while depth != len(namespace1) and depth != len(namespace2) and namespace1[depth] == namespace2[depth]:
        depth += 1
    
    return namespace2[depth:]

def split_namespace(class_name):
    template_start = class_name.find("<")

    if template_start == -1:
        template_start = len(class_name)

    templateless_class_name = class_name[:template_start]

    templateless_class_name_parts = templateless_class_name.split("::")


    namespace_parts = [x for x in takewhile(lambda x: not re.match(r'[A-Z]', x), templateless_class_name_parts)]
    local_templateless_class_name_parts = [x for x in dropwhile(lambda x: not re.match(r'[A-Z]', x), templateless_class_name_parts)]

    if len(local_templateless_class_name_parts) == 0:
        if len(namespace_parts) == 0:
            raise Exception('zero length name?')
        
        last = namespace_parts.pop()
        local_templateless_class_name_parts = [last]

    local_templateless_class_name = "::".join(local_templateless_class_name_parts)
    local_class_name = local_templateless_class_name + class_name[template_start:]

    return namespace_parts, local_class_name, local_templateless_class_name_parts[0]


for i in range(0, ida_name.get_nlist_size()):
    rtti_name = ida_name.demangle_name(ida_name.get_nlist_name(i), 0)

    if rtti_name == None or not "`RTTI Class Hierarchy Descriptor'" in rtti_name:
        continue

    ea = ida_name.get_nlist_ea(i)

    class_name = rtti_name[:rtti_name.rfind("::")]

    class_namespace_parts, local_class_name, templateless_local_class_name = split_namespace(class_name)

    base_arr_size = ida_bytes.get_dword(ea + 8)
    base_arr_ea = image_base + ida_bytes.get_dword(ea + 12)
    cur_base = 1

    bases = []
    while cur_base < base_arr_size:
        base_ea = image_base + ida_bytes.get_dword(base_arr_ea + cur_base * 4)

        num_base_bases = ida_bytes.get_dword(base_ea + 4)

        base_class_rtti_name = ida_name.get_demangled_name(base_ea, 0, 0)
        base_class_name = base_class_rtti_name[:base_class_rtti_name.rfind("::")]

        base_class_namespace_parts, local_base_class_name, _ = split_namespace(base_class_name)

        namespace_qualifier = get_shortest_qualifier(class_namespace_parts, base_class_namespace_parts)

        bases.append("::".join([*namespace_qualifier, local_base_class_name]))

        cur_base += num_base_bases + 1

    outdir = "/".join([basedir, *class_namespace_parts])
    os.makedirs(outdir, 0o777, True)
    f = open(f'{outdir}/{templateless_local_class_name}.h', 'a')
    f.write(f"""
namespace {"::".join(class_namespace_parts)} {"{"}
    class {local_class_name}{"" if len(bases) == 0 else f' : {", ".join(bases)}'} {"{"}
    {"};"}
{"}"}
""")
    f.close()


print('done')