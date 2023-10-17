from ida_bytes import get_full_flags
from ida_funcs import get_func, FUNC_THUNK
from ida_name import demangle_name
from ida_nalt import get_imagebase
from analrangers.lib.naming import nlist_names

image_base = get_imagebase()

f = open(f'thunks.asm', 'w')
f.write("""; Some thunks
.data
	moduleOffset dq 0

.code

PUBLIC SetBaseAddress
SetBaseAddress:
	mov moduleOffset, rcx
	ret

;PUBLIC GetFunctionAddress
;GetFunctionAddress:
;	mov rax, moduleOffset
;    jmp rcx+
""")
for name, ea in nlist_names():
    flags = get_full_flags(ea)
    demangled = demangle_name(name, 0)
    if len(name) > 300 or name.startswith('j_') or not demangled:
        continue
    func = get_func(ea)
    if not func or func.flags & FUNC_THUNK or func.start_ea != ea:
        continue

    f.write(f"""
PUBLIC {name}
{name}:
	mov rax, moduleOffset
	add rax, 0{ea - image_base:x}h
	jmp rax
""")

f.write('end\n')
f.close()
