import ida_typeinf
import ida_kernwin
import ida_ua
import ida_name

cur_ea = ida_kernwin.get_screen_ea()

while ida_ua.print_insn_mnem(cur_ea) == 'mov':
    print(f'{cur_ea:x}')
    source_insn = ida_ua.insn_t()
    source_insn_size = ida_ua.decode_insn(source_insn, cur_ea)
    source_addr = source_insn.Op2.addr

    cur_ea += source_insn_size
    
    dest_insn = ida_ua.insn_t()
    dest_insn_size = ida_ua.decode_insn(dest_insn, cur_ea)
    dest_addr = dest_insn.Op1.addr
    
    cur_ea += dest_insn_size

    source_name = ida_name.get_ea_name(source_addr)

    if source_name == None:
        print(f'No name for addr {source_addr:x}')
        continue
    else:
        ida_name.set_name(dest_addr, f'{source_name}Tls')

    typ = ida_typeinf.idc_get_type_raw(source_addr)

    if typ == None:
        print(f'No type for addr {source_addr:x}')
        continue
    else:
        (bt1, bt2) = typ

        source_tinfo = ida_typeinf.tinfo_t()
        source_tinfo.deserialize(None, bt1, bt2)

        new_tinfo = ida_typeinf.tinfo_t()
        new_tinfo.create_ptr(source_tinfo)

        ida_typeinf.apply_tinfo(dest_addr, new_tinfo, ida_typeinf.TINFO_STRICT)
