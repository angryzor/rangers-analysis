from ida_idaapi import BADADDR
import ida_bytes
import ida_kernwin

# def add_strlits():
result, cur_ea, max_ea = ida_kernwin.read_range_selection(None)

if not result:
    exit()

print(f'From {cur_ea:x} to {max_ea:x}')

str_count = 0

while cur_ea < max_ea:
    result = ida_bytes.create_strlit(cur_ea, 0, 0)
    print(result)
    str_count += 1

    cur_ea = ida_bytes.next_not_tail(cur_ea)
    while ida_bytes.get_byte(cur_ea) == 0:
        cur_ea = ida_bytes.next_addr(cur_ea)

print(f'Inserted {str_count} strs')

# try:
#     hotkey_ctx
#     if ida_kernwin.del_hotkey(hotkey_ctx):
#         print("Hotkey unregistered!")
#         del hotkey_ctx
#     else:
#         print("Failed to delete hotkey!")
# except:
#     hotkey_ctx = ida_kernwin.add_hotkey("Shift-A", add_strlits)
#     if hotkey_ctx is None:
#         print("Failed to register hotkey!")
#         del hotkey_ctx
#     else:
#         print("Hotkey registered!")
