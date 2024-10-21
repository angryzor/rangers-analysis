import sys

analysismodules = [mod for mod in sys.modules if mod.startswith('rangers_analysis')]
for mod in analysismodules:
    del sys.modules[mod]

from rangers_analysis.config import autoconfigure_rangers_analysis
autoconfigure_rangers_analysis()

from ida_bytes import get_byte, has_user_name, get_full_flags
from ida_ua import o_void, o_mem, o_near, o_phrase, o_displ, o_far
from ida_name import get_name, demangle_name
from ida_funcs import FUNC_THUNK, get_func_name
from rangers_analysis.lib.ua_data_extraction import decoded_insns_forward
from rangers_analysis.lib.xrefs import get_fcrefs_from, get_drefs_from
from rangers_analysis.lib.funcs import get_all_functions

pat_min_length = 10
pat_max_length = 32

CRC16_TABLE = [
	0x0, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1,
	0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7, 0x1081, 0x108, 0x3393, 0x221a,
	0x56a5, 0x472c, 0x75b7, 0x643e, 0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64,
	0xf9ff, 0xe876, 0x2102, 0x308b, 0x210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5, 0x3183, 0x200a,
	0x1291, 0x318, 0x77a7, 0x662e, 0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9, 0x8f50,
	0xfbef, 0xea66, 0xd8fd, 0xc974, 0x4204, 0x538d, 0x6116, 0x709f, 0x420, 0x15a9,
	0x2732, 0x36bb, 0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x528, 0x37b3, 0x263a, 0xdecd, 0xcf44,
	0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72, 0x6306, 0x728f, 0x4014, 0x519d,
	0x2522, 0x34ab, 0x630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3,
	0x8a78, 0x9bf1, 0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70, 0x8408, 0x9581,
	0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x840, 0x19c9, 0x2b52, 0x3adb,
	0x4e64, 0x5fed, 0x6d76, 0x7cff, 0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324,
	0xf1bf, 0xe036, 0x18c1, 0x948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5, 0x2942, 0x38cb,
	0xa50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd, 0xb58b, 0xa402, 0x9699, 0x8710,
	0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1, 0xb58, 0x7fe7, 0x6e6e,
	0x5cf5, 0x4d7c, 0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0xc60, 0x1de9, 0x2f72, 0x3efb, 0xd68d, 0xc704,
	0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232, 0x5ac5, 0x4b4c, 0x79d7, 0x685e,
	0x1ce1, 0xd68, 0x3ff3, 0x2e7a, 0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3,
	0x8238, 0x93b1, 0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0xe70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e,
	0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0xf78
]

def crc16(data, crc):
	for byte in data:
		crc = (crc >> 8) ^ CRC16_TABLE[(crc ^ ord(byte)) & 0xFF]
	crc = (~crc) & 0xFFFF
	crc = (crc << 8) | ((crc >> 8) & 0xFF)
	return crc & 0xffff

def find_ref_loc(ea, ref):
	insn = ida_ua.insn_t()
	insn_size = ida_ua.decode_insn(insn, ea)

	ops = [*insn.ops]
	for i, op in enumerate(ops):
		if op.type != 0 and op.addr == ref:
			j = i + 1
			return ea + op.offb, ea + (insn_size if j >= len(ops) or ops[j].type == 0 else ops[j].offb)
		
	raise Exception(f'Could not find op for {ea:x}, {ref:x}')

def get_operand_ea_range(insn, op):
	ops = insn.insn.ops
	j = op.n + 1

	return insn.ea + op.offb, insn.ea + (insn.size if j >= len(ops) or ops[j].type == 0 else ops[j].offb)

def generate_signature(f):
	var_bytes = set()
	xrefs = dict()
	publics = []

	pat_end_ea = min(f.start_ea + pat_max_length, f.end_ea) if pat_max_length != None else f.end_ea

	publics.append(f.start_ea)

	for insn in decoded_insns_forward(f.start_ea, pat_end_ea):
		# if get_name(insn.ea):
		# 	publics.append(insn.ea)

		xref_addrs = dict()
		
		for op in insn.insn.ops:
			if op.type == o_void:
				continue

			# if op.type in (o_mem, o_near, o_phrase, o_displ, o_far) and (op.addr >= 0x1000000 and (op.addr & 0xFF00000000000000) == 0) and (op.addr < f.start_ea or op.addr >= f.end_ea):
			if op.type in (o_mem, o_near, o_phrase, o_displ, o_far) and (op.addr >= 0x1000000 and (op.addr & 0xFF00000000000000) == 0):
			# if op.type in (o_mem, o_near, o_far) and (op.addr < f.start_ea or op.addr >= f.end_ea):
				start_ea, end_ea = get_operand_ea_range(insn, op)

				for ea in range(start_ea, end_ea):
					var_bytes.add(ea)

				if op.addr:
					xref_addrs[op.addr] = start_ea

		for ea in get_drefs_from(insn.ea):
			if (ea & 0xFF00000000000000) == 0:
				if ea in xref_addrs:
					xrefs[xref_addrs[ea]] = ea

		for ea in get_fcrefs_from(insn.ea):
			if (ea & 0xFF00000000000000) == 0 and (ea < f.start_ea or ea >= f.end_ea):
				if ea in xref_addrs:
					xrefs[xref_addrs[ea]] = ea

	sig = ''
	for ea in range(f.start_ea, f.start_ea + 32):
		if ea >= pat_end_ea or ea in var_bytes:
			sig += '..'
		else:
			sig += f'{get_byte(ea):02X}'

	if pat_end_ea - f.start_ea > 32:
		crc_data = [0 for i in range(256)]

		# for 255 bytes starting at index 32, or til end of ftion, or variable byte
		for loc in range(32, min(pat_end_ea - f.start_ea, 32 + 255)):
			if f.start_ea + loc in var_bytes:
				break

			crc_data[loc - 32] = get_byte(f.start_ea + loc)
		else:
			loc += 1

		# TODO: is this required everywhere? ie. with variable bytes?
		alen = loc - 32

		crc = crc16("".join(map(chr, crc_data[:alen])), crc=0xFFFF)
	else:
		loc = pat_end_ea - f.start_ea
		alen = 0
		crc = 0

	sig += " %02X" % (alen)
	sig += " %04X" % (crc)
	# TODO: does this need to change for 64bit?
	sig += " %04X" % (pat_end_ea - f.start_ea)

	# this will be either " :%04d %s" or " :%08d %s"
	public_format = " :%%0%dX %%s" % 8
	for public in publics:
		name = get_name(public)
		if name is None or name == "":
			continue

		sig += public_format % (public - f.start_ea, name)

	for ref_loc, ref in xrefs.items():
		name = get_name(ref)
		if name is None or name == "":
			continue

		if ref_loc >= f.start_ea:
			# this will be either " ^%04d %s" or " ^%08d %s"
			addr = ref_loc - f.start_ea
			ref_format = " ^%%0%dX %%s" % 8
		else:
			# this will be either " ^-%04d %s" or " ^-%08d %s"
			addrs = f.start_ea - ref_loc
			ref_format = " ^-%%0%dX %%s" % 8
		sig += ref_format % (addr, name)
		
	# Tail of the module starts at the end of the CRC16 block.
	if loc < pat_end_ea - f.start_ea:
		tail = " "
		for ea in range(f.start_ea + loc, min(pat_end_ea, f.start_ea + 0x8000)):
			if ea in var_bytes:
				tail += ".."
			else:
				tail += "%02X" % (get_byte(ea))
		sig += tail

	return sig

def main():
	sigs = []

	for f in get_all_functions():
		if has_user_name(get_full_flags(f.start_ea)) and f.flags & FUNC_THUNK == 0 and f.end_ea - f.start_ea >= pat_min_length:
			name = get_func_name(f.start_ea)
			demangled = demangle_name(name, 0)
			if len(name) > 200 or name.startswith('j_') or name.startswith('??_7') or name.startswith('??_R') or name.startswith('??__E') or name.startswith('??__F') or not demangled:
				continue

			# try:
			sigs.append(generate_signature(f))
			# except Exception as e:
			# 	print(e)
			# 	print(f'Failed to create signature for function at {f.start_ea:x}, {get_name(f.start_ea) or ""}')

	with open("out.pat", 'wb') as f:
		for sig in sigs:
			f.write(sig.encode('ascii'))
			f.write(b"\r\n")
		f.write(b"---")
		f.write(b"\r\n")

main()
