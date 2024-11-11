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
from math import log2, floor
import json

transform_weights = {
	'constantless': 0.4,
	'indefinite-registers': 0.7,
}

ignored_prefixes = ['j_', '??_7', '??_R', '??_D', '??__E', '??__F']

def is_sdk_name(name):
	return len(name) <= 200 and not any(map(lambda pfx: name.startswith(pfx), ignored_prefixes)) and demangle_name(name, 0)

def get_operand_ea_range(insn, op):
	ops = insn.insn.ops
	j = op.n + 1

	return insn.ea + op.offb, insn.ea + (insn.size if j >= len(ops) or ops[j].type == 0 else ops[j].offb)

def generate_signaturelet(f, insn):
	var_bytes = set()
	xrefs = []
	xref_addrs = dict()
	
	for op in insn.insn.ops:
		if op.type == o_void:
			continue

		if op.type in (o_mem, o_near, o_phrase, o_displ, o_far) and (op.addr >= 0x1000000 and (op.addr & 0xFF00000000000000) == 0):
			op_start_ea, op_end_ea = get_operand_ea_range(insn, op)

			for ea in range(op_start_ea, op_end_ea):
				var_bytes.add(ea)

			if op.addr:
				xref_addrs[op.addr] = op_start_ea

	for ea in get_drefs_from(insn.ea):
		if (ea & 0xFF00000000000000) == 0 and ea in xref_addrs:
			if xref_name := get_name(ea):
				if is_sdk_name(xref_name):
					xrefs.append({ 'offset': xref_addrs[ea] - insn.ea, 'target_addr': ea, 'target_canonical_name': xref_name })

	for ea in get_fcrefs_from(insn.ea):
		if (ea & 0xFF00000000000000) == 0 and (ea < f.start_ea or ea >= f.end_ea) and ea in xref_addrs:
			if xref_name := get_name(ea):
				if is_sdk_name(xref_name):
					xrefs.append({ 'offset': xref_addrs[ea] - insn.ea, 'target_addr': ea, 'target_canonical_name': xref_name })
	
	pat = ''
	for ea in range(insn.ea, insn.ea + insn.size):
		pat += '?? ' if ea in var_bytes else f'{get_byte(ea):02x} '

	return { 'sig': pat[:-1], 'addr': insn.ea, 'offset': insn.ea - f.start_ea, 'size': insn.size, 'xrefs': xrefs }

def combine_siglets(siglets):
	xrefs = []
	off = 0

	for sig in siglets:
		for xref in sig['xrefs']:
			xrefs.append({ **xref, 'offset': off + xref['offset'] })
		off += sig['size']

	return {
		'sig': ' '.join(map(lambda s: s['sig'], siglets)),
		'size': sum(map(lambda s: s['size'], siglets)),
		'addr': siglets[0]['addr'],
		'offset': siglets[0]['offset'],
		'xrefs': xrefs
	}

def subdivide_harmonics(insn_count):
	for order in range(0, floor(log2(insn_count))):
		for i in range(0, order):
			yield i, order, order

def subdivide_bisection(insn_count):
	for order in range(0, floor(log2(insn_count))):
		subdivisions = pow(2, order)
		for i in range(0, subdivisions):
			yield i, subdivisions, order

def align(ea, alignment):
	return (ea + alignment - 1) & ~(alignment - 1)

def generate_signatures(f):
	insn_siglets = []
	sigs = []
	func_size = f.end_ea - f.start_ea

	name = get_func_name(f.start_ea)
	
	for insn in decoded_insns_forward(f.start_ea, f.end_ea):
		insn_siglets.append(generate_signaturelet(f, insn))
	
	insn_count = len(insn_siglets)
	for i, subdivisions, order in subdivide_bisection(insn_count):
		start_idx = floor(i * insn_count / subdivisions)
		end_idx = floor((i + 1) * insn_count / subdivisions)

		sigs.append({ 'order': order, 'first': i == 0, 'last': i == subdivisions - 1, **combine_siglets(insn_siglets[start_idx:end_idx]) })

	return { 'addr': f.start_ea, 'canonical_name': name, 'size': func_size, 'sigs': sigs }

def generate_duplicate_key(sig):
	return json.dumps({ 'sig': sig['sig'], 'xrefs': sig['xrefs'] })

def main():
	results = []
	found_sigs = set()
	found_duplicates = set()

	for f in get_all_functions():
		if f.flags & FUNC_THUNK == 0:# and f.end_ea - f.start_ea >= pat_min_length:
			# Since miller some pure functions are just 0xCCCCCCCCCCCCCCCCCC
			if get_byte(f.start_ea) == 0xCC:
				continue

			sig_group = generate_signatures(f)

			# for sig in sig_group['sigs']:
			# 	key = generate_duplicate_key(sig)
			# 	if key in found_sigs:
			# 		found_duplicates.add(key)
			# 	found_sigs.add(key)

			if has_user_name(get_full_flags(f.start_ea)) and is_sdk_name(get_func_name(f.start_ea)):
				results.append(sig_group)
	
	for result in results:
		result['sigs'] = [*filter(lambda sig: generate_duplicate_key(sig) not in found_duplicates, result['sigs'])]
		
	with open("out.pat.json", 'w') as file:
		json.dump(results, file, indent=2)

		# for sig in found_duplicates:
		# 	file.write(f'DUPLICATE: {sig}\r\n'.encode('ascii'))

	print(f'{len(found_duplicates)} duplicates found\r\n')

main()
