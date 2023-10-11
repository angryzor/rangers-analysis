from analrangers.lib.util import require_type, require_name_ea
from analrangers.lib.xrefs import get_safe_crefs_to
from analrangers.lib.heuristics import get_best_class_name, require_constructor_thunk_from_instantiator
from analrangers.lib.funcs import require_thunk, require_function, ensure_functions, find_implementation
from analrangers.lib.ua_data_extraction import read_source_op_addr_from_reg_assignment
from analrangers.lib.naming import set_generated_func_name, set_generated_name
from analrangers.lib.require import NotFoundException
from .report import handle_anal_exceptions, report_failure

rfl_type_info_tif = require_type('hh::ut::StateDesc')

def handle_state_desc(xref, static_initializers):
    initializer = require_function(xref)
    initializer_thunk = require_thunk(initializer)

    initializer_ea = initializer.start_ea

    if initializer_thunk.start_ea not in static_initializers:
        print(f'warn: ignoring {initializer_thunk.start_ea:x} as it does not appear in the list of dynamic initializers')
        return
    
    state_desc_ea = read_source_op_addr_from_reg_assignment(initializer_ea, 1) - 8
    name_ea = read_source_op_addr_from_reg_assignment(initializer_ea, 2)
    atexit_dtor = ensure_functions(read_source_op_addr_from_reg_assignment(xref, 1))
    instantiator_thunk = ensure_functions(read_source_op_addr_from_reg_assignment(initializer_ea, 8))
    instantiator = find_implementation(instantiator_thunk)

    try:
        ctor_thunk = require_constructor_thunk_from_instantiator(instantiator)
        ctor = find_implementation(ctor_thunk)
    except NotFoundException as err:
        ctor_thunk = None
        ctor = None
        report_failure(err)

    class_name, is_fallback_name = get_best_class_name(ctor, name_ea, 'states')
    backrefs = "".join([str(i) for i in range(1, 1 + len(class_name.split("@")))])

    print(f'info: handling StateDesc at {state_desc_ea:x}: {class_name} (instantiator: {instantiator.start_ea:x}, ctor_thunk: {ctor_thunk.start_ea if ctor_thunk else 0:x}, constructor: {ctor.start_ea if ctor else 0:x})')

    # Set desc info
    # force_apply_tinfo(state_desc_ea, state_desc_tif)
    set_generated_name(state_desc_ea, f'?staticInstance@{class_name}@@0VStateDesc@ut@hh@@B')

    # Set instantiator info
    set_generated_func_name(instantiator_thunk, f'?Instantiate@{class_name}@@CAPEAV{backrefs}@PEAVIAllocator@fnd@csl@@@Z')
    # force_apply_tinfo()

    # Set constructor info
    if ctor_thunk:
        set_generated_func_name(ctor_thunk, f'??0{class_name}@@QEAA@PEAVIAllocator@fnd@csl@@@Z')

    # Set initializer info
    set_generated_func_name(initializer_thunk, f'??__EstaticInstance@{class_name}@@0VStateDesc@ut@hh@@B')

    # Set atexit dtor info
    set_generated_func_name(atexit_dtor, f'??__FstaticInstance@{class_name}@@0VStateDesc@ut@hh@@B')

def find_state_descs(static_initializers):
    ctor_ea = require_name_ea('??0StateDescImpl@internal@ut@hh@@QEAA@PEBDP6APEAVStateDesc@23@PEAVIAllocator@fnd@csl@@@ZH@Z')
    
    for xref in get_safe_crefs_to(ctor_ea):
        handle_anal_exceptions(lambda: handle_state_desc(xref, static_initializers))
