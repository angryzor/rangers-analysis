from rangers_analysis.lib.util import require_type, require_name_ea, force_apply_tinfo
from rangers_analysis.lib.xrefs import get_safe_crefs_to
from rangers_analysis.lib.heuristics import get_best_class_name, require_constructor_thunk_from_instantiator
from rangers_analysis.lib.funcs import require_thunk, require_function, ensure_functions, find_implementation
from rangers_analysis.lib.ua_data_extraction import read_source_op_addr_from_reg_assignment
from rangers_analysis.lib.naming import set_private_instantiator_func_name, set_simple_constructor_func_name, set_static_initializer_func_name, set_static_atexit_dtor_func_name, set_static_var_name, StaticObjectVar, StaticObjectVarType, friendly_class_name
from rangers_analysis.lib.require import NotFoundException
from .report import handle_anal_exceptions, report_failure

state_desc_tif = require_type('hh::ut::StateDesc')

statedesc_class_name = ['StateDesc', 'ut', 'hh']

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

    instance_var = StaticObjectVar('stateDesc', statedesc_class_name, StaticObjectVarType.VAR, True)

    print(f'info: handling StateDesc at {state_desc_ea:x}: {friendly_class_name(class_name)} (instantiator: {instantiator.start_ea:x}, ctor_thunk: {ctor_thunk.start_ea if ctor_thunk else 0:x}, constructor: {ctor.start_ea if ctor else 0:x})')

    # Set desc info
    force_apply_tinfo(state_desc_ea, state_desc_tif)
    set_static_var_name(state_desc_ea, class_name, instance_var)

    # Set instantiator info
    set_private_instantiator_func_name(instantiator_thunk, class_name)
    # force_apply_tinfo()

    # Set constructor info
    if ctor_thunk:
        set_simple_constructor_func_name(ctor_thunk, class_name)

    # Set initializer info
    set_static_initializer_func_name(initializer_thunk, class_name, instance_var)

    # Set atexit dtor info
    set_static_atexit_dtor_func_name(atexit_dtor, class_name, instance_var)

def find_state_descs(static_initializers):
    ctor_ea = require_name_ea('??0StateDescImpl@internal@ut@hh@@QEAA@PEBDP6APEAVStateDesc@23@PEAVIAllocator@fnd@csl@@@ZH@Z')
    
    for xref in get_safe_crefs_to(ctor_ea):
        handle_anal_exceptions(lambda: handle_state_desc(xref, static_initializers))
