import sys

analysismodules = [mod for mod in sys.modules if mod.startswith('rangers_analysis')]
for mod in analysismodules:
    del sys.modules[mod]

from rangers_analysis.config import autoconfigure_rangers_analysis

autoconfigure_rangers_analysis()

from ida_name import get_demangled_name, MNG_SHORT_FORM
from rangers_analysis.lib.util import require_type, require_name_ea
from rangers_analysis.lib.heuristics import discover_class_hierarchy, estimate_class_name_from_constructor
from rangers_analysis.lib.funcs import require_function

class_tif = require_type('hh::game::GOComponentClass')

f = open(f'rangers-classes.txt', 'w')

for instantiator_thunk, instantiator_func, ctor_thunk, ctor_func, base_ctor_func in discover_class_hierarchy(require_function(require_name_ea('hh::game::GameService::GameService'))):
    name = estimate_class_name_from_constructor(ctor_func) or get_demangled_name(ctor_func.start_ea, MNG_SHORT_FORM, 0)
    base_name = estimate_class_name_from_constructor(base_ctor_func) or get_demangled_name(base_ctor_func.start_ea, MNG_SHORT_FORM, 0)

    f.write(f'{instantiator_func.start_ea if instantiator_func else 0:016x}/{ctor_func.start_ea:016x} -- {"*" if instantiator_func == ctor_func else " "} {name} : {base_name}\n')

f.close()
