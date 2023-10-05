import sys

analmodules = [mod for mod in sys.modules if mod.startswith('analrangers')]
for mod in analmodules:
    del sys.modules[mod]

from analrangers.informed_analysis.static_initializers import find_static_initializers
from analrangers.informed_analysis.services import find_services
from analrangers.informed_analysis.rfl import find_rfl_statics
from analrangers.informed_analysis.gocs import find_gocs
from analrangers.informed_analysis.object_classes import find_obj_classes
from analrangers.informed_analysis.state_descs import find_state_descs
from analrangers.informed_analysis.math_objects import find_common_math_objects
from analrangers.informed_analysis.singletons import find_singletons
from analrangers.informed_analysis.report import clear_report, print_report

clear_report()

static_initializer_eas = find_static_initializers()

print('=== SERVICE ANALYSIS ===')
find_services()
print('=== REFLECTION ANALYSIS ===')
find_rfl_statics(static_initializer_eas)
print('=== GOC ANALYSIS ===')
find_gocs()
print('=== GAMEOBJECT ANALYSIS ===')
find_obj_classes()
print('=== STATEDESC ANALYSIS ===')
find_state_descs(static_initializer_eas)
print('=== FLOATING POINT MATH OBJECT ANALYSIS ===')
find_common_math_objects()
print('=== SINGLETON ANALYSIS ===')
find_singletons(static_initializer_eas)

print_report()
