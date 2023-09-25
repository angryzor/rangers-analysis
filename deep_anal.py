import sys

analmodules = [mod for mod in sys.modules if mod.startswith('analrangers')]
for mod in analmodules:
    del sys.modules[mod]

from analrangers.informed_analysis.static_initializers import find_static_initializers
from analrangers.informed_analysis.services import find_services
from analrangers.informed_analysis.rfl import find_rfl_statics
from analrangers.informed_analysis.gocs import find_gocs
from analrangers.informed_analysis.object_classes import find_obj_classes
# from analrangers.informed_analysis.state_descs import find_state_descs
from analrangers.informed_analysis.report import clear_report, print_report

clear_report()

static_initializer_eas = find_static_initializers()

find_services()
find_rfl_statics()
find_gocs()
find_obj_classes()
# find_state_descs(static_initializer_eas)

print_report()
