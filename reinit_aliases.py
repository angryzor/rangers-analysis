import sys

analysismodules = [mod for mod in sys.modules if mod.startswith('rangers_analysis')]
for mod in analysismodules:
    del sys.modules[mod]

from rangers_analysis.config import autoconfigure_rangers_analysis
autoconfigure_rangers_analysis()

from rangers_analysis.lib.naming import nlist_names, add_alias, get_alias_ea, remove_alias

for name, ea in nlist_names():
    if backref := get_alias_ea(name):
        if backref != ea:
            remove_alias(backref, name)
    add_alias(ea, name)
