from rangers_analysis.lib.naming import nlist_names, add_alias, get_alias_ea, remove_alias

for name, ea in nlist_names():
    if backref := get_alias_ea(name):
        if backref != ea:
            remove_alias(backref, name)
    add_alias(ea, name)
