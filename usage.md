
## Object system registries
### Tag the GameObjectClass array.
* Go to the `app::MyApplication` vtable.
* Enter the second vfunc, `Startup`. (i.e. the first real vfunc, not the destructor)
* All the way at the start of this function you'll see it do something with a string "sound".
  Right after that call it will call `LoadGameObjectClasses`, and you'll find the address of the
  `staticGameObjectClasses` array.
* Tag this array as `?staticGameObjectClasses@GameObjectRegistry@game@hh@@0PAPEAVGameObjectClass@23@A`

### Tag the GOComponent array (rangers only)
* Go back up, the next call initializes the `GOComponentRegistry`.
* It is initialized from the array of `GOComponentClass` items.
* Tag this array as ``.

### Tag the ObjInfo array
* The next call initializes the `ObjInfoRegistry`.
* Tag the array loaded here as `?staticObjInfoClasses@ObjInfoRegistry@game@hh@@0PAPEAVObjInfoClass@23@A`.

## RFL registries
### The RflClass array
* Go back to the array of GameObjectClasses.
* Find an object class that has a spawner RFL class and go to it.
* Follow an xref up to a location where it is loaded as an offset in an array of other classes.
* Tag this array as `?staticRflClasses@RflClassNameRegistry@fnd@hh@@0PAPEAVRflClass@23@A`.

### The RflTypeInfo array
* Follow an xref of this array up, to the `hh::fnd::BuiltinTypeRegistry` initialization function.
* Another object is being initialized here with another array. Tag that array as `?staticRflTypeInfos@RflTypeInfoRegistry@fnd@hh@@0PAPEAVRflTypeInfo@23@A`.

### The singleton list
* Follow xrefs of the `BuiltinTypeRegistry` constructor up until you end up in its static initializer.
* One of the adresses referenced there has a bunch of xrefs, every time 1 read and 1 write. This is the singleton list.
* Tag this address as `singletonList`.

### The static initializer list
* Follow an xref up from this initializer to get to the static initializer list.
* Tag this array as `staticInitializersStart`.
* Tag the first address past this array as `staticInitializersEnd`.

## Major constructor functions
## `hh::game::GameObject`
* Find the GameObject vtable and tag its constructor:
    * wars: `??0GameObject@game@hh@@QEAA@XZ`
    * rangers+: `??0GameObject@game@hh@@QEAA@PEAVIAllocator@fnd@csl@@@Z`

## `hh::game::GOComponent`
* Find the GOComponent vtable and tag its constructor
    * wars: `??0GOComponent@game@hh@@QEAA@XZ`

## `hh::game::GameService`
* Find the GameService vtable and tag its constructor
    * wars: `??0GameService@game@hh@@QEAA@XZ`
