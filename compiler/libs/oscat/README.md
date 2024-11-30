# Oscat Basic

## An Oscat basic library for RuSTy

A modified version of the Oscat Library that could be compiled using RuSTy.

In its current status, not every feature of the library compiles.

### Build Oscat

[StandardFunctions](https://github.com/PLC-lang/StandardFunctions) are needed to compile Oscat.\
To avoid compile errors, `stubs.st` includes stubs for functions that are not part of [StandardFunctions](https://github.com/PLC-lang/StandardFunctions).

To build Oscat, `plc.json` can be used as the build description.
> **_NOTE:_** Paths need to be adjusted in `plc.json`\
> for more info see [RuSTy build with build configuration](https://plc-lang.github.io/rusty/using_rusty/build_configuration.html)

### Modifications

To reduce warnings we made the following non breaking changes :

- String range changed from `()` to `[]`
- `POINTER TO` was changed to `REF_TO`
- `FUNCTIONBLOCK` renamed to `FUNCTON_BLOCK`

To avoid errors we made the following non breaking changes :

- Array initializers are surrounded by `[]`
  - (PLC-lang/rusty#352) fixed
- TOD literals are moved to 3 sections
  - (PLC-lang/rusty#355) fixed
- ADR was replaced with &
  - (PLC-lang/rusty#469) fixed
- Functions parameters are changed to `()` instead of `[]`

To avoid errors, the following **breaking** changes were made :

- `VAR_INPUT CONSANT` was changed to `VAR_INPUT`
- `OVERRIDE` was renamed to `_OVERRIDE`
- `ARRAY_MAX/MIN/SPR/SUM` type of size changed to ULINT
