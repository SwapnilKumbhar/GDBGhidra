# GDBGhidra

A GDB plugin to provide Ghidra's decompilation within GDB. To achieve this, the plugin uses `r2ghidra` underneath. `r2ghidra` abstracts all interactions with Ghidra's native decompiler and combined with `r2pipe`, provides a clean interface to use in Python.

## Demo :rocket:

![BasicDemo](./Demo/decompilerDemo.gif)

## Usage

Add the following line in your `gdbinit` 

```
source /path/to/gdbghidra/gdbinit.py
```

This will give you access to the `decompileGhidra` function within GDB. 

```
decompileGhidra [ADDRESS|FUNC_NAME]
```

You can run the function in two ways:

1. With an argument, where the argument can be the name of the function or an address
2. Without an argument, at which point the function will decompile whatever is at the current Program Counter.

#### Disclaimer

I have tested this _only_ on the x86-64 architecture. Other architectures have not been tested yet, but feel free to report any bugs!


## Requirements
- r2pipe
- r2ghidra

