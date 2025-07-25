# Tools

Tools used to interact with the project.

Compilation instructions given here assumes that the tools are built on an
`x86_64` machines with an `aarch64` toolchain installed, while usage examples
assume the program runs on an `aarch64` machine.

## `load_rmm.c`

This program is used to load the RMM directly into memory. It does so by
writing the RMM binary to `/dev/mem` (this requires to enable unsecure
`/dev/mem` accesses in the kernel config), and telling KVM where the RMM was
loaded.

```sh
# Building
aarch64-linux-gnu-gcc dedicate_core.c -o dedicate_core -static

# Example usage
./load_rmm 0x2100000000 rmm.img
```

## `dedicate_core.c`

This program is used to dedicate a core the RMM. It must be used _after_ the RMM
has been loaded into memory.

If no argument is passed, the current core is dedicated, otherwise dedicate the
core with the provided ID.

```sh
# Building
aarch64-linux-gnu-gcc dedicate_core.c -o dedicate_core -static

# Example usage
./dedicate_core 10
```
