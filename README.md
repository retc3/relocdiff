# relocdiff

Find the same function across different builds of a PE binary.

```sh
relocdiff find old.exe new.exe --address 0x140187F980
```

`relocdiff` normalizes address-dependent x86-64 instructions before matching.

## Install

```sh
cargo install relocdiff
```

## Usage

```sh
relocdiff find OLD NEW --address VA
relocdiff find OLD NEW --rva RVA
relocdiff inspect FILE --address VA
```

Use `relocdiff --help` for all options.

## Support

v0.1 supports x86-64 PE32+ images.

## License

MIT OR Apache-2.0
