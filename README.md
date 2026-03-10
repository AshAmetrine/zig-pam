# Zig PAM Wrapper

A Zig wrapper around the PAM (Pluggable Authentication Modules) C library (libpam).

## Features

- Minimal, direct mapping to PAM calls.
- Typed flags and items for common operations.
- Conversation helpers (`Messages`, `Prompt.respond`).

## Requirements

- Zig 0.15.2.
- `libc`.
- `libpam`.

## Usage

Add the dependency with `zig fetch`:

```sh
zig fetch --save git+https://github.com/ashametrine/zig-pam
```

Then add it as an import in `build.zig`:

```zig
const pam = b.dependency("zig_pam", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("pam", pam.module("pam"));
```

## Example

The example program lives at `example/main.zig`.

To build the included example:

```sh
zig build example
```

Run it:

```sh
./zig-out/bin/example <user>
```
