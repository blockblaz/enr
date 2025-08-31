# enr
Ethereum Node Records (ENR) utility in Zig.

## Prerequisites

- Zig 0.14.1

## Building

To build the project, run the following command in the root directory of the project:

```bash
zig build -Doptimize=ReleaseSafe
```

## Running Tests

To run the tests, run the following command in the root directory of the project:

```bash
zig build test --summary all
```

## Docs

To generate documentation for the project, run the following command in the root directory of the project:

```bash
zig build docs
```

# Usage

Update `build.zig.zon`:

```sh
zig fetch --save git+https://github.com/blockblaz/enr
```

In your `build.zig`:

```zig
const enr_dep = b.dependency("zig_enr", .{
    .target = target,
    .optimize = optimize,
});
const enr_module = enr_dep.module("zig-enr");
root_module.addImport("zig-enr", enr_module);
```
