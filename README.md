# SigHunter

Fast and simple signature scanning tool. It utilizes [Rayon](https://github.com/rayon-rs/rayon) for parallelism and [Memflow](https://github.com/memflow/memflow) for memory access.

## Usage

```bash
sighunter.exe --process-name PROCESS.EXE --signature SIGNATURE [OPTIONS]
```

### Required arguments

- `-p, --process-name <PROCESS.EXE>` – Process to iterate over  
- `-s, --signature <SIGNATURE>` – Signature pattern to find

### Optional arguments

- `-m, --module-name <MODULE>` – Scan only a specific module. If omitted, all modules are scanned.
- `-i, --ignore-os` – Ignore OS/system modules (has no effect if `--module-name` is set).

---

### Examples

Scan all modules in a process:

```bash
sighunter.exe -p game.exe -s "48 8B ?? ?? ??"
```

Scan a specific module:

```bash
sighunter.exe  -p game.exe -m engine.dll -s "48 8B ?? ?? ??"
```

Ignore system modules:

```bash
sighunter.exe -p game.exe -s "48 8B ?? ?? ??" --ignore-os
```
