# pepatch

Safe byte-level patcher for Windows PE executables (PE32 and PE32+). Pure
Python 3, no external dependencies. It does binary surgery on a file — it does
not need Windows to run.

## Safety rails

1. **Address → file offset** — `va:`, `rva:` and `off:` inputs are translated
   through the real section table and file alignment, so you patch the byte you
   mean to.
2. **Verify before write** — `patch --expect <hex>` refuses to write unless the
   current bytes match; guards against the wrong build, version or address.
3. **Backup** — the first write of a session copies the target to `<file>.bak`
   (`.bak1`, `.bak2`, … if one exists).
4. **Spare section for new code** — `addsection` appends a new executable
   section and fixes up section count, `SizeOfImage` and alignment so the
   loader accepts it. Somewhere to put a detour/trampoline target.
5. **Undoable log** — every change is appended to `<file>.patchlog.json` with
   before/after bytes. `undo` replays in reverse (and checks the current bytes
   still match what it wrote, unless `--force`). `restore` just copies the
   backup back.

## Usage

```
pepatch info      file.exe                      # headers + section table
pepatch resolve   file.exe va:0x401000          # -> RVA, VA, file offset, section
pepatch read      file.exe off:0x400 -n 16
pepatch patch     file.exe va:0x401000 "90 90" -e "74 1f"   # verify then write
pepatch addsection file.exe --name .inj --size 0x1000 [--writable] [--data <hex>|--data-file f]
pepatch trampoline file.exe [--data <hex>|--data-file f] [--name .tramp] [--writable]
pepatch log       file.exe
pepatch undo      file.exe [--all] [--force]
pepatch restore   file.exe                       # from backup
```

Addresses accept a `va:` / `rva:` / `off:` prefix; a bare number is treated as a
VA. Bytes are hex, spaces/commas optional (`"90 90"` or `9090`).

### Entry-point trampoline

`trampoline` carves a new executable section, writes `[your payload][jmp back
to the original entry point]` into it, and repoints `AddressOfEntryPoint` at
your payload. Your code runs first at startup, then falls through to the real
entry point:

```
pepatch trampoline app.exe --data-file hook.bin   # hook.bin = your shellcode
pepatch log  app.exe        # shows ADDSECTION + SETENTRY
pepatch undo app.exe --all  # restores the entry point AND removes the section
```

Rules for the payload:
* it runs with the loader's initial register/stack state — preserve whatever
  the real entry point needs (save/restore registers you clobber);
* **fall through** off the end of your bytes into the appended `jmp`; do not
  add your own `ret`/`jmp` — pepatch appends the jump back to the OEP for you;
* pass `--writable` if your payload writes into its own section.

The back-jump is a relative `E9 rel32`, computed from the planned section RVA,
so it is position-correct for both PE32 and PE32+.

### Typical flow

```
pepatch resolve app.exe va:0x4015A0            # confirm it lands where you think
pepatch read    app.exe va:0x4015A0 -n 2       # see the original bytes
pepatch patch   app.exe va:0x4015A0 "eb" -e "74"   # je -> jmp, only if it was 0x74
pepatch log     app.exe
pepatch undo    app.exe                        # roll it back
```

## Tests

`tests/run_tests.sh` compiles a tiny program with MinGW to both PE32
(`i686-w64-mingw32-gcc`) and PE32+ (`x86_64-w64-mingw32-gcc`), then for each:
patches a string, adds a section, installs an entry-point trampoline, runs the
result under Wine at every stage, and undoes everything checking the file is
byte-for-byte the original. 30/30 pass on this box. A compiler that is missing
makes that architecture skip rather than fail.
