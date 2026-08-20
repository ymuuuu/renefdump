# renefdump

Memory dumper for [renef](https://github.com/Ahmeth4n/renef), the Android ARM64 instrumentation toolkit. A port of [fridump3](https://github.com/rootbsd/fridump3), for targets that detect Frida but not renef.

Two files: `scripts/examples/renefdump.lua` (runs inside the app, no dependencies) and `renefdump.sh` (drives the whole job from the PC).

## Usage

```
./renefdump.sh com.example.app
```

Requires a rooted device (KernelSU works; `adb root` is not needed) with `renef_server`
running.

> **Launch the app, use it, and leave it on screen.** A freshly started app has an empty
> heap, and Android freezes backgrounded apps — a frozen process cannot run the agent.

```
./renefdump.sh -a <pid>               # attach by pid instead of package
./renefdump.sh -s <package>           # spawn first (rarely useful: empty heap)
./renefdump.sh -o <dir> <package>     # local output parent (default: ./dumps)
./renefdump.sh -r <path> <package>    # path to the renef client binary
./renefdump.sh -k <package>           # keep the dump on the device
```

Or from inside a renef REPL — the script picks its own output directory and prints the
commands to retrieve the files:

```
renef> l scripts/examples/renefdump.lua
```

## Output

`dumps/<package>-<date>/`, one file per memory range:

```
renefdump-12847-20260818-144407_7f8a2c0000-7f8a2e0000_rw-p_heap.data
renefdump-12847-20260818-144407_7f9012a000-7f9012c000_rw-p_libart.so.data
renefdump-12847-20260818-144407_maps.txt
renefdump-12847-20260818-144407_DONE
```

The filename identifies which mapping a hit came from. Ranges above `SPLIT_MB` become
`.part0`, `.part1`, … which `cat` back together in order. `DONE` holds
`<ranges> <bytes> <failed>` and is written only on completion — the wrapper waits for it
before pulling, because the renef client returning does not mean the dump finished.

```
strings -n 8 dumps/com.example.app-*/*.data | sort -u > strings.txt
```


## Configuration

Edit `M.config` at the top of `scripts/examples/renefdump.lua` — renef's `l` command passes
no arguments.

| Key | Default | Meaning |
|---|---|---|
| `PERMS_FILTER` | `"rw"` | `"rw"` = writable ranges only, `"r"` = every readable range |
| `SKIP_FILE_BACKED` | `false` | `true` limits the dump to anon/heap/stack |
| `SKIP_EMPTY` | `true` | Skip ranges with `Rss: 0` |
| `MAX_TOTAL_MB` | `4096` | Abort if the selection is larger |
| `SPLIT_MB` | `64` | Split above this; clamped to 64 — `File.write` rejects calls over 100 MB |
| `VERBOSE` | `false` | Log every range |

**The script never runs a shell.** No `os.execute`, no `io.popen` — exec from an app process
can be blocked by SELinux, and Lua has no `mkdir` binding to fall back on.

## Testing

```
lua tests/test_renefdump.lua      # 158 unit tests
sh -n renefdump.sh
```

Tests cover the maps/smaps parsers, range filter, filename sanitization, split arithmetic,
output-directory selection, guards, and the dump loop — the last via a fake `File.write`
that records its arguments and writes real bytes from a synthetic source, so it runs on a
host without renef.
