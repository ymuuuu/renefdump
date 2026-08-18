# renefdump

Memory dumper for [renef](https://github.com/Ahmeth4n/renef), the Android ARM64
instrumentation toolkit. A port of [fridump3](https://github.com/rootbsd/fridump3) to
renef's Lua agent, for targets that detect Frida but not renef.

The device-side dumper is a single file with no dependencies,
`scripts/examples/renefdump.lua`; the PC-side wrapper `renefdump.sh` runs the whole job end
to end.

## Quick start (wrapper)

The normal way to use this is the wrapper, which spawns the app, runs the dump inside it,
pulls the result, and cleans up. The dump lands in the app's own private directory on the
device and is retrieved through `adb shell su`, so the device must be rooted (KernelSU
works; `adb root` is not required):

```
./renefdump.sh com.example.app
```

That produces `dumps/renefdump-<pid>-<timestamp>/` locally:

```
dumps/renefdump-12847-20260818-143022/
├── renefdump-12847-20260818-143022_7f8a2c0000-7f8a2e0000_rw-p_heap.data
├── renefdump-12847-20260818-143022_7f9012a000-7f9012c000_rw-p_libart.so.data
├── ...
└── renefdump-12847-20260818-143022_maps.txt
```

The `renefdump-<pid>-<ts>_` prefix is what lets the wrapper and the operator pick a run's
files out of the app's cache directory, which also holds the app's own files.

Other invocations:

```
./renefdump.sh -a <pid>               # attach to a running pid instead of spawning
./renefdump.sh -o <dir> <package>     # local output parent (default: ./dumps)
./renefdump.sh -r <path> <package>    # path to the renef client binary
./renefdump.sh -k <package>           # keep the dump on the device (skip cleanup)
```

The wrapper resolves the renef client from `-r`, `$RENEF_BIN`, `./build/renef`,
`../renef/build/renef`, or `renef` on PATH; verifies exactly one device is connected;
verifies `adb shell su -c id` reports uid=0 (root is needed to read the dump back out of
the app's private directory); feeds `exit` to the client so it does not sit in the REPL;
and fails loudly if the run produces no files on the device.

## Manual route (inside a renef REPL)

If you are already attached inside a renef client, load the script directly:

```
renef> l scripts/examples/renefdump.lua
```

There is no setup step: the script picks a writable directory inside the app's own storage
(`/data/data/<pkg>/cache` first) and writes the dump there. The script prints the three
commands to stage and pull the files through root:

```
  adb shell su -c "mkdir -p /data/local/tmp/renefdump-12847-20260818-143022 && cp /data/data/com.example.app/cache/renefdump-12847-20260818-143022_* /data/local/tmp/renefdump-12847-20260818-143022/ && chmod -R 777 /data/local/tmp/renefdump-12847-20260818-143022"
  adb pull /data/local/tmp/renefdump-12847-20260818-143022 ./dump
  adb shell su -c "rm -rf /data/local/tmp/renefdump-12847-20260818-143022 /data/data/com.example.app/cache/renefdump-12847-20260818-143022_*"
```

## Where the code runs

The `.lua` script is never copied to the device. The renef client on the PC reads it,
hex-encodes it, and ships the source over a socket to the agent injected in the target app;
the Lua then executes inside the app process on the phone. That is why its `io.open` calls
resolve against the device filesystem and the dump lands on the device, even though the
source never leaves the PC as a file.

## Configuration

Edit the `M.config` table at the top of `scripts/examples/renefdump.lua` — renef's `l`
command passes no arguments.

| Key | Default | Meaning |
|---|---|---|
| `PERMS_FILTER` | `"rw"` | `"rw"` = writable ranges only (fridump default), `"r"` = every readable range |
| `SKIP_FILE_BACKED` | `false` | `true` limits the dump to anon/heap/stack |
| `SKIP_EMPTY` | `true` | Skip ranges with `Rss: 0` — never-touched reservations that can only read as zeros |
| `MAX_TOTAL_MB` | `4096` | Abort if the selection is larger |
| `SPLIT_MB` | `256` | Split a single range above this into `.partN` files |
| `CHUNK_KB` | `1024` | Read granularity |
| `HEARTBEAT_MB` | `32` | Emit a progress line every this many MB while dumping a range |
| `VERBOSE` | `false` | Log every range |

## Output

The dump is written inside the app's own storage — `/data/data/<pkg>/cache` when it is
writable, else `/data/user/0/<pkg>/cache`, `/data/data/<pkg>/files`, then `/data/data/<pkg>`.
One file per memory range, named `<prefix><start>-<end>_<perms>_<label>.data` where
`<prefix>` is `renefdump-<pid>-<timestamp>_`, plus a `<prefix>maps.txt` copy of
`/proc/self/maps`. A range above `SPLIT_MB` becomes `.part0`, `.part1`, … which `cat` back
together in order. Every file is exactly `end - start` bytes: unreadable chunks are
zero-filled, so offsets in the dump always match addresses in the maps — a gap shows up as a
run of zero bytes, not as missing data.

When the run completes, the script writes a `<prefix>DONE` file containing
`<ranges> <bytes_written> <bytes_zero_filled>`; the wrapper waits for that sentinel before
pulling, because the client returning does not mean the dump finished.

Unlike fridump3, the filename identifies the mapping a hit came from, and there are no
routine split boundaries cutting a string in half.

## Why the dump is smaller than the map total

The filter counts *mapped* bytes, not *resident* ones. On a real app, `rw-` ranges total
3359 MB mapped but only 205 MB (6.1%) is actually resident: 448 ranges totalling 1344 MB
have `Rss: 0` — address space ART reserved and never touched, physically unbacked, and only
readable as zeros (the worst offenders are two 1024 MB `[anon:dalvik-LinearAlloc]`
reservations). Dumping them is pure waste, so the script reads `/proc/self/smaps` and skips
zero-resident ranges (`SKIP_EMPTY`); the run reports them, e.g.
`[*] skipped 448 non-resident ranges (1344.4 MB of untouched reservations)`. Only ranges
that pass every other filter are counted, so the figure is comparable to the selection it
sits next to. If smaps is unreadable, the script falls back to plain maps and keeps
everything.

Run `strings` on the host after pulling — it is faster and better than anything the agent
could do on the device:

```
strings -n 8 dump/*.data | sort -u > strings.txt
```

## Why /proc/self/mem

renef's `Memory.read()` and `File.write()` dereference the address directly with no fault
guard, so one unreadable page kills the target process. `/proc/self/mem` returns a read
error instead. The agent runs inside the target, so `self` is the target.

## No shell, by design

The Lua script never calls `os.execute` or `io.popen`. Executing a shell from inside an app
process can be blocked by SELinux, and Lua has no `mkdir` binding to fall back on. The
script only ever writes files and calls `os.remove` (a stdlib call, not a shell); the
chosen output directory is the app's own, which already exists and is writable, so no
creation step is needed. Shell work — staging to `/data/local/tmp` and cleanup — happens on
the host with `adb shell su -c`, run by the operator or the wrapper.

## Why the app's own directory, and why root to retrieve

The dump cannot be written to `/data/local/tmp` in the first place. On an enforcing device
the agent runs as `untrusted_app`, whose SELinux domain has no write access to
`shell_data_file` (the label `/data/local/tmp` carries) — mode 0777 does not help, because
SELinux is checked after DAC and no `chmod` can change a process's domain. The app's own
data directories are labelled `app_data_file` and owned by the app, so they are always
writable with no setup. That is why the wrapper retrieves the files through `adb shell su`
(root): plain `adb pull` on an app-private path returns "Permission denied" no matter who
is attached.

## Testing

```
lua tests/test_renefdump.lua
```

Unit tests cover the maps parser, range filter, filename sanitization, split arithmetic,
on-device output-directory selection, space guards, the skipped-non-resident count, and the
dump loop (against a synthetic memory file, including zero-filled gaps). The wrapper is
shell — check it with `sh -n renefdump.sh`. Device verification is manual — see
`docs/manual-test.md`.
