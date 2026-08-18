# renefdump

Memory dumper for [renef](https://github.com/Ahmeth4n/renef), the Android ARM64
instrumentation toolkit. A port of [fridump3](https://github.com/rootbsd/fridump3) to
renef's Lua agent, for targets that detect Frida but not renef.

Single file, no dependencies: `scripts/examples/renefdump.lua`.

## Usage

Copy the script into a renef checkout (or run it from this repo's path), then:

```
adb forward tcp:1907 tcp:1907
./build/renef
renef> attach <pid>
renef> l scripts/examples/renefdump.lua
```

The dump is written on the device. The script prints the commands to pull it:

```
  adb pull /data/local/tmp/renefdump-12847-1755512400 ./dump
  adb shell rm -rf /data/local/tmp/renefdump-12847-1755512400
```

## Configuration

Edit the `M.config` table at the top of the script — renef's `l` command passes no arguments.

| Key | Default | Meaning |
|---|---|---|
| `OUT_BASE` | `/data/local/tmp` | Parent directory for the dump |
| `PERMS_FILTER` | `"rw"` | `"rw"` = writable ranges only (fridump default), `"r"` = every readable range |
| `SKIP_FILE_BACKED` | `false` | `true` limits the dump to anon/heap/stack |
| `MAX_TOTAL_MB` | `1024` | Abort if the selection is larger |
| `SPLIT_MB` | `256` | Split a single range above this into `.partN` files |
| `CHUNK_KB` | `1024` | Read granularity |
| `FREE_MARGIN` | `1.2` | Require free space >= total x this |
| `VERBOSE` | `false` | Log every range |

## Output

One file per memory range, named `<start>-<end>_<perms>_<label>.data`, plus a `maps.txt`
copy of `/proc/self/maps`. A range above `SPLIT_MB` becomes `.part0`, `.part1`, … which
`cat` back together in order.

Unlike fridump3, the filename identifies the mapping a hit came from, and there are no
routine split boundaries cutting a string in half.

Run `strings` on the host after pulling — it is faster and better than anything the agent
could do on the device:

```
strings -n 8 dump/*.data | sort -u > strings.txt
```

## Why /proc/self/mem

renef's `Memory.read()` and `File.write()` dereference the address directly with no fault
guard, so one unreadable page kills the target process. `/proc/self/mem` returns a read
error instead. The agent runs inside the target, so `self` is the target.

## Testing

```
lua tests/test_renefdump.lua
```

Unit tests cover the maps parser, range filter, filename sanitization, split arithmetic,
space guards, and the dump loop (against a synthetic memory file). Device verification is
manual — see `docs/manual-test.md`.
