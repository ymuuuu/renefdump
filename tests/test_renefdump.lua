-- Host-side unit tests for renefdump.lua
-- Run: lua tests/test_renefdump.lua

_G.RENEFDUMP_TEST = true

local ok, M = pcall(dofile, "scripts/examples/renefdump.lua")
if not ok then
  io.stderr:write("failed to load script: " .. tostring(M) .. "\n")
  os.exit(1)
end

local passed, failed = 0, 0

local function check(name, cond, detail)
  if cond then
    passed = passed + 1
  else
    failed = failed + 1
    io.write("FAIL: " .. name)
    if detail then io.write(" -- " .. tostring(detail)) end
    io.write("\n")
  end
end

local function eq(name, got, want)
  check(name, got == want, "got " .. tostring(got) .. ", want " .. tostring(want))
end

-- parse_maps_line ---------------------------------------------------------

local r = M.parse_maps_line("7f8a2c0000-7f8a2e0000 rw-p 00000000 00:00 0                          [heap]")
check("heap line parses", r ~= nil)
eq("heap start", r.start_addr, 0x7f8a2c0000)
eq("heap end", r.end_addr, 0x7f8a2e0000)
eq("heap size", r.size, 0x20000)
eq("heap perms", r.perms, "rw-p")
eq("heap path", r.path, "[heap]")

local anon = M.parse_maps_line("7fb0000000-7fb0001000 rw-p 00000000 00:00 0 ")
check("anon line parses", anon ~= nil)
eq("anon path empty", anon.path, "")
eq("anon size", anon.size, 0x1000)

local so = M.parse_maps_line("7f9012a000-7f9012c000 rw-p 00034000 fd:03 1234    /apex/com.android.art/lib64/libart.so")
check("so line parses", so ~= nil)
eq("so path", so.path, "/apex/com.android.art/lib64/libart.so")
eq("so perms", so.perms, "rw-p")

local spaced = M.parse_maps_line("7000000000-7000001000 rw-p 00000000 00:00 0    [anon:dalvik-main space (region space)]")
check("spaced path parses", spaced ~= nil)
eq("spaced path", spaced.path, "[anon:dalvik-main space (region space)]")

local del = M.parse_maps_line("7c00000000-7c00002000 r--p 00000000 fd:03 99    /data/app/base.apk (deleted)")
check("deleted line parses", del ~= nil)
eq("deleted path", del.path, "/data/app/base.apk (deleted)")

local big = M.parse_maps_line("7fffffff0000-7fffffff8000 rw-p 00000000 00:00 0    [stack]")
check("64-bit address parses", big ~= nil)
eq("64-bit start", big.start_addr, 0x7fffffff0000)

eq("zero size rejected", M.parse_maps_line("7f00000000-7f00000000 rw-p 00000000 00:00 0"), nil)
eq("garbage rejected", M.parse_maps_line("not a maps line at all"), nil)
eq("empty rejected", M.parse_maps_line(""), nil)

-- parse_maps --------------------------------------------------------------

local sample = table.concat({
  "7f8a2c0000-7f8a2e0000 rw-p 00000000 00:00 0                          [heap]",
  "garbage line",
  "7f9012a000-7f9012c000 r-xp 00000000 fd:03 1234    /system/lib64/libc.so",
  "",
}, "\n")
local list = M.parse_maps(sample)
eq("parse_maps count", #list, 2)
eq("parse_maps first path", list[1].path, "[heap]")
eq("parse_maps second path", list[2].path, "/system/lib64/libc.so")

-- parse_smaps -------------------------------------------------------------

local smaps_sample = table.concat({
  "76c0000000-7700000000 rw-p 00000000 00:00 0                              [anon:dalvik-LinearAlloc]",
  "  Size:            1048576 kB",
  "  KernelPageSize:        4 kB",
  "  MMUPageSize:           4 kB",
  "  Rss:                   0 kB",
  "  Pss:                   0 kB",
  "  Private_Dirty:         0 kB",
  "  VmFlags: rd wr mr mw me ac",
  "7700000000-7740000000 rw-p 00000000 00:00 0                              [anon:dalvik-LinearAlloc]",
  "  Size:            1048576 kB",
  "  Rss:                 512 kB",
  "  VmFlags: rd wr mr mw me ac",
  "7f8a2c0000-7f8a2e0000 rw-p 00000000 00:00 0                          [heap]",
}, "\n")
local srs = M.parse_smaps(smaps_sample)
eq("smaps count", #srs, 3)
eq("smaps block1 rss zero", srs[1].rss, 0)
eq("smaps block1 start", srs[1].start_addr, 0x76c0000000)
eq("smaps block1 size", srs[1].size, 0x40000000)
eq("smaps block1 perms", srs[1].perms, "rw-p")
eq("smaps block1 path", srs[1].path, "[anon:dalvik-LinearAlloc]")
eq("smaps block2 rss", srs[2].rss, 512 * 1024)
eq("smaps block3 rss default at EOF", srs[3].rss, 0)
eq("smaps block3 path", srs[3].path, "[heap]")
eq("smaps empty", #M.parse_smaps(""), 0)
eq("smaps non-string", #M.parse_smaps(nil), 0)

-- should_dump -------------------------------------------------------------

local cfg_rw = { PERMS_FILTER = "rw", SKIP_FILE_BACKED = false }
local cfg_r  = { PERMS_FILTER = "r",  SKIP_FILE_BACKED = false }
local cfg_anon = { PERMS_FILTER = "rw", SKIP_FILE_BACKED = true }

local function range(perms, path, size)
  return { start_addr = 0x1000, end_addr = 0x1000 + (size or 0x1000),
           size = size or 0x1000, perms = perms, path = path or "" }
end

check("rw anon kept", M.should_dump(range("rw-p", ""), cfg_rw))
check("rw heap kept", M.should_dump(range("rw-p", "[heap]"), cfg_rw))
check("rw stack kept", M.should_dump(range("rw-p", "[stack]"), cfg_rw))
check("rw file-backed kept by default",
      M.should_dump(range("rw-p", "/system/lib64/libc.so"), cfg_rw))

check("r-x skipped under rw filter", not M.should_dump(range("r-xp", "/system/lib64/libc.so"), cfg_rw))
check("r-x kept under r filter", M.should_dump(range("r-xp", "/system/lib64/libc.so"), cfg_r))

check("non-readable skipped", not M.should_dump(range("-w-p", ""), cfg_rw))
check("guard page skipped", not M.should_dump(range("---p", ""), cfg_rw))
check("guard page skipped under r filter", not M.should_dump(range("---p", ""), cfg_r))

check("/dev skipped", not M.should_dump(range("rw-p", "/dev/kgsl-3d0"), cfg_rw))
check("/dev skipped under r filter", not M.should_dump(range("rw-p", "/dev/binder"), cfg_r))
check("vvar skipped", not M.should_dump(range("r--p", "[vvar]"), cfg_r))
check("vvar_vclock skipped", not M.should_dump(range("r--p", "[vvar_vclock]"), cfg_r))

check("file-backed skipped when SKIP_FILE_BACKED",
      not M.should_dump(range("rw-p", "/data/app/base.apk"), cfg_anon))
check("anon kept when SKIP_FILE_BACKED",
      M.should_dump(range("rw-p", "[anon:libc_malloc]"), cfg_anon))

check("zero size skipped", not M.should_dump(range("rw-p", "", 0), cfg_rw))
check("nil range skipped", not M.should_dump(nil, cfg_rw))

-- SKIP_EMPTY: an explicit rss of 0 skips only when the flag is on; rss == nil
-- (residency unknown) is never treated as empty.
local cfg_skip_empty = { PERMS_FILTER = "rw", SKIP_FILE_BACKED = false, SKIP_EMPTY = true }
local cfg_keep_empty = { PERMS_FILTER = "rw", SKIP_FILE_BACKED = false, SKIP_EMPTY = false }

local rempty0 = range("rw-p", "[anon:dalvik-LinearAlloc]")
rempty0.rss = 0
check("rss 0 skipped when SKIP_EMPTY", not M.should_dump(rempty0, cfg_skip_empty))
check("rss 0 kept when SKIP_EMPTY off", M.should_dump(rempty0, cfg_keep_empty))

local rnil0 = range("rw-p", "[heap]")
rnil0.rss = nil
check("rss nil kept under SKIP_EMPTY", M.should_dump(rnil0, cfg_skip_empty))

local rsome0 = range("rw-p", "[heap]")
rsome0.rss = 4096
check("rss nonzero kept under SKIP_EMPTY", M.should_dump(rsome0, cfg_skip_empty))

-- sanitize_label ----------------------------------------------------------

eq("label anon", M.sanitize_label(""), "anon")
eq("label heap", M.sanitize_label("[heap]"), "heap")
eq("label stack", M.sanitize_label("[stack]"), "stack")
eq("label so basename", M.sanitize_label("/apex/com.android.art/lib64/libart.so"), "libart.so")
eq("label deleted stripped", M.sanitize_label("/data/app/base.apk (deleted)"), "base.apk")
eq("label spaces replaced", M.sanitize_label("[anon:dalvik-main space (region space)]"),
   "anon_dalvik-main_space__region_space")
eq("label keeps dots and dashes", M.sanitize_label("/system/lib64/libc++-hwasan.so"),
   "libc__-hwasan.so")

-- range_filename ----------------------------------------------------------

local TP = "renefdump-123-20260818-133552_"

local fr = { start_addr = 0x7f8a2c0000, end_addr = 0x7f8a2e0000,
             size = 0x20000, perms = "rw-p", path = "[heap]" }
eq("filename single part", M.range_filename(TP, fr, 0, 1),
   "renefdump-123-20260818-133552_7f8a2c0000-7f8a2e0000_rw-p_heap.data")
eq("filename part 0", M.range_filename(TP, fr, 0, 3),
   "renefdump-123-20260818-133552_7f8a2c0000-7f8a2e0000_rw-p_heap.part0.data")
eq("filename part 2", M.range_filename(TP, fr, 2, 3),
   "renefdump-123-20260818-133552_7f8a2c0000-7f8a2e0000_rw-p_heap.part2.data")

local fanon = { start_addr = 0x1000, end_addr = 0x2000, size = 0x1000,
                perms = "rw-p", path = "" }
eq("filename anon", M.range_filename(TP, fanon, 0, 1),
   "renefdump-123-20260818-133552_1000-2000_rw-p_anon.data")

-- run_prefix ---------------------------------------------------------------

eq("run prefix shape", M.run_prefix(123, "20260818-133552"),
   "renefdump-123-20260818-133552_")

-- split_parts -------------------------------------------------------------

local one = M.split_parts(1000, 4096)
eq("small range single part", #one, 1)
eq("small part offset", one[1].offset, 0)
eq("small part len", one[1].len, 1000)

local exact = M.split_parts(8192, 4096)
eq("exact multiple part count", #exact, 2)
eq("exact part2 offset", exact[2].offset, 4096)
eq("exact part2 len", exact[2].len, 4096)

local rem = M.split_parts(10000, 4096)
eq("remainder part count", #rem, 3)
eq("remainder last offset", rem[3].offset, 8192)
eq("remainder last len", rem[3].len, 1808)

local total = 0
for _, p in ipairs(rem) do total = total + p.len end
eq("parts sum to size", total, 10000)

eq("zero size gives no parts", #M.split_parts(0, 4096), 0)

-- fmt_size ----------------------------------------------------------------

eq("fmt bytes", M.fmt_size(512), "512 B")
eq("fmt kb", M.fmt_size(2048), "2.0 KB")
eq("fmt mb", M.fmt_size(191299584), "182.4 MB")
eq("fmt gb", M.fmt_size(4509715660), "4.2 GB")
eq("fmt zero", M.fmt_size(0), "0 B")

-- check_space -------------------------------------------------------------

local scfg = { MAX_TOTAL_MB = 1024 }

local ok1 = M.check_space(100 * 1024 * 1024, scfg)
check("space ok under cap", ok1)

local ok3, msg3 = M.check_space(2000 * 1024 * 1024, scfg)
check("cap rejected", not ok3)
check("cap message mentions MAX_TOTAL_MB", msg3 and msg3:find("MAX_TOTAL_MB"), msg3)

-- dump_range --------------------------------------------------------------

local tmp = os.getenv("TMPDIR") or "/tmp"
local test_dir = tmp .. "/renefdump-test-" .. tostring(os.time())
os.execute("mkdir -p '" .. test_dir .. "'")

-- Build a 3 MB synthetic "memory" file with a recognizable pattern.
local mem_path = test_dir .. "/fakemem"
local mf = assert(io.open(mem_path, "wb"))
local block = string.rep("ABCD", 256)          -- 1 KB
for _ = 1, 3 * 1024 do mf:write(block) end     -- 3 MB
mf:close()

local dcfg = { SPLIT_MB = 1, CHUNK_KB = 64 }
local out_dir = test_dir .. "/out"
os.execute("mkdir -p '" .. out_dir .. "'")

local mem = assert(io.open(mem_path, "rb"))

-- A 2 KB range starting at offset 4096.
local small = { start_addr = 4096, end_addr = 4096 + 2048, size = 2048,
                perms = "rw-p", path = "[heap]" }
local res = M.dump_range(mem, small, out_dir, TP, dcfg)
eq("small range written", res.written, 2048)
check("small range not failed", not res.failed)
eq("small range one file", #res.files, 1)

local f = assert(io.open(out_dir .. "/" .. res.files[1], "rb"))
local content = f:read("a")
f:close()
eq("small dump size on disk", #content, 2048)
eq("small dump content", content:sub(1, 4), "ABCD")

-- A 2.5 MB range that must split into three 1 MB parts.
local big = { start_addr = 0, end_addr = 2621440, size = 2621440,
              perms = "rw-p", path = "" }
local bres = M.dump_range(mem, big, out_dir, TP, dcfg)
eq("big range written", bres.written, 2621440)
eq("big range parts", #bres.files, 3)
check("big part0 named", bres.files[1]:find("part0", 1, true) ~= nil, bres.files[1])
check("big part2 named", bres.files[3]:find("part2", 1, true) ~= nil, bres.files[3])

local total_on_disk = 0
for _, name in ipairs(bres.files) do
  local pf = assert(io.open(out_dir .. "/" .. name, "rb"))
  total_on_disk = total_on_disk + #pf:read("a")
  pf:close()
end
eq("big parts sum on disk", total_on_disk, 2621440)

-- A range past the end of the file: unreadable chunks are zero-filled and
-- the range is not abandoned.
local past = { start_addr = 3 * 1024 * 1024, end_addr = 3 * 1024 * 1024 + 4096,
               size = 4096, perms = "rw-p", path = "[stack]" }
local pres = M.dump_range(mem, past, out_dir, TP, dcfg)
check("past-end marked partial", pres.partial)
check("past-end did not error", pres.failed == false)
check("past-end has gaps", pres.gaps > 0)
eq("past-end written zero", pres.written, 0)
local pf = assert(io.open(out_dir .. "/" .. pres.files[1], "rb"))
local pcontent = pf:read("a")
pf:close()
eq("past-end file full size", #pcontent, 4096)
check("past-end file all zero", pcontent == string.rep("\0", 4096))

-- A range straddling the end of the file: data before the gap is kept, the
-- rest is zero-filled, and the chunk loop keeps running.
local straddle = { start_addr = 3 * 1024 * 1024 - 2048,
                   end_addr = 3 * 1024 * 1024 - 2048 + 8192,
                   size = 8192, perms = "rw-p", path = "[anon:straddle]" }
local sres = M.dump_range(mem, straddle, out_dir, TP, dcfg)
check("straddle marked partial", sres.partial)
eq("straddle written", sres.written, 2048)
eq("straddle gaps", sres.gaps, 6144)
eq("straddle one file", #sres.files, 1)
local sf = assert(io.open(out_dir .. "/" .. sres.files[1], "rb"))
local scontent = sf:read("a")
sf:close()
eq("straddle file full size", #scontent, 8192)
eq("straddle keeps data", scontent:sub(1, 4), "ABCD")
eq("straddle zero tail", scontent:sub(2049, 2052), "\0\0\0\0")

-- Output-open failure: failed, nothing written, no files listed.
local bad = M.dump_range(mem, small, test_dir .. "/no-such-out", TP, dcfg)
check("open failure marks failed", bad.failed)
eq("open failure written zero", bad.written, 0)
eq("open failure no files", #bad.files, 0)

-- Heartbeat: mid-range progress lines keep the renef client relaying output.
local beat_lines = {}
local saved_log = M.log
M.log = function(msg) beat_lines[#beat_lines + 1] = msg end

local hb_cfg = { SPLIT_MB = 1, CHUNK_KB = 64, HEARTBEAT_MB = 1 }
local hb_range = { start_addr = 0, end_addr = 3 * 1024 * 1024, size = 3 * 1024 * 1024,
                   perms = "rw-p", path = "[anon:heartbeat]" }

-- A 2 KB range finishes before the first 1 MB beat: no heartbeat lines.
M.dump_range(mem, small, out_dir, TP, hb_cfg)
eq("no heartbeat for small range", #beat_lines, 0)

-- A 3 MB range with a 1 MB heartbeat fires exactly three lines.
M.dump_range(mem, hb_range, out_dir, TP, hb_cfg)
M.log = saved_log

eq("heartbeat count", #beat_lines, 3)
eq("heartbeat first line", beat_lines[1], "[*] 0-300000 rw-p ... 1.0 MB / 3.0 MB")
eq("heartbeat last line", beat_lines[3], "[*] 0-300000 rw-p ... 3.0 MB / 3.0 MB")

-- dump_all ----------------------------------------------------------------

local dstats = M.dump_all(mem, { small, past }, out_dir, TP, dcfg)
eq("dump_all done", dstats.done, 2)
eq("dump_all written", dstats.written, 2048)
eq("dump_all gaps", dstats.gaps, 4096)
eq("dump_all failed", dstats.failed, 0)
eq("dump_all partial", dstats.partial, 1)

-- done_line ---------------------------------------------------------------

eq("done line", M.done_line({ done = 47, written = 205000000, gaps = 1024 }),
   "47 205000000 1024")

-- write_maps_copy ----------------------------------------------------------

local wmc_dir = test_dir .. "/wmc"
os.execute("mkdir -p '" .. wmc_dir .. "'")
check("write_maps_copy ok", M.write_maps_copy(wmc_dir, TP, "fake maps text"))
local wmc_f = io.open(wmc_dir .. "/" .. TP .. "maps.txt", "r")
check("write_maps_copy writes prefixed maps.txt", wmc_f ~= nil)
if wmc_f then
  eq("write_maps_copy content", wmc_f:read("a"), "fake maps text")
  wmc_f:close()
end
check("write_maps_copy fails on missing dir",
      not M.write_maps_copy(wmc_dir .. "/nope", TP, "x"))

mem:close()
os.execute("rm -rf '" .. test_dir .. "'")

-- count_skipped_empty ------------------------------------------------------

local empty_cfg = { PERMS_FILTER = "rw", SKIP_FILE_BACKED = false, SKIP_EMPTY = true }
local mixed_empty = {
  range("---p", ""),                    -- non-readable, rss 0: NOT counted
  range("rw-p", "[heap]", 8192),        -- rw, rss 0: counted
  range("rw-p", "/dev/kgsl-3d0"),       -- /dev, rss 0: NOT counted
}
for _, r in ipairs(mixed_empty) do r.rss = 0 end
local ne, be = M.count_skipped_empty(mixed_empty, empty_cfg)
eq("skipped-empty counts only passable", ne, 1)
eq("skipped-empty bytes", be, 8192)
local ne_off = M.count_skipped_empty(mixed_empty,
  { PERMS_FILTER = "rw", SKIP_FILE_BACKED = false, SKIP_EMPTY = false })
eq("skipped-empty zero when SKIP_EMPTY off", ne_off, 0)

local nerr = M.count_skipped_empty({ range("rw-p", "[heap]", 4096) },
  { PERMS_FILTER = "rw", SKIP_FILE_BACKED = false, SKIP_EMPTY = true })
eq("skipped-empty ignores resident range", nerr, 0)

-- select_ranges ------------------------------------------------------------

local sel_cfg = { PERMS_FILTER = "rw", SKIP_FILE_BACKED = false }
local mixed = {
  range("rw-p", ""),
  range("r-xp", "/system/lib64/libc.so"),
  range("rw-p", "/dev/kgsl-3d0"),
  range("rw-p", "[heap]", 8192),
}
local ssel, stotal = M.select_ranges(mixed, sel_cfg)
eq("select ranges count", #ssel, 2)
eq("select ranges total", stotal, 0x1000 + 8192)
check("select keeps anon", ssel[1].path == "")
check("select keeps heap", ssel[2].path == "[heap]")

-- config and entry point --------------------------------------------------

check("config table exists", type(M.config) == "table")
check("OUT_DIR removed from config", M.config.OUT_DIR == nil)
check("resolve_out_dir removed", M.resolve_out_dir == nil)
check("check_out_dir removed", M.check_out_dir == nil)

-- read_package and app_dir -------------------------------------------------

local app_tmp = tmp .. "/renefdump-app-test-" .. tostring(os.time())
os.execute("mkdir -p '" .. app_tmp .. "'")

local cmdline_path = app_tmp .. "/cmdline"
local cmdline_f = assert(io.open(cmdline_path, "wb"))
cmdline_f:write("com.example.app\0")
cmdline_f:close()

local app_real = app_tmp .. "/real"
os.execute("mkdir -p '" .. app_real .. "/com.example.app'")
local app_missing = app_tmp .. "/missing"

local saved_cmdline = M.CMDLINE_PATH
local saved_candidates = M.OUT_CANDIDATES
M.CMDLINE_PATH = cmdline_path

eq("package from fake cmdline", M.read_package(), "com.example.app")

local sub_cmdline = app_tmp .. "/cmdline-sub"
local sub_f = assert(io.open(sub_cmdline, "wb"))
sub_f:write("com.example.app:remote\0")
sub_f:close()
M.CMDLINE_PATH = sub_cmdline
eq("package strips :subprocess", M.read_package(), "com.example.app")
M.CMDLINE_PATH = cmdline_path

M.OUT_CANDIDATES = { app_missing .. "/%s", app_real .. "/%s" }
eq("app_dir picks first writable candidate", M.app_dir(), app_real .. "/com.example.app")

M.OUT_CANDIDATES = { app_missing .. "/%s" }
eq("app_dir nil when no candidate writable", M.app_dir(), nil)

M.OUT_CANDIDATES = { app_real .. "/%s" }
check("app_dir leaves no probe behind",
      io.open(app_real .. "/com.example.app/.renefdump-probe", "r") == nil)

M.CMDLINE_PATH = saved_cmdline
M.OUT_CANDIDATES = saved_candidates

local nocmdline = app_tmp .. "/no-cmdline"
M.CMDLINE_PATH = nocmdline
eq("app_dir nil when cmdline unreadable", M.app_dir(), nil)
M.CMDLINE_PATH = saved_cmdline

os.execute("rm -rf '" .. app_tmp .. "'")

check("get_pid returns a number", type(M.get_pid()) == "number")
check("get_pid is positive", M.get_pid() > 0)

-- host_commands ------------------------------------------------------------

local hc = M.host_commands("/data/data/com.example.app/cache", "renefdump-123-20260818-133552_")
check("host commands stage via su",
      hc:find('adb shell su -c "mkdir -p /data/local/tmp/renefdump-123-20260818-133552', 1, true) ~= nil, hc)
check("host commands cp from app dir",
      hc:find('cp /data/data/com.example.app/cache/renefdump-123-20260818-133552_*', 1, true) ~= nil, hc)
check("host commands chmod staging dir",
      hc:find('chmod -R 777 /data/local/tmp/renefdump-123-20260818-133552"', 1, true) ~= nil, hc)
check("host commands pull from staging dir",
      hc:find("adb pull /data/local/tmp/renefdump-123-20260818-133552 ./dump", 1, true) ~= nil, hc)
check("host commands clean staging and app copy",
      hc:find('rm -rf /data/local/tmp/renefdump-123-20260818-133552 /data/data/com.example.app/cache/renefdump-123-20260818-133552_*', 1, true) ~= nil, hc)
check("host commands contain no bare adb pull of app dir",
      hc:find("adb pull /data/data/", 1, true) == nil, hc)
check("host commands are three lines", (hc:gsub("[^\n]", "")) == "\n\n")

check("main not run under test guard", _G.RENEFDUMP_RAN == nil)

-- summary -----------------------------------------------------------------

io.write(string.format("\n%d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
