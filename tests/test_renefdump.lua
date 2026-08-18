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

check("File resolved from _G at load", M.File == _G.File)

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

-- clamp_split_mb -----------------------------------------------------------

eq("clamp default", M.clamp_split_mb(nil), 64)
eq("clamp below ceiling", M.clamp_split_mb(32), 32)
eq("clamp at ceiling", M.clamp_split_mb(64), 64)
eq("clamp above ceiling", M.clamp_split_mb(256), 64)

-- dump_range (File.write) --------------------------------------------------

local tmp = os.getenv("TMPDIR") or "/tmp"
local test_dir = tmp .. "/renefdump-test-" .. tostring(os.time())
os.execute("mkdir -p '" .. test_dir .. "'")
local out_dir = test_dir .. "/out"
os.execute("mkdir -p '" .. out_dir .. "'")

-- A 3 MB synthetic memory image and a fake File that records its arguments
-- and writes real bytes from the image, standing in for renef's File.write on
-- a host that has no renef.
local image = string.rep(string.rep("ABCD", 256), 3072)  -- 3 MB known pattern

local function make_fake_file(img, base)
  local fake = { calls = {} }
  fake.write = function(path, addr, size)
    fake.calls[#fake.calls + 1] = { path = path, addr = addr, size = size }
    local rel = addr - base
    if rel < 0 or rel + size > #img then
      return false, "read out of range"
    end
    local f = io.open(path, "wb")
    if not f then return false, "failed to open file for writing" end
    f:write(img:sub(rel + 1, rel + size))
    f:close()
    return true
  end
  return fake
end

local fake = make_fake_file(image, 0)
M.File = fake

local dcfg = { SPLIT_MB = 1, VERBOSE = false }

-- A 2 KB range starting at offset 4096: one part, one file, exact name, and
-- File.write called once at the absolute address.
local small = { start_addr = 4096, end_addr = 4096 + 2048, size = 2048,
                perms = "rw-p", path = "[heap]" }
fake.calls = {}
local res = M.dump_range(small, out_dir, TP, dcfg)
eq("small range written", res.written, 2048)
check("small range not failed", not res.failed)
eq("small range one file", #res.files, 1)
eq("small file name", res.files[1],
   "renefdump-123-20260818-133552_1000-1800_rw-p_heap.data")
eq("small write address", fake.calls[1].addr, 4096)
eq("small write size", fake.calls[1].size, 2048)
eq("small write path", fake.calls[1].path, out_dir .. "/" .. res.files[1])

local f = assert(io.open(out_dir .. "/" .. res.files[1], "rb"))
local content = f:read("a")
f:close()
eq("small dump size on disk", #content, 2048)
eq("small dump content", content:sub(1, 4), "ABCD")

-- A 2.5 MB range above the 1 MB split ceiling: three parts, addresses equal to
-- r.start_addr + part.offset.
local big = { start_addr = 0, end_addr = 2621440, size = 2621440,
              perms = "rw-p", path = "" }
fake.calls = {}
local bres = M.dump_range(big, out_dir, TP, dcfg)
eq("big range written", bres.written, 2621440)
eq("big range parts", #bres.files, 3)
check("big part0 named", bres.files[1]:find("part0", 1, true) ~= nil, bres.files[1])
check("big part2 named", bres.files[3]:find("part2", 1, true) ~= nil, bres.files[3])

eq("part0 address is start", fake.calls[1].addr, 0)
eq("part1 address is start+1MB", fake.calls[2].addr, 1024 * 1024)
eq("part2 address is start+2MB", fake.calls[3].addr, 2 * 1024 * 1024)
eq("part2 size is remainder", fake.calls[3].size, 2621440 - 2 * 1024 * 1024)

local total_on_disk = 0
for _, name in ipairs(bres.files) do
  local pf = assert(io.open(out_dir .. "/" .. name, "rb"))
  total_on_disk = total_on_disk + #pf:read("a")
  pf:close()
end
eq("big parts sum on disk", total_on_disk, 2621440)

-- A false return from File.write marks the range failed and stops it: the
-- part that succeeded stays, the rest of the range is not attempted.
local flaky = make_fake_file(image, 0)
local orig_write = flaky.write
flaky.write = function(path, addr, size)
  if addr == 1024 * 1024 then
    return false, "simulated fault"
  end
  return orig_write(path, addr, size)
end
M.File = flaky
local fres = M.dump_range(big, out_dir, TP, dcfg)
check("failure marks range failed", fres.failed)
eq("failure stops the range", #fres.files, 1)
eq("failure written is first part", fres.written, 1024 * 1024)

-- With VERBOSE the failure message is printed.
local err_lines = {}
local saved_print = print
print = function(s) err_lines[#err_lines + 1] = tostring(s) end
M.dump_range(big, out_dir, TP, { SPLIT_MB = 1, VERBOSE = true })
print = saved_print
local joined = table.concat(err_lines, "\n")
check("verbose failure message printed", joined:find("simulated fault", 1, true) ~= nil, joined)

-- An out-of-image read (the app unmapped the range mid-dump) is also a
-- failure: failed, nothing written for that range.
local short = make_fake_file(string.rep("A", 4096), 0)
M.File = short
local oob = { start_addr = 0, end_addr = 8192, size = 8192,
              perms = "rw-p", path = "[heap]" }
local ores = M.dump_range(oob, out_dir, TP, dcfg)
check("out-of-range read marks failed", ores.failed)
eq("out-of-range written zero", ores.written, 0)
eq("out-of-range no files", #ores.files, 0)

-- dump_all ----------------------------------------------------------------

M.File = fake
local dstats = M.dump_all({ small, big }, out_dir, TP, dcfg)
eq("dump_all done", dstats.done, 2)
eq("dump_all written", dstats.written, 2048 + 2621440)
eq("dump_all failed", dstats.failed, 0)

-- done_line ---------------------------------------------------------------

eq("done line", M.done_line({ done = 47, written = 205000000, failed = 3 }),
   "47 205000000 3")

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
eq("SPLIT_MB default", M.config.SPLIT_MB, 64)
check("CHUNK_KB removed from config", M.config.CHUNK_KB == nil)
check("HEARTBEAT_MB removed from config", M.config.HEARTBEAT_MB == nil)
check("MEM_PATH removed", M.MEM_PATH == nil)
check("clamp_split_mb exposed", type(M.clamp_split_mb) == "function")

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
