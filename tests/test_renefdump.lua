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

local fr = { start_addr = 0x7f8a2c0000, end_addr = 0x7f8a2e0000,
             size = 0x20000, perms = "rw-p", path = "[heap]" }
eq("filename single part", M.range_filename(fr, 0, 1),
   "7f8a2c0000-7f8a2e0000_rw-p_heap.data")
eq("filename part 0", M.range_filename(fr, 0, 3),
   "7f8a2c0000-7f8a2e0000_rw-p_heap.part0.data")
eq("filename part 2", M.range_filename(fr, 2, 3),
   "7f8a2c0000-7f8a2e0000_rw-p_heap.part2.data")

local fanon = { start_addr = 0x1000, end_addr = 0x2000, size = 0x1000,
                perms = "rw-p", path = "" }
eq("filename anon", M.range_filename(fanon, 0, 1), "1000-2000_rw-p_anon.data")

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
local res = M.dump_range(mem, small, out_dir, dcfg)
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
local bres = M.dump_range(mem, big, out_dir, dcfg)
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
local pres = M.dump_range(mem, past, out_dir, dcfg)
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
local sres = M.dump_range(mem, straddle, out_dir, dcfg)
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
local bad = M.dump_range(mem, small, test_dir .. "/no-such-out", dcfg)
check("open failure marks failed", bad.failed)
eq("open failure written zero", bad.written, 0)
eq("open failure no files", #bad.files, 0)

-- dump_all ----------------------------------------------------------------

local dstats = M.dump_all(mem, { small, past }, out_dir, dcfg)
eq("dump_all done", dstats.done, 2)
eq("dump_all written", dstats.written, 2048)
eq("dump_all gaps", dstats.gaps, 4096)
eq("dump_all failed", dstats.failed, 0)
eq("dump_all partial", dstats.partial, 1)

-- write_maps_copy ----------------------------------------------------------

local wmc_dir = test_dir .. "/wmc"
os.execute("mkdir -p '" .. wmc_dir .. "'")
check("write_maps_copy ok", M.write_maps_copy(wmc_dir, "fake maps text"))
local wmc_f = io.open(wmc_dir .. "/maps.txt", "r")
check("write_maps_copy writes maps.txt", wmc_f ~= nil)
if wmc_f then
  eq("write_maps_copy content", wmc_f:read("a"), "fake maps text")
  wmc_f:close()
end
check("write_maps_copy fails on missing dir",
      not M.write_maps_copy(wmc_dir .. "/nope", "x"))

mem:close()
os.execute("rm -rf '" .. test_dir .. "'")

-- check_out_dir ------------------------------------------------------------

local cd_dir = tmp .. "/renefdump-out-test-" .. tostring(os.time())
os.execute("mkdir -p '" .. cd_dir .. "'")

local okcd, msgcd = M.check_out_dir(cd_dir)
check("check_out_dir ok on writable dir", okcd)
check("check_out_dir ok message has dir", msgcd and msgcd:find(cd_dir, 1, true) ~= nil, msgcd)
local probe = io.open(cd_dir .. "/.renefdump-probe", "r")
check("check_out_dir removes probe", probe == nil)
if probe then probe:close() end

local missing = cd_dir .. "/does-not-exist"
local okmiss, msgmiss = M.check_out_dir(missing)
check("check_out_dir fails on missing dir", not okmiss)
check("check_out_dir message has adb root",
      msgmiss and msgmiss:find("adb root", 1, true) ~= nil, msgmiss)
check("check_out_dir message has mkdir cmd",
      msgmiss and msgmiss:find("adb shell mkdir -p " .. missing, 1, true) ~= nil, msgmiss)
check("check_out_dir message has chmod cmd",
      msgmiss and msgmiss:find("adb shell chmod 777 " .. missing, 1, true) ~= nil, msgmiss)

os.execute("rm -rf '" .. cd_dir .. "'")

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

-- resolve_out_dir ----------------------------------------------------------

local saved_out_dir = _G.RENEFDUMP_OUT_DIR
local ro_cfg = { OUT_DIR = "/data/local/tmp/renefdump" }

_G.RENEFDUMP_OUT_DIR = nil
eq("resolve out dir default", M.resolve_out_dir(ro_cfg), "/data/local/tmp/renefdump")
_G.RENEFDUMP_OUT_DIR = "/data/local/tmp/renefdump/com.example.app-20260818-143022"
eq("resolve out dir override", M.resolve_out_dir(ro_cfg),
   "/data/local/tmp/renefdump/com.example.app-20260818-143022")
_G.RENEFDUMP_OUT_DIR = ""
eq("resolve out dir empty falls back", M.resolve_out_dir(ro_cfg), "/data/local/tmp/renefdump")
_G.RENEFDUMP_OUT_DIR = saved_out_dir

check("get_pid returns a number", type(M.get_pid()) == "number")
check("get_pid is positive", M.get_pid() > 0)

local hc = M.host_commands("/data/local/tmp/renefdump/run")
check("host commands mention adb pull",
      hc:find("adb pull /data/local/tmp/renefdump/run ./dump", 1, true) ~= nil, hc)
check("host commands mention rm -rf",
      hc:find("adb shell rm -rf /data/local/tmp/renefdump/run", 1, true) ~= nil, hc)
check("host commands contain no tar", hc:find("tar", 1, true) == nil, hc)
check("host commands contain no exec-out", hc:find("exec-out", 1, true) == nil, hc)
check("host commands are two lines", (hc:gsub("[^\n]", "")) == "\n")

check("main not run under test guard", _G.RENEFDUMP_RAN == nil)

-- summary -----------------------------------------------------------------

io.write(string.format("\n%d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
