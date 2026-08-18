-- renefdump - memory dumper for renef
-- Usage inside the renef client:
--   attach <pid>
--   l scripts/examples/renefdump.lua
--
-- Dumps writable memory ranges of the target process to the device, then
-- prints the adb commands to pull them to the host.

local M = {}

-- ===================== configuration =====================
-- renef's `l` command passes no arguments, so tune the dump here.

M.config = {
  OUT_BASE         = "/data/local/tmp", -- parent dir for the dump directory
  PERMS_FILTER     = "rw",              -- "rw" = writable only (fridump default), "r" = any readable
  SKIP_FILE_BACKED = false,             -- true = anon/heap/stack only, skips mapped .so/.dex/.apk
  MAX_TOTAL_MB     = 1024,              -- abort if the selection exceeds this
  SPLIT_MB         = 256,               -- split a single range above this into .partN files
  CHUNK_KB         = 1024,              -- read granularity, bounds peak Lua memory
  FREE_MARGIN      = 1.2,               -- require free space >= total * this
  VERBOSE          = false,             -- per-range logging
}

M.MAPS_PATH = "/proc/self/maps"
M.MEM_PATH  = "/proc/self/mem"

-- Color globals exist inside the renef agent but not on a bare host interpreter.
local CYAN   = _G.CYAN or "\27[36m"
local GREEN  = _G.GREEN or "\27[32m"
local RED    = _G.RED or "\27[31m"
local YELLOW = _G.YELLOW or "\27[33m"
local RESET  = _G.RESET or "\27[0m"
-- =========================================================

-- Parse one /proc/self/maps line into a range record.
-- Returns nil for unparseable lines and zero-size ranges.
function M.parse_maps_line(line)
  if type(line) ~= "string" then return nil end

  local s, e, perms, rest = line:match("^(%x+)%-(%x+)%s+(%S+)%s+(.*)$")
  if not s then return nil end

  -- rest is: offset dev inode [path]
  local path = rest:match("^%x+%s+%S+%s+%d+%s*(.*)$")
  if not path then return nil end
  path = path:gsub("%s+$", "")

  local start_addr = tonumber(s, 16)
  local end_addr = tonumber(e, 16)
  if not start_addr or not end_addr then return nil end

  local size = end_addr - start_addr
  if size <= 0 then return nil end

  return {
    start_addr = start_addr,
    end_addr = end_addr,
    size = size,
    perms = perms,
    path = path,
  }
end

-- Parse a full maps file into an array of range records.
function M.parse_maps(text)
  local ranges = {}
  if type(text) ~= "string" then return ranges end
  for line in text:gmatch("[^\n]+") do
    local r = M.parse_maps_line(line)
    if r then ranges[#ranges + 1] = r end
  end
  return ranges
end

-- Ranges that are never safe or never useful to dump, whatever the config.
local function always_skip(path)
  if path:sub(1, 5) == "/dev/" then return true end  -- device memory: read can block
  if path:sub(1, 6) == "[vvar]" then return true end  -- kernel page, unreadable via /proc/*/mem
  if path:sub(1, 6) == "[vvar_" then return true end  -- [vvar_vclock] and friends
  return false
end

-- Decide whether a range should be dumped under the given config.
function M.should_dump(r, cfg)
  if type(r) ~= "table" then return false end
  if not r.size or r.size <= 0 then return false end
  if type(r.perms) ~= "string" or #r.perms < 2 then return false end

  if r.perms:sub(1, 1) ~= "r" then return false end
  if cfg.PERMS_FILTER == "rw" and r.perms:sub(2, 2) ~= "w" then return false end

  local path = r.path or ""
  if always_skip(path) then return false end
  if cfg.SKIP_FILE_BACKED and path:sub(1, 1) == "/" then return false end

  return true
end

-- Turn a maps path into a filesystem-safe label.
function M.sanitize_label(path)
  path = path or ""
  path = path:gsub("%s*%(deleted%)%s*$", "")
  if path == "" then return "anon" end

  local base = path:match("([^/]+)$") or path
  base = base:gsub("[^%w%._%-]", "_")
  base = base:gsub("^_+", ""):gsub("_+$", "")
  if base == "" then return "anon" end
  return base
end

-- Build the output filename for one range (or one part of a split range).
-- part_index is 0-based. No suffix is added when part_count == 1.
function M.range_filename(r, part_index, part_count)
  local name = string.format("%x-%x_%s_%s",
    r.start_addr, r.end_addr, r.perms, M.sanitize_label(r.path))
  if part_count and part_count > 1 then
    name = name .. string.format(".part%d", part_index)
  end
  return name .. ".data"
end

-- Split a range size into contiguous parts no larger than split_bytes.
function M.split_parts(size, split_bytes)
  local parts = {}
  if not size or size <= 0 then return parts end
  if not split_bytes or split_bytes <= 0 then
    return { { offset = 0, len = size } }
  end

  local offset = 0
  while offset < size do
    local len = size - offset
    if len > split_bytes then len = split_bytes end
    parts[#parts + 1] = { offset = offset, len = len }
    offset = offset + len
  end
  return parts
end

-- Human-readable byte count.
function M.fmt_size(bytes)
  bytes = bytes or 0
  if bytes < 1024 then
    return string.format("%d B", bytes)
  elseif bytes < 1024 * 1024 then
    return string.format("%.1f KB", bytes / 1024)
  elseif bytes < 1024 * 1024 * 1024 then
    return string.format("%.1f MB", bytes / (1024 * 1024))
  else
    return string.format("%.1f GB", bytes / (1024 * 1024 * 1024))
  end
end

-- Extract available kilobytes from `df -k <dir>` output.
-- Columns from the right are: Mounted-on, Use%, Available.
function M.parse_df_avail(text)
  if type(text) ~= "string" then return nil end

  for line in text:gmatch("[^\n]+") do
    if not line:find("1K%-blocks") and not line:find("Filesystem") then
      local fields = {}
      for field in line:gmatch("%S+") do fields[#fields + 1] = field end
      if #fields >= 5 then
        local avail = tonumber(fields[#fields - 2])
        if avail then return avail end
      end
    end
  end
  return nil
end

-- Pre-flight guard. avail_kb may be nil when df is unavailable.
function M.check_space(total_bytes, avail_kb, cfg)
  local cap = (cfg.MAX_TOTAL_MB or 1024) * 1024 * 1024
  if total_bytes > cap then
    return false, string.format(
      "selection is %s, above the MAX_TOTAL_MB cap of %d MB - raise MAX_TOTAL_MB or narrow the filter",
      M.fmt_size(total_bytes), cfg.MAX_TOTAL_MB or 1024)
  end

  if not avail_kb then
    return true, "free space unknown, skipping check"
  end

  local need = total_bytes * (cfg.FREE_MARGIN or 1.2)
  local avail = avail_kb * 1024
  if avail < need then
    return false, string.format(
      "not enough free space: need %s, free %s",
      M.fmt_size(need), M.fmt_size(avail))
  end

  return true, string.format("free %s, need %s", M.fmt_size(avail), M.fmt_size(need))
end

-- Copy one range from `mem` (an open /proc/<pid>/mem style handle) to disk.
--
-- The handle is re-seeked before every chunk: a failed read on /proc/*/mem
-- leaves the file position undefined, and the target keeps running, so a
-- mapping can disappear mid-dump. Never dereference the address directly -
-- renef's Memory.read and File.write do, and a bad page kills the target.
function M.dump_range(mem, r, out_dir, cfg)
  local result = { written = 0, failed = false, partial = false, files = {} }

  local split_bytes = (cfg.SPLIT_MB or 256) * 1024 * 1024
  local chunk = (cfg.CHUNK_KB or 1024) * 1024
  local parts = M.split_parts(r.size, split_bytes)

  for i, part in ipairs(parts) do
    local name = M.range_filename(r, i - 1, #parts)
    local out, oerr = io.open(out_dir .. "/" .. name, "wb")
    if not out then
      result.failed = true
      return result
    end

    local part_written = 0
    local offset = 0
    while offset < part.len do
      local want = part.len - offset
      if want > chunk then want = chunk end

      local pos = r.start_addr + part.offset + offset
      local sought = mem:seek("set", pos)
      if not sought then
        result.partial = true
        break
      end

      local ok, data = pcall(mem.read, mem, want)
      if not ok or not data or #data == 0 then
        result.partial = true
        break
      end

      out:write(data)
      part_written = part_written + #data
      offset = offset + #data

      if #data < want then
        result.partial = true
        break
      end
    end

    out:close()
    result.written = result.written + part_written
    result.files[#result.files + 1] = name

    if result.partial then break end
  end

  return result
end

-- Target pid. renef exposes OS.getpid(); fall back to /proc/self/stat on a
-- bare interpreter so the host tests can run.
function M.get_pid()
  if _G.OS and _G.OS.getpid then
    local ok, pid = pcall(_G.OS.getpid)
    if ok and type(pid) == "number" and pid > 0 then return pid end
  end

  local f = io.open("/proc/self/stat", "r")
  if f then
    local line = f:read("l")
    f:close()
    local pid = tonumber(line and line:match("^(%d+)"))
    if pid then return pid end
  end

  return 0
end

-- The commands the operator runs on the host once the dump finishes.
function M.host_commands(out_dir)
  return string.format(
    "  adb pull %s ./dump\n  adb shell rm -rf %s",
    out_dir, out_dir)
end

local function read_file(path)
  local f = io.open(path, "r")
  if not f then return nil end
  local content = f:read("a")
  f:close()
  return content
end

local function free_kb(dir)
  local p = io.popen("df -k '" .. dir .. "' 2>/dev/null")
  if not p then return nil end
  local out = p:read("a")
  p:close()
  return M.parse_df_avail(out)
end

function M.main()
  local cfg = M.config
  local pid = M.get_pid()

  print(CYAN .. "[*] renefdump - pid " .. tostring(pid) .. RESET)

  local maps_text = read_file(M.MAPS_PATH)
  if not maps_text then
    print(RED .. "[-] cannot read " .. M.MAPS_PATH .. RESET)
    return
  end

  local all = M.parse_maps(maps_text)
  print(string.format("[*] parsed %s: %d ranges", M.MAPS_PATH, #all))

  local selected, total = {}, 0
  for _, r in ipairs(all) do
    if M.should_dump(r, cfg) then
      selected[#selected + 1] = r
      total = total + r.size
    end
  end

  if #selected == 0 then
    print(YELLOW .. "[-] no ranges matched the filter" .. RESET)
    return
  end
  print(string.format("[*] selected %d ranges, %s", #selected, M.fmt_size(total)))

  local ok, msg = M.check_space(total, free_kb(cfg.OUT_BASE), cfg)
  print("[*] " .. msg)
  if not ok then
    print(RED .. "[-] aborting before writing anything" .. RESET)
    return
  end

  local out_dir = string.format("%s/renefdump-%d-%d", cfg.OUT_BASE, pid, os.time())
  os.execute("mkdir -p '" .. out_dir .. "'")

  local probe = io.open(out_dir .. "/maps.txt", "w")
  if not probe then
    print(RED .. "[-] cannot write to " .. out_dir .. RESET)
    return
  end
  probe:write(maps_text)
  probe:close()

  local mem, merr = io.open(M.MEM_PATH, "rb")
  if not mem then
    print(RED .. "[-] cannot open " .. M.MEM_PATH .. ": " .. tostring(merr) .. RESET)
    return
  end

  print("[*] output: " .. out_dir)

  local written, failed, partial, done = 0, 0, 0, 0
  for _, r in ipairs(selected) do
    local res = M.dump_range(mem, r, out_dir, cfg)
    written = written + res.written
    if res.failed then failed = failed + 1 end
    if res.partial then partial = partial + 1 end
    done = done + 1

    if cfg.VERBOSE then
      print(string.format("    %x-%x %s %s %s",
        r.start_addr, r.end_addr, r.perms, M.fmt_size(res.written), r.path))
    elseif done % 10 == 0 or done == #selected then
      print(string.format("    %d/%d ranges, %s", done, #selected, M.fmt_size(written)))
    end
  end
  mem:close()

  print(string.format("%s[+] %d/%d ranges, %s written, %d failed, %d partial%s",
    GREEN, done, #selected, M.fmt_size(written), failed, partial, RESET))
  print("")
  print(CYAN .. "[*] Run on host:" .. RESET)
  print(M.host_commands(out_dir))
end

if not _G.RENEFDUMP_TEST then
  _G.RENEFDUMP_RAN = true
  M.main()
end

return M
