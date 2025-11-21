-- auto_twitch_category.lua

--[[
======================================================================
 Auto Twitch Category Switcher (Windows only) – What this script does
======================================================================

Short version:
- Watches your running Windows processes (exe + last folder).
- Tries to match them to rules in "game_mappings.lua" next to this file.
- If no rule matches, it asks Discord's "detectable applications" API
  for help and auto-creates rules from that.
- Picks a Twitch category + default title + tags from the selected rule.
- Optionally pulls the live title/tags back from Twitch and writes them
  into the mapping file (so your rules learn over time).
- Falls back to a configurable "Just Chatting" rule if nothing matches.
- Refreshes your Twitch OAuth token automatically via refresh_token.
- Can run once on demand or on a timer (auto polling).

Highlevel flow for every tick:
1) (Re)load "game_mappings.lua" when it changed on disk.
2) Scan running processes via WinAPI (Toolhelp32 + QueryFullProcessImageNameW).
3) Drop ignored processes (system stuff, browsers, tools you don't care about).
4) Try to match remaining processes against cfg.rules in game_mappings.lua.
5) If nothing hits:
   a) Pull Discord "detectable applications" (cached with a TTL).
   b) Try to match processes against Discord app entries.
   c) Merge/add a new rule into cfg.rules and save the file.
6) If there is still no match:
   a) Add the remaining processes to cfg.unknown.
   b) Use the Just Chatting rule from mappings.just_chatting as a fallback.
7) Resolve the Twitch game_id using /helix/games and /helix/search/categories.
8) PATCH /helix/channels with the new game_id, title and tags.
9) If backporting is enabled and the cooldown is over, fetch the current
   Twitch title/tags and write them back into the matching rule.
]]



--[[
======================================================================
 Changelog
======================================================================

2025.11.18    M.Stahl    - Initial version
2025.11.19    M.Stahl    - Added fuzzy search + unicode-safe Twitch name handling
2025.11.20    M.Stahl    - Exposed title pattern options in OBS UI
                         - Added tooltips and this header documentation
						 
======================================================================
]]



--[[
======================================================================
 Twitch Tokens & IDs – Quick Setup Guide
======================================================================

The script needs these Twitch values (you paste them into the OBS script
settings panel):

  1) Client ID
  2) Client Secret
  3) Access Token        → field: "Twitch OAuth Token"
  4) Refresh Token       → field: "Twitch Refresh Token"
  5) Broadcaster ID      → your numeric Twitch user ID

---------------------------------------------------------------
 1. Create (or reuse) a Twitch Application
---------------------------------------------------------------
• Open https://dev.twitch.tv/console/apps
• Create an app:
     Name: anything
     Redirect URL: http://localhost
     Category: Application Integration
• Copy: Client ID + Client Secret

---------------------------------------------------------------
 2. Get the Authorization Code
---------------------------------------------------------------
Open this URL in your browser (single line, replace YOUR_CLIENT_ID):

https://id.twitch.tv/oauth2/authorize
  ?client_id=YOUR_CLIENT_ID
  &redirect_uri=http://localhost
  &response_type=code
  &scope=channel:manage:broadcast

• Log in → Authorize
• You will be redirected to
     http://localhost/?code=XXXXX
• Copy everything after "code=" → this is your Authorization Code

---------------------------------------------------------------
 3. Exchange the Authorization Code for Tokens
---------------------------------------------------------------
Open the browser dev tools (F12 → Console) and run:

fetch("https://id.twitch.tv/oauth2/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    client_id:     "YOUR_CLIENT_ID",
    client_secret: "YOUR_CLIENT_SECRET",
    code:          "YOUR_AUTH_CODE",
    grant_type:    "authorization_code",
    redirect_uri:  "http://localhost"
  })
})
 .then(r => r.json())
 .then(console.log);

The JSON response contains:
   • access_token  → paste into "Twitch OAuth Token"
   • refresh_token → paste into "Twitch Refresh Token"

---------------------------------------------------------------
 4. Get Your Broadcaster ID
---------------------------------------------------------------
Use any "Twitch username → user ID" website
OR call this (with a valid token) in a REST client / browser extension:

  GET https://api.twitch.tv/helix/users?login=YOUR_NAME

(use a converter site if you want to keep it simple)

---------------------------------------------------------------
 5. Fill in the OBS Script Fields
---------------------------------------------------------------
In the OBS script settings for this Lua file:

• Twitch Client ID       = your Client ID
• Twitch Client Secret   = your Client Secret
• Twitch OAuth Token     = access_token
• Twitch Refresh Token   = refresh_token
• Twitch Broadcaster ID  = your numeric ID

Optional but recommended:
• Enable "Auto Polling"
• Set a safe polling interval (≥ 2000 ms, e.g. 5000 ms)

---------------------------------------------------------------
 6. Token Refresh Handling
---------------------------------------------------------------
When the access token expires the script:

 • uses the Refresh Token to grab a new access_token
 • updates its internal state
 • keeps working without you touching anything

You only need to repeat the whole setup if:
 • you reset the Client Secret
 • you delete / recreate the Twitch application
 • Twitch invalidates your refresh token for some reason

======================================================================
]]--




-----------------------------------------------------
-- OBS / FFI SETUP
-----------------------------------------------------
local obs = obslua
local ffi = require("ffi")

-----------------------------------------------------
-- SMALL BUILT-IN JSON ENCODER/DECODER (with pre-defined utf encode)
-----------------------------------------------------

local function utf8_from_codepoint(cp)
    -- encode a single Unicode codepoint to UTF-8 (we had issues with unicode characters coming from discord api)
    if cp <= 0x7F then
        return string.char(cp)
    elseif cp <= 0x7FF then
        local b1 = 0xC0 + math.floor(cp / 0x40)
        local b2 = 0x80 + (cp % 0x40)
        return string.char(b1, b2)
    elseif cp <= 0xFFFF then
        local b1 = 0xE0 + math.floor(cp / 0x1000)
        local b2 = 0x80 + (math.floor(cp / 0x40) % 0x40)
        local b3 = 0x80 + (cp % 0x40)
        return string.char(b1, b2, b3)
    elseif cp <= 0x10FFFF then
        local b1 = 0xF0 + math.floor(cp / 0x40000)
        local b2 = 0x80 + (math.floor(cp / 0x1000) % 0x40)
        local b3 = 0x80 + (math.floor(cp / 0x40) % 0x40)
        local b4 = 0x80 + (cp % 0x40)
        return string.char(b1, b2, b3, b4)
    end
    return "?"
end



local json_encode, json_decode

do
    -- Simple JSON encoder: handles tables (object/array), strings, numbers, booleans, nil
    local function escape_str(s)
        s = s:gsub("\\", "\\\\")
        s = s:gsub("\"", "\\\"")
        s = s:gsub("\b", "\\b")
        s = s:gsub("\f", "\\f")
        s = s:gsub("\n", "\\n")
        s = s:gsub("\r", "\\r")
        s = s:gsub("\r", "\\r")
        s = s:gsub("\t", "\\t")
        return s
    end

    local function is_array(t)
        local max = 0
        local count = 0
        for k, _ in pairs(t) do
            if type(k) == "number" and k > 0 and math.floor(k) == k then
                if k > max then max = k end
                count = count + 1
            else
                return false
            end
        end
        if max > count * 2 then
            -- very sparse: treat as object
            return false
        end
        return true
    end

    local encode_value

    encode_value = function(v)
        local tv = type(v)
        if tv == "nil" then
            return "null"
        elseif tv == "boolean" then
            return v and "true" or "false"
        elseif tv == "number" then
            return tostring(v)
        elseif tv == "string" then
            return "\"" .. escape_str(v) .. "\""
        elseif tv == "table" then
            if is_array(v) then
                local parts = {}
                for i = 1, #v do
                    parts[#parts + 1] = encode_value(v[i])
                end
                return "[" .. table.concat(parts, ",") .. "]"
            else
                local parts = {}
                for k, val in pairs(v) do
                    parts[#parts + 1] = "\"" .. escape_str(tostring(k)) .. "\":" .. encode_value(val)
                end
                return "{" .. table.concat(parts, ",") .. "}"
            end
        else
            -- unsupported type: encode as string
            return "\"" .. escape_str(tostring(v)) .. "\""
        end
    end

    json_encode = function(v)
        return encode_value(v)
    end

    -- Simple JSON decoder: enough for Twitch/Discord responses
    json_decode = function(str)
        local pos = 1
        local len = #str

        local function skip_ws()
            local s
            repeat
                s = str:sub(pos, pos)
                if s == " " or s == "\n" or s == "\r" or s == "\t" then
                    pos = pos + 1
                else
                    break
                end
            until pos > len
        end

        local parse_value, parse_object, parse_array, parse_string, parse_number, parse_literal

        parse_string = function()
            -- assume current char is '"'
            pos = pos + 1
            local start = pos
            local res = {}
            while pos <= len do
                local c = str:sub(pos, pos)
                if c == "\"" then
                    res[#res + 1] = str:sub(start, pos - 1)
                    pos = pos + 1
                    return table.concat(res)
                elseif c == "\\" then
                    res[#res + 1] = str:sub(start, pos - 1)
                    pos = pos + 1
                    local esc = str:sub(pos, pos)
                    if esc == "b" then res[#res + 1] = "\b"
                    elseif esc == "f" then res[#res + 1] = "\f"
                    elseif esc == "n" then res[#res + 1] = "\n"
                    elseif esc == "r" then res[#res + 1] = "\r"
                    elseif esc == "t" then res[#res + 1] = "\t"
                    elseif esc == "\"" then res[#res + 1] = "\""
                    elseif esc == "\\" then res[#res + 1] = "\\"
                    elseif esc == "/" then res[#res + 1] = "/"
                    elseif esc == "u" then
						-- proper \uXXXX handling: convert to UTF-8
						local hex = str:sub(pos + 1, pos + 4)
						pos = pos + 4
						local cp = tonumber(hex, 16)
						local ch
					
						-- normalize some common “fancy” punctuation to ASCII
						if cp == 0x2019 then         -- RIGHT SINGLE QUOTATION MARK
							ch = "'"                 -- plain apostrophe
						elseif cp and cp >= 0 and cp <= 0x10FFFF then
							ch = utf8_from_codepoint(cp)
						else
							ch = "?"
						end
					
						res[#res + 1] = ch

                    else
                        res[#res + 1] = esc
                    end
                    pos = pos + 1
                    start = pos
                else
                    pos = pos + 1
                end
            end
            error("Unterminated string at position " .. tostring(start))
        end

        parse_number = function()
            local start = pos
            while pos <= len do
                local c = str:sub(pos, pos)
                if c:match("[%d%+%-%e%E%.]") then
                    pos = pos + 1
                else
                    break
                end
            end
            local num_str = str:sub(start, pos - 1)
            local num = tonumber(num_str)
            if not num then
                error("Invalid number: " .. num_str)
            end
            return num
        end

        parse_literal = function()
            if str:sub(pos, pos + 3) == "true" then
                pos = pos + 4
                return true
            elseif str:sub(pos, pos + 4) == "false" then
                pos = pos + 5
                return false
            elseif str:sub(pos, pos + 3) == "null" then
                pos = pos + 4
                return nil
            else
                error("Invalid literal at position " .. tostring(pos))
            end
        end

        parse_array = function()
            -- assume current char is '['
            pos = pos + 1
            skip_ws()
            local arr = {}
            if str:sub(pos, pos) == "]" then
                pos = pos + 1
                return arr
            end
            while true do
                local v = parse_value()
                arr[#arr + 1] = v
                skip_ws()
                local c = str:sub(pos, pos)
                if c == "," then
                    pos = pos + 1
                    skip_ws()
                elseif c == "]" then
                    pos = pos + 1
                    break
                else
                    error("Expected ',' or ']' in array at position " .. tostring(pos))
                end
            end
            return arr
        end

        parse_object = function()
            -- assume current char is '{'
            pos = pos + 1
            skip_ws()
            local obj = {}
            if str:sub(pos, pos) == "}" then
                pos = pos + 1
                return obj
            end
            while true do
                skip_ws()
                if str:sub(pos, pos) ~= "\"" then
                    error("Expected string key at position " .. tostring(pos))
                end
                local key = parse_string()
                skip_ws()
                if str:sub(pos, pos) ~= ":" then
                    error("Expected ':' after key at position " .. tostring(pos))
                end
                pos = pos + 1
                skip_ws()
                local val = parse_value()
                obj[key] = val
                skip_ws()
                local c = str:sub(pos, pos)
                if c == "," then
                    pos = pos + 1
                    skip_ws()
                elseif c == "}" then
                    pos = pos + 1
                    break
                else
                    error("Expected ',' or '}' in object at position " .. tostring(pos))
                end
            end
            return obj
        end

        parse_value = function()
            skip_ws()
            local c = str:sub(pos, pos)
            if c == "{" then
                return parse_object()
            elseif c == "[" then
                return parse_array()
            elseif c == "\"" then
                return parse_string()
            elseif c == "-" or c:match("%d") then
                return parse_number()
            else
                return parse_literal()
            end
        end

        local ok, res = pcall(function()
            skip_ws()
            local v = parse_value()
            skip_ws()
            return v
        end)

        if ok then
            return res
        else
            return nil, res
        end
    end
end

-----------------------------------------------------
-- FFI DECLARATIONS
-----------------------------------------------------

ffi.cdef[[
void* __stdcall WinHttpOpen(wchar_t* userAgent, unsigned int accessType,
                            wchar_t* proxy, wchar_t* proxyBypass, unsigned int flags);
void* __stdcall WinHttpConnect(wchar_t* session, wchar_t* server, unsigned short port, unsigned int flags);
void* __stdcall WinHttpOpenRequest(wchar_t* connect, wchar_t* verb, wchar_t* objectName,
                                   wchar_t* version, wchar_t* referrer, wchar_t** acceptTypes, unsigned int flags);
bool  __stdcall WinHttpAddRequestHeaders(void* request, wchar_t* headers, unsigned int length, unsigned int flags);
bool  __stdcall WinHttpSendRequest(void* request, wchar_t* headers, unsigned int headerLength,
                                   void* optional, unsigned int optionalLength,
                                   unsigned int totalLength, unsigned int context);
bool  __stdcall WinHttpWriteData(void* request, const void* buffer, unsigned int bytesToWrite,
                                 unsigned int* bytesWritten);
bool  __stdcall WinHttpReceiveResponse(void* request, void* reserved);
bool  __stdcall WinHttpReadData(void* request, void* buffer, unsigned int bufferSize, unsigned int* bytesRead);
unsigned int __stdcall WinHttpCloseHandle(void* handle);
]]

ffi.cdef[[
typedef unsigned long DWORD;
typedef int BOOL;
typedef void* HANDLE;

typedef struct tagPROCESSENTRY32W {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    uintptr_t th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    long pcPriClassBase;
    DWORD dwFlags;
    wchar_t szExeFile[260];
} PROCESSENTRY32W;

HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL Process32FirstW(HANDLE hSnapshot, PROCESSENTRY32W* lppe);
BOOL Process32NextW(HANDLE hSnapshot, PROCESSENTRY32W* lppe);
BOOL CloseHandle(HANDLE hObject);
]]

ffi.cdef[[
typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME;

typedef struct _WIN32_FILE_ATTRIBUTE_DATA {
    DWORD    dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD    nFileSizeHigh;
    DWORD    nFileSizeLow;
} WIN32_FILE_ATTRIBUTE_DATA;

BOOL GetFileAttributesExW(const wchar_t* lpFileName, int fInfoLevelId, void* lpFileInformation);
]]

-- For full process image path
ffi.cdef[[
HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
BOOL QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, wchar_t* lpExeName, DWORD* lpdwSize);
]]

local kernel32 = ffi.load("kernel32")
local winhttp  = ffi.load("winhttp")

local TH32CS_SNAPPROCESS                  = 0x00000002
local WINHTTP_ACCESS_TYPE_DEFAULT_PROXY   = 0
local WINHTTP_NO_PROXY_NAME               = nil
local WINHTTP_NO_PROXY_BYPASS             = nil
local WINHTTP_FLAG_SECURE                 = 0x00800000

local PROCESS_QUERY_LIMITED_INFORMATION    = 0x1000

-----------------------------------------------------
-- WCHAR HELPER
-----------------------------------------------------

local function to_wchar(str)
    local len = #str
    local buf = ffi.new("wchar_t[?]", len + 1)
    for i = 1, len do
        buf[i - 1] = string.byte(str, i)
    end
    buf[len] = 0
    return buf
end

-----------------------------------------------------
-- LOGGING
-----------------------------------------------------
local LOG_OFF   = 0
local LOG_ERROR = 1
local LOG_INFO  = 2
local LOG_DEBUG = 3
local LOG_TRACE = 4

local log_level = LOG_INFO

local function log(lvl, msg)
    if lvl == nil then lvl = LOG_INFO end
    if log_level < lvl then return end

    local severity = obs.LOG_INFO
    if lvl == LOG_ERROR then severity = obs.LOG_ERROR end
	if lvl == LOG_DEBUG then severity = obs.LOG_DEBUG end
	if lvl == LOG_TRACE then severity = obs.LOG_DEBUG end	

    obs.script_log(severity, "[AutoCategory] " .. msg)
end



-----------------------------------------------------
-- SMALL PATTERN HELPER
-----------------------------------------------------
-- Escape all magic characters so we can safely use user-provided
-- strings (like the delimiter) inside Lua patterns.
local function escape_lua_pattern(s)
    s = s or ""
    return (s:gsub("(%W)", "%%%1"))
end

-----------------------------------------------------
-- GLOBAL CONFIG / STATE
-----------------------------------------------------
-- general script /location stuff
local script_dir    = script_path()
local map_file_path = script_dir .. "game_mappings.lua"
local mappings      = nil

-- twitch stuff
local twitch_client_id      = ""
local twitch_oauth          = ""
local twitch_broadcaster_id = ""
local twitch_client_secret  = ""
local twitch_refresh_token  = ""

-- polliong/interval
local timer_active          = false
local auto_polling          = false
local poll_interval_ms      = 15000

-- Title configuration (global)
local use_pattern     = false
local title_prefix    = ""
local title_suffix    = ""
local title_delimiter = " | "
local title_pattern  = "{prefix}{delimiter}{title}{delimiter}{suffix}"
-- Default pattern: PREFIX + delim + base title + delim + suffix
-- placeholders:
--   {prefix}   -> title_prefix
--   {suffix}   -> title_suffix
--   {delim}	-> title_delimiter
--   {title}    -> "base" Titel from the rule
--   {game}     -> Twitch-Gamename (rule.twitch_game_name)

-- last set items
local last_applied_rule = nil
local last_set_game     = nil
local last_set_title    = nil
local last_set_tags     = nil
local last_mapping_timestamp = nil

-- caching and backporting
local backport_title        = true
local backport_tags         = true
local twitch_game_cache   = {}
local discord_cache_data  = nil
local discord_cache_ts    = 0
local discord_cache_ttl   = 3600

local function get_file_timestamp(path)
    local wpath = to_wchar(path)
    local data  = ffi.new("WIN32_FILE_ATTRIBUTE_DATA[1]")
    local ok    = kernel32.GetFileAttributesExW(wpath, 0, data)
    if ok == 0 then
        return nil
    end
    local ft = data[0].ftLastWriteTime
    return {
        low  = tonumber(ft.dwLowDateTime),
        high = tonumber(ft.dwHighDateTime)
    }
end

local function timestamps_equal(a, b)
    if not a or not b then return false end
    return a.low == b.low and a.high == b.high
end

-- Discord index
local discord_index = nil

-----------------------------------------------------
-- HELPERS: PATH / BASENAME
-----------------------------------------------------

local function basename(path)
    if not path then return "" end
    path = path:gsub("\\", "/")
    local name = path:match("([^/]+)$")
    return name or path
end

local function normalize_for_match(s)
    s = s or ""
    s = s:lower()
    s = s:gsub("%.exe$", "")
    s = s:gsub("%s+", "")
    s = s:gsub("\\", "/")
    return s
end

-- full Windows path -> "LastFolder/File.exe"
local function build_display_key_from_full_path(full_path, exe)
    if not full_path or full_path == "" then
        return exe
    end

    local norm = full_path:gsub("\\", "/")

    -- strip drive "C:/"
    norm = norm:gsub("^%a:/+", "")

    local dir, file = norm:match("([^/]+)/([^/]+)$")
    if dir and file then
        return dir .. "/" .. file
    end

    return exe
end

-- Query full image path by PID
local function get_process_full_path(pid)
    local h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    if h == nil or h == ffi.cast("HANDLE", 0) then
        return nil
    end

    local buf_len = 1024
    local buf = ffi.new("wchar_t[?]", buf_len)
    local size = ffi.new("DWORD[1]", buf_len)

    local ok = kernel32.QueryFullProcessImageNameW(h, 0, buf, size)
    kernel32.CloseHandle(h)

    if ok == 0 then
        return nil
    end

    local bytes = size[0] * 2
    local raw   = ffi.string(ffi.cast("char*", buf), bytes)
    local path  = raw:gsub("%z", "")

    if path == "" then return nil end
    return path
end

-----------------------------------------------------
-- MAPPING FILE HANDLING
-----------------------------------------------------

local function file_exists(path)
    local f = io.open(path, "r")
    if f then f:close() return true end
    return false
end

local function create_default_mapping_file()
    log(LOG_INFO, "Creating default game_mappings.lua...")
    local f = io.open(map_file_path, "w")
    f:write([[
-- game_mappings.lua
-- Auto-generated default mapping file for auto_twitch_category.lua
-- This file tells the script which processes belong to which Twitch game.
-- Unknown processes that can't be mapped (and aren't found via Discord)
-- will be written into cfg.unknown. Move them into cfg.rules to make them work.
-- Whenever the script updates mappings (new rules, backported title/tags),
-- the blocks cfg.just_chatting, cfg.unknown and cfg.rules are completely
-- rewritten. Any comments inside those blocks will be lost on save.
-- The sections already contain examples to help you tweak things.

-- Root config table that holds everything the script needs.
local cfg = {}

-- Tags here are always applied, no matter which game you are playing
-- (for example: "English" if you want your language as a tag).
cfg.global_tags = {
    -- "Chill Stream",
    -- "Bored Panda"
}

-- List of *.exe processes that should be ignored completely while scanning.
cfg.ignore_exact = {
    "[System Process]",
    "adb.exe",
    "AggregatorHost.exe",
    "ApplicationFrameHost.exe",
    "AppProvisioningPlugin.exe",
    "atieclxx.exe",
    "atiesrxx.exe",
    "audiodg.exe",
    "backgroundTaskHost.exe",
    "brave.exe",
    "BraveCrashHandler.exe",
    "BraveCrashHandler64.exe",
    "ChatGPT.exe",
    "chrome.exe",
    "cmd.exe",
    "cncmd.exe",
    "conhost.exe",
    "ControlServer.exe",
    "csrss.exe",
    "ctfmon.exe",
    "curl.exe",
    "dasHost.exe",
    "DataExchangeHost.exe",
    "discord.exe",
    "dllhost.exe",
    "dwm.exe",
    "explorer.exe",
    "firefox.exe",
    "FnHotkeyCapsLKNumLK.exe",
    "FnHotkeyUtility.exe",
    "fontdrvhost.exe",
    "gamingservices.exe",
    "gamingservicesnet.exe",
    "Lenovo.Modern.ImController.exe",
    "LenovoUtilityService.exe",
    "LockApp.exe",
    "logi_lamparray_service.exe",
    "lsass.exe",
    "MediaInfoGrabber.exe",
    "Memory Compression",
    "MicrosoftStartFeedProvider.exe",
    "MixItUp.exe",
    "MoNotificationUx.exe",
    "MoUsoCoreWorker.exe",
    "MpDefenderCoreService.exe",
    "mqsvc.exe",
    "msdtc.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "MsMpEng.exe",
    "nahimicNotifSys.exe",
    "NahimicService.exe",
    "NisSrv.exe",
    "NordUpdateService.exe",
    "nordvpn-service.exe",
    "notepad++.exe",
    "NVDisplay.Container.exe",
    "NVIDIA Overlay.exe",
    "nvsphelper64.exe",
    "obs32.exe",
    "obs64.exe",
    "obs-browser-page.exe",
    "OpenConsole.exe",
    "PhoneExperienceHost.exe",
    "powershell.exe",
    "provtool.exe",
    "r1710svc.exe",
    "RadeonSoftware.exe",
    "Registry",
    "RtkAudUService64.exe",
    "RtkBtManServ.exe",
    "rundll32.exe",
    "RuntimeBroker.exe",
    "SearchHost.exe",
    "SearchIndexer.exe",
    "SecurityHealthService.exe",
    "SecurityHealthSystray.exe",
    "services.exe",
    "ShellExperienceHost.exe",
    "ShellHost.exe",
    "sihost.exe",
    "smss.exe",
    "SMSvcHost.exe",
    "spoolsv.exe",
    "Spotify.exe",
    "StartMenuExperienceHost.exe",
    "steam.exe",
    "steamservice.exe",
    "steamwebhelper.exe",
    "streamdeck.exe",
    "svchost.exe",
    "taskhostw.exe",
    "taskmgr.exe",
    "TextInputHost.exe",
    "TouchPortal.exe",
    "TouchPortalServices.exe",
    "UDClientService.exe",
    "unsecapp.exe",
    "VBoxSDS.exe",
    "VirtualBox/VBoxSVC.exe",
    "wallpaper32.exe",
    "WidgetBoard.exe",
    "WidgetService.exe",
    "wininit.exe",
    "winlogon.exe",
    "WmiPrvSE.exe",
    "WUDFHost.exe",
	"_setup64.tmp",
	"BraveUpdate.exe",
	"CompatTelRunner.exe",
	"DeviceCensus.exe",
	"DismHost.exe",
	"Fences/Fences.exe",
	"IdleScheduleEventAction.exe",
	"Lenovo.Modern.ImController.PluginHost.CompanionApp.exe",
	"Lenovo.Modern.ImController.PluginHost.Device.exe",
	"Lenovo.Modern.ImController.PluginHost.Device.exe",
	"Lenovo.Modern.ImController.PluginHost.Device.exe",
	"LenovoOobePlugin.exe",
	"lpremove.exe",
	"MicrosoftEdgeUpdate.exe",
	"mlgyqdwe.exe",
	"mlgyqdwe.tmp",
	"MpCmdRun.exe",
	"MpSigStub.exe",
	"msiexec.exe",
	"ngentask.exe",
	"OpenWith.exe",
	"QtWebEngineProcess.exe",
	"SearchFilterHost.exe",
	"SearchProtocolHost.exe",
	"sppsvc.exe",
	"StoreDesktopExtension.exe",
	"timeout.exe",
	"TiWorker.exe",
	"TrustedInstaller.exe",
	"UIEOrchestrator.exe",
	"updater.exe",
	"VirtualBox/VirtualBox.exe",
	"vulkandriverquery.exe",
	"WMIADAP.exe",
	"wuaucltcore.exe",
}

-- If whitelist is filled, ONLY processes inside these folders are considered.
-- Subfolders are included automatically.
cfg.whitelist = {
    -- "C:/Program Files/Steam/",
    -- "C:/Program Files (x86)/Epic Games/",
}


-- If you have multiple tasks that share the same prefix, you dont have to add them individually but rather add the prefix here
cfg.ignore_prefix = {
    "system",
    "nvcontainer",
    "amd",
    "intel",
    "windows",
    "PowerToys",
	"AM_Delta_Patch",
}

																			  
										 
				 
								 
											
 

-- Sets what will be displayed when we're in "just chatting"
cfg.just_chatting = {
    twitch_game_name = "Just Chatting",
    title = "Just chatting with viewers",
    tags = { "Chatting" },
}

-----------------------------------------------------------------------------------------------------
-- EVERYTHING below this line will be "rewritten" everytime the game changes or title/tags are backported to here
-- Thus comments within each seperate section will be removed/deleted
-- "unknown" holds path/exe combinatiosn that neither have a mapping nor could be found via discord API
-- "rules" will have all (automatically and manually) added mappings.
-- I've provided Yuppie Psycho and Jackbox Party Games to give you a feel for how it works
-- The "ID" field is only important for interal handling and will be automatically set to the corresponding game id from discord API
-- However, you are free to rename them however you want.
------------------------------------------------------------------------------


cfg.unknown = {
}

cfg.rules = {
	{
        id = "1124351811659247626",
        processes = {
            "The Jackbox Megapicker.exe",
            "The Jackbox Party Pack.exe",
            "The Jackbox Party Pack 2.exe",
            "The Jackbox Party Pack 3.exe",
            "The Jackbox Party Pack 4.exe",
            "The Jackbox Party Pack 5.exe",
            "The Jackbox Party Pack 6.exe",
            "The Jackbox Party Pack 7.exe",
            "The Jackbox Party Pack 8.exe",
            "The Jackbox Party Pack 9.exe",
            "The Jackbox Party Pack 10.exe",
            "The Jackbox Party Pack 11.exe",
            "The Jackbox Party Pack 12.exe",
        },
        twitch_game_name = "Jackbox Party Packs",
        title = "Playing Jackbox Games",
        tags = {
            "JackboxPartyPacks",
            "PvP",
            "AudienceEngagement",
            "AudienceParticipation",
            "AudienceInteraction",
            "PartyGame",
        }
    },
    {
        id = "1124360255543984209",
        processes = {
            "YuppiePsycho/game.exe",
            "yuppiepsycho.exe",
        },
        twitch_game_name = "Yuppie Psycho",
        title = "Yuppie Psycho",
        tags = {
            "Gaming",
        }
    },
}
}



return cfg
]])
    f:close()
end

local function load_mappings()
    if not file_exists(map_file_path) then
        create_default_mapping_file()
    end

    local stamp = get_file_timestamp(map_file_path)

    if stamp and last_mapping_timestamp
       and mappings ~= nil
       and timestamps_equal(stamp, last_mapping_timestamp)
    then
        return
    end

    log(LOG_DEBUG, "Loading mapping file: " .. map_file_path)
    local ok, cfg = pcall(dofile, map_file_path)
    if not ok then
        log(LOG_ERROR, "Failed to load mapping file: " .. tostring(cfg))
        return
    end

    mappings = cfg

    mappings.global_tags   = mappings.global_tags   or {}
    mappings.ignore_exact  = mappings.ignore_exact  or {}
    mappings.ignore_prefix = mappings.ignore_prefix or {}
    mappings.whitelist     = mappings.whitelist     or {}
    mappings.just_chatting = mappings.just_chatting or {
        twitch_game_name = "Just Chatting",
        title = "Just chatting",
        tags = { "Chatting" }
    }
    mappings.rules         = mappings.rules         or {}
    mappings.unknown       = mappings.unknown       or {}

    last_mapping_timestamp = stamp

    log(LOG_DEBUG, "Mapping file loaded (or reloaded) successfully")
end

local function save_mappings()
    if not mappings then return end
    log(LOG_DEBUG, "Saving mapping file (only cfg.unknown + cfg.rules will be rewritten)...")

    -- Read current file as plain text
    local lines = {}
    local f, err = io.open(map_file_path, "r")
    if not f then
        log(LOG_ERROR, "Failed to open mapping file for read: " .. tostring(err))
        return
    end
    for line in f:lines() do
        table.insert(lines, line)
    end
    f:close()

    local function find_block(start_pattern)
        -- returns start_line_index, end_line_index (inclusive)
        local start_idx, end_idx = nil, nil
        local depth = 0
        for i, line in ipairs(lines) do
            if not start_idx and line:match("^%s*" .. start_pattern) then
                start_idx = i
                -- count '{' on this line
                depth = select(2, line:gsub("{", "")) - select(2, line:gsub("}", ""))
                if depth <= 0 then
                    -- single-line block (unlikely here but for completeness)
                    end_idx = i
                    break
                end
            elseif start_idx then
                -- track brace depth until we close the top-level '{ ... }'
                local open_cnt  = select(2, line:gsub("{", ""))
                local close_cnt = select(2, line:gsub("}", ""))
                depth = depth + open_cnt - close_cnt
                if depth <= 0 then
                    end_idx = i
                    break
                end
            end
        end
        return start_idx, end_idx
    end

	local function render_just_chatting_block()
		local out = {}
		local jc = mappings.just_chatting or {
			twitch_game_name = "Just Chatting",
			title            = "Just chatting",
			tags             = { "Chatting" },
		}
	
		table.insert(out, "cfg.just_chatting = {")
		table.insert(out, string.format('    twitch_game_name = "%s",', jc.twitch_game_name or "Just Chatting"))
		table.insert(out, string.format('    title = "%s",', jc.title or "Just chatting"))
		table.insert(out, "    tags = {")
		for _, t in ipairs(jc.tags or {}) do
			table.insert(out, string.format('        "%s",', t))
		end
		table.insert(out, "    },")
		table.insert(out, "}")
		return out
	end

    local function render_unknown_block()
        local out = {}
        table.insert(out, "cfg.unknown = {")
        for _, v in ipairs(mappings.unknown or {}) do
            table.insert(out, string.format('    "%s",', v))
        end
        table.insert(out, "}")
        return out
    end

    local function render_rules_block()
        local out = {}
        table.insert(out, "cfg.rules = {")
        for _, r in ipairs(mappings.rules or {}) do
            table.insert(out, "    {")
            table.insert(out, string.format('        id = "%s",', r.id or "rule"))
            table.insert(out, "        processes = {")
            for _, p in ipairs(r.processes or {}) do
                table.insert(out, string.format('            "%s",', p))
            end
            table.insert(out, "        },")
            table.insert(out, string.format('        twitch_game_name = "%s",', r.twitch_game_name or ""))
            table.insert(out, string.format('        title = "%s",', r.title or ""))
            table.insert(out, "        tags = {")
            for _, t in ipairs(r.tags or {}) do
                table.insert(out, string.format('            "%s",', t))
            end
            table.insert(out, "        }")
            table.insert(out, "    },")
        end
        table.insert(out, "}")
        return out
    end

	local jc_start, jc_end = find_block("cfg%.just_chatting%s*=%s*{")
    local u_start, u_end = find_block("cfg%.unknown%s*=%s*{")
    local r_start, r_end = find_block("cfg%.rules%s*=%s*{")

	
	if not jc_start or not jc_end then
		log(LOG_ERROR, "Could not locate cfg.just_chatting block in mapping file; aborting save.")
		return
	end
    if not u_start or not u_end then
        log(LOG_ERROR, "Could not locate cfg.unknown block in mapping file; aborting save.")
        return
    end
    if not r_start or not r_end then
        log(LOG_ERROR, "Could not locate cfg.rules block in mapping file; aborting save.")
        return
    end
	
    local new_lines = {}
    local i = 1
    while i <= #lines do
        if i == jc_start then
			local block = render_just_chatting_block()
			for _, l in ipairs(block) do table.insert(new_lines, l) end
			i = jc_end + 1
		elseif i == u_start then
            -- insert new unknown block
            local block = render_unknown_block()
            for _, l in ipairs(block) do table.insert(new_lines, l) end
            i = u_end + 1
        elseif i == r_start then
            -- insert new rules block
            local block = render_rules_block()
            for _, l in ipairs(block) do table.insert(new_lines, l) end
            i = r_end + 1
        else
            table.insert(new_lines, lines[i])
            i = i + 1
        end
    end

    local wf, werr = io.open(map_file_path, "w")
    if not wf then
        log(LOG_ERROR, "Failed to open mapping file for write: " .. tostring(werr))
        return
    end
    wf:write(table.concat(new_lines, "\n"))
    wf:close()

    last_mapping_timestamp = get_file_timestamp(map_file_path)
    log(LOG_DEBUG, "Mapping file saved (comments outside cfg.unknown/cfg.rules preserved).")
end


-----------------------------------------------------
-- PROCESS ENUMERATION
-- returns { { exe = "...", key = "Folder/file.exe" }, ... }
-----------------------------------------------------

local function scan_processes()
    log(LOG_DEBUG, "Scanning running processes...")

    local snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == ffi.cast("HANDLE", -1) then
        log(LOG_ERROR, "CreateToolhelp32Snapshot failed")
        return {}
    end

    local entry = ffi.new("PROCESSENTRY32W")
    entry.dwSize = ffi.sizeof(entry)

    local processes = {}

    if kernel32.Process32FirstW(snapshot, entry) == 0 then
        kernel32.CloseHandle(snapshot)
        log(LOG_ERROR, "Process32FirstW failed")
        return processes
    end

    repeat
        local exe_raw = ffi.string(ffi.cast("char*", entry.szExeFile), 260 * 2)
        local exe = exe_raw:gsub("%z", "")
        if exe ~= "" then
            local pid  = tonumber(entry.th32ProcessID)
            local path = get_process_full_path(pid)
            local key  = build_display_key_from_full_path(path, exe)

            table.insert(processes, {
                exe       = exe,
                key       = key,
                full_path = path,
            })
        end
    until kernel32.Process32NextW(snapshot, entry) == 0

    kernel32.CloseHandle(snapshot)

    log(LOG_DEBUG, "Found " .. tostring(#processes) .. " processes")
    return processes
end

-----------------------------------------------------
-- IGNORE CHECK + UNKNOWN BUCKET
-----------------------------------------------------

local function process_is_ignored_base(name)
    -- name can be "steam.exe", "Steam/steam.exe" or even "C:\\Games\\Steam\\steam.exe"
    local lname = string.lower(name or "")
    local base  = string.lower(basename(name or ""))

    -- exact ignores: match either full string or just the basename
    for _, ex in ipairs(mappings.ignore_exact or {}) do
        local lex = string.lower(ex)
        if lname == lex or base == lex then
            log(LOG_DEBUG, string.format(
                "Ignoring process (exact): '%s' (matched '%s')",
                name, ex
            ))
            return true
        end
    end

    -- prefix ignores: also match on basename, not only the full string
    for _, px in ipairs(mappings.ignore_prefix or {}) do
        local lp = string.lower(px)
        if lname:sub(1, #lp) == lp or base:sub(1, #lp) == lp then
            log(LOG_DEBUG, string.format(
                "Ignoring process (prefix): '%s' (matched '%s')",
                name, px
            ))
            return true
        end
    end

    return false
end

local function process_is_in_unknown(name)
    local lname = string.lower(name)
    for _, u in ipairs(mappings.unknown or {}) do
        if lname == string.lower(u) then
            return true
        end
    end
    return false
end

local function process_is_ignored_name(name)
    if process_is_ignored_base(name) then
        return true
    end
    if process_is_in_unknown(name) then
        log(LOG_DEBUG, "Ignoring process (unknown bucket): " .. name)
        return true
    end
    return false
end


local function normalize_path(p)
    p = (p or ""):gsub("\\", "/"):lower()
    if p ~= "" and p:sub(-1) ~= "/" then p = p .. "/" end
    return p
end

local function process_is_whitelisted(proc)
    local wl = mappings.whitelist or {}
    if #wl == 0 then
        return true
    end

    local full = normalize_path(proc.full_path or "")
    if full == "" then
        return false
    end

    for _, w in ipairs(wl) do
        local nw = normalize_path(w)
        if nw ~= "" and full:sub(1, #nw) == nw then
            return true
        end
    end
    return false
end

local function process_is_ignored_proc(proc)
    if not process_is_whitelisted(proc) then
        log(LOG_TRACE, "Skipping process (not whitelisted): " .. (proc.full_path or proc.key or proc.exe))
        return true
    end
    local name = proc.key or proc.exe
    return process_is_ignored_name(name)
end


-- Add all non-ignored processes of this tick to cfg.unknown
-- using their display key ("Folder/file.exe")
local function update_unknown_bucket(processes)
    mappings.unknown = mappings.unknown or {}

    local existing = {}
    for _, v in ipairs(mappings.unknown) do
        existing[string.lower(v)] = true
    end

    local added_any = false

    for _, proc in ipairs(processes) do
        local key = proc.key or proc.exe
        local lname = string.lower(key)

        if process_is_whitelisted(proc) and (not process_is_ignored_base(key)) and (not existing[lname]) then
            table.insert(mappings.unknown, key)
            existing[lname] = true
            added_any = true
            log(LOG_INFO, "Adding process to cfg.unknown: " .. key)
        end
    end

    if added_any then
        save_mappings()
    else
        log(LOG_DEBUG, "No new processes to add to cfg.unknown")
    end
end

-----------------------------------------------------
-- HTTP HELPERS
-----------------------------------------------------

local function http_get_json(host, path, headers_tbl)
    log(LOG_DEBUG, "HTTP GET https://" .. host .. path)

    local w_host = to_wchar(host)
    local w_path = to_wchar(path)
    local w_GET  = to_wchar("GET")

    local session = winhttp.WinHttpOpen(nil,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    )
    if session == nil then
        log(LOG_ERROR, "WinHttpOpen failed (GET)")
        return nil
    end

    local conn = winhttp.WinHttpConnect(session, w_host, 443, 0)
    if conn == nil then
        log(LOG_ERROR, "WinHttpConnect failed (GET)")
        winhttp.WinHttpCloseHandle(session)
        return nil
    end

    local req = winhttp.WinHttpOpenRequest(
        conn, w_GET, w_path, nil, nil, nil, WINHTTP_FLAG_SECURE
    )
    if req == nil then
        log(LOG_ERROR, "WinHttpOpenRequest failed (GET)")
        winhttp.WinHttpCloseHandle(conn)
        winhttp.WinHttpCloseHandle(session)
        return nil
    end

    for k, v in pairs(headers_tbl or {}) do
        local line = k .. ": " .. v .. "\r\n"
        local w_line = to_wchar(line)
        winhttp.WinHttpAddRequestHeaders(req, w_line, -1, 0)
    end

    if winhttp.WinHttpSendRequest(req, nil, 0, nil, 0, 0, 0) == false then
        log(LOG_ERROR, "WinHttpSendRequest failed (GET)")
        winhttp.WinHttpCloseHandle(req)
        winhttp.WinHttpCloseHandle(conn)
        winhttp.WinHttpCloseHandle(session)
        return nil
    end

    winhttp.WinHttpReceiveResponse(req, nil)

    local buf  = ffi.new("uint8_t[4096]")
    local out  = {}
    local read = ffi.new("unsigned int[1]")

    while true do
        if winhttp.WinHttpReadData(req, buf, 4096, read) == false then
            log(LOG_ERROR, "WinHttpReadData failed (GET)")
            break
        end
        if read[0] == 0 then
            break
        end
        table.insert(out, ffi.string(buf, read[0]))
    end

    winhttp.WinHttpCloseHandle(req)
    winhttp.WinHttpCloseHandle(conn)
    winhttp.WinHttpCloseHandle(session)

    local data = table.concat(out)
    if data == "" then
        log(LOG_ERROR, "HTTP GET returned empty body")
        return nil
    end

    local res, err = json_decode(data)
    if not res then
        log(LOG_ERROR, "JSON decode failed (GET): " .. tostring(err))
        return nil
    end

    return res
end

local function http_patch_json(host, path, json_body, headers_tbl)
    log(LOG_DEBUG, "HTTP PATCH https://" .. host .. path)

    local w_host  = to_wchar(host)
    local w_path  = to_wchar(path)
    local w_PATCH = to_wchar("PATCH")

    local session = winhttp.WinHttpOpen(nil,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    )
    if session == nil then
        log(LOG_ERROR, "WinHttpOpen failed (PATCH)")
        return nil
    end

    local conn = winhttp.WinHttpConnect(session, w_host, 443, 0)
    if conn == nil then
        log(LOG_ERROR, "WinHttpConnect failed (PATCH)")
        winhttp.WinHttpCloseHandle(session)
        return nil
    end

    local req = winhttp.WinHttpOpenRequest(
        conn, w_PATCH, w_path, nil, nil, nil, WINHTTP_FLAG_SECURE
    )
    if req == nil then
        log(LOG_ERROR, "WinHttpOpenRequest failed (PATCH)")
        winhttp.WinHttpCloseHandle(conn)
        winhttp.WinHttpCloseHandle(session)
        return nil
    end

    for k, v in pairs(headers_tbl or {}) do
        local line = k .. ": " .. v .. "\r\n"
        local w_line = to_wchar(line)
        winhttp.WinHttpAddRequestHeaders(req, w_line, -1, 0)
    end

    local body     = json_body or ""
    local body_len = #body

    if winhttp.WinHttpSendRequest(req, nil, 0, nil, 0, body_len, 0) == false then
        log(LOG_ERROR, "WinHttpSendRequest failed (PATCH)")
        winhttp.WinHttpCloseHandle(req)
        winhttp.WinHttpCloseHandle(conn)
        winhttp.WinHttpCloseHandle(session)
        return nil
    end

    if body_len > 0 then
        local buf     = ffi.new("char[?]", body_len, body)
        local written = ffi.new("unsigned int[1]")
        if winhttp.WinHttpWriteData(req, buf, body_len, written) == false then
            log(LOG_ERROR, "WinHttpWriteData failed (PATCH)")
        else
            log(LOG_DEBUG, "WinHttpWriteData wrote " .. tostring(written[0]) .. " bytes")
        end
    end

    winhttp.WinHttpReceiveResponse(req, nil)

    local buffer = ffi.new("uint8_t[4096]")
    local out    = {}
    local read   = ffi.new("unsigned int[1]")

    while true do
        if winhttp.WinHttpReadData(req, buffer, 4096, read) == false then
            log(LOG_ERROR, "WinHttpReadData failed (PATCH)")
            break
        end
        if read[0] == 0 then
            break
        end
        table.insert(out, ffi.string(buffer, read[0]))
    end

    winhttp.WinHttpCloseHandle(req)
    winhttp.WinHttpCloseHandle(conn)
    winhttp.WinHttpCloseHandle(session)

    local response_data = table.concat(out)
    if response_data == "" then
        log(LOG_DEBUG, "HTTP PATCH returned empty body")
        return nil
    end

    local res, err = json_decode(response_data)
    if not res then
        log(LOG_ERROR, "JSON decode failed (PATCH): " .. tostring(err))
        return nil
    end
    return res
end

-----------------------------------------------------
-- HTTP POST FORM (for token refresh)
-----------------------------------------------------

local function urlencode(str)
    str = tostring(str or "")
    str = str:gsub("\n", "\r\n")
    str = str:gsub("([^%w%-_%.~])", function(c)
        return string.format("%%%02X", string.byte(c))
    end)
    return str
end

local function http_post_form(host, path, form_tbl)
    log(LOG_DEBUG, "HTTP POST https://" .. host .. path .. " (x-www-form-urlencoded)")

    local w_host = to_wchar(host)
    local w_path = to_wchar(path)
    local w_POST = to_wchar("POST")

    local session = winhttp.WinHttpOpen(nil,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    )
    if session == nil then
        log(LOG_ERROR, "WinHttpOpen failed (POST)")
        return nil
    end

    local conn = winhttp.WinHttpConnect(session, w_host, 443, 0)
    if conn == nil then
        log(LOG_ERROR, "WinHttpConnect failed (POST)")
        winhttp.WinHttpCloseHandle(session)
        return nil
    end

    local req = winhttp.WinHttpOpenRequest(
        conn, w_POST, w_path, nil, nil, nil, WINHTTP_FLAG_SECURE
    )
    if req == nil then
        log(LOG_ERROR, "WinHttpOpenRequest failed (POST)")
        winhttp.WinHttpCloseHandle(conn)
        winhttp.WinHttpCloseHandle(session)
        return nil
    end

    local parts = {}
    for k, v in pairs(form_tbl or {}) do
        parts[#parts + 1] = urlencode(k) .. "=" .. urlencode(v)
    end
    local body = table.concat(parts, "&")
    local body_len = #body

    local hdr = "Content-Type: application/x-www-form-urlencoded\r\n"
    winhttp.WinHttpAddRequestHeaders(req, to_wchar(hdr), -1, 0)

    if winhttp.WinHttpSendRequest(req, nil, 0, nil, 0, body_len, 0) == false then
        log(LOG_ERROR, "WinHttpSendRequest failed (POST)")
        winhttp.WinHttpCloseHandle(req)
        winhttp.WinHttpCloseHandle(conn)
        winhttp.WinHttpCloseHandle(session)
        return nil
    end

    if body_len > 0 then
        local buf     = ffi.new("char[?]", body_len, body)
        local written = ffi.new("unsigned int[1]")
        if winhttp.WinHttpWriteData(req, buf, body_len, written) == false then
            log(LOG_ERROR, "WinHttpWriteData failed (POST)")
        else
            log(LOG_DEBUG, "WinHttpWriteData wrote " .. tostring(written[0]) .. " bytes (POST)")
        end
    end

    winhttp.WinHttpReceiveResponse(req, nil)

    local buffer = ffi.new("uint8_t[4096]")
    local out    = {}
    local read   = ffi.new("unsigned int[1]")

    while true do
        if winhttp.WinHttpReadData(req, buffer, 4096, read) == false then
            log(LOG_ERROR, "WinHttpReadData failed (POST)")
            break
        end
        if read[0] == 0 then
            break
        end
        table.insert(out, ffi.string(buffer, read[0]))
    end

    winhttp.WinHttpCloseHandle(req)
    winhttp.WinHttpCloseHandle(conn)
    winhttp.WinHttpCloseHandle(session)

    local data = table.concat(out)
    if data == "" then
        log(LOG_ERROR, "HTTP POST returned empty body")
        return nil
    end

    local res, err = json_decode(data)
    if not res then
        log(LOG_ERROR, "JSON decode failed (POST): " .. tostring(err))
        return nil
    end

    return res
end

-----------------------------------------------------
-- TWITCH TOKEN REFRESH
-----------------------------------------------------

local function twitch_refresh_access_token()
    if twitch_client_id == "" or twitch_client_secret == "" or twitch_refresh_token == "" then
        log(LOG_ERROR, "Cannot refresh Twitch token: client_id, client_secret or refresh_token missing.")
        return false
    end

    log(LOG_INFO, "Refreshing Twitch OAuth token via refresh_token...")

    local resp = http_post_form("id.twitch.tv", "/oauth2/token", {
        grant_type    = "refresh_token",
        refresh_token = twitch_refresh_token,
        client_id     = twitch_client_id,
        client_secret = twitch_client_secret,
    })

    if not resp then
        log(LOG_ERROR, "Twitch token refresh failed: no response")
        return false
    end

    if resp.status and resp.status ~= 200 then
        log(LOG_ERROR, string.format(
            "Twitch token refresh error: status=%s message=%s",
            tostring(resp.status), tostring(resp.message)
        ))
        return false
    end

    if not resp.access_token then
        local raw = ""
        local ok, enc = pcall(json_encode, resp)
        if ok then raw = enc else raw = "<json_encode failed: " .. tostring(enc) .. ">" end
        log(LOG_ERROR, "Twitch token refresh response missing access_token. Raw: " .. raw)
        return false
    end

    twitch_oauth = resp.access_token
    if resp.refresh_token then
        twitch_refresh_token = resp.refresh_token
    end

    log(LOG_INFO, "Twitch OAuth token refreshed successfully.")
    return true
end

-----------------------------------------------------
-- TWITCH HELPERS
-----------------------------------------------------

local function get_twitch_game_id(game_name)
    -- Helper: check if this game name is already marked as unknown
    local function is_unknown_game(name)
        if not mappings or not mappings.unknown then return false end
        local lname = string.lower(name or "")
        for _, v in ipairs(mappings.unknown) do
            if lname == string.lower(v) then
                return true
            end
        end
        return false
    end

    -- Helper: mark a game name as unknown in cfg.unknown and save
    local function mark_game_unknown(name)
        if not mappings then return end
        mappings.unknown = mappings.unknown or {}

        local lname = string.lower(name or "")
        for _, v in ipairs(mappings.unknown) do
            if lname == string.lower(v) then
                return
            end
        end

        table.insert(mappings.unknown, name)
        log(LOG_INFO, string.format("Marking game '%s' as unknown in cfg.unknown", name))
        save_mappings()
    end

    -- Helper: normalize dashes and remove trademark-like characters
    local function normalize_dashes_and_trademarks(name)
        local n = name or ""

        -- Replace hyphen/en dash/em dash with colon
        n = n:gsub("–", ":")   -- en dash
        n = n:gsub("—", ":")   -- em dash
        n = n:gsub("%-", ":")  -- ASCII hyphen

        -- Remove some common trademark symbols
        n = n:gsub("™", "")    -- TM
        n = n:gsub("®", "")    -- registered
        n = n:gsub("©", "")    -- copyright

        -- Trim whitespace
        n = n:gsub("^%s+", ""):gsub("%s+$", "")

        return n
    end

    -- Helper: remove "all" special characters for fuzzy search
    local function strip_special_chars(name)
        local n = name or ""
        -- Keep only letters, digits and spaces (Lua %w is ASCII-ish, good enough for fallback)
        n = n:gsub("[^%w%s]", " ")
        -- Collapse multiple spaces → single, trim
        n = n:gsub("%s+", " ")
        n = n:gsub("^%s+", ""):gsub("%s+$", "")
        return n
    end

    -- Helper: perform /helix/games?name=...
    local function resolve_via_games_api(name, headers)
        local encoded = urlencode(name or "")
        local path = "/helix/games?name=" .. encoded

        local function call()
            return http_get_json("api.twitch.tv", path, headers)
        end

        local resp = call()
        if resp and resp.status == 401 and resp.message == "Invalid OAuth token" then
            log(LOG_ERROR, "Twitch game resolve failed (games?name): Invalid OAuth token. Trying to refresh...")
            if twitch_refresh_access_token() then
                headers["Authorization"] = "Bearer " .. twitch_oauth
                resp = call()
            end
        end

        if not resp then
            return nil, nil
        end

        if resp.error or (resp.status and resp.status ~= 200) then
            log(LOG_ERROR, string.format(
                "Twitch error while resolving game '%s' via games?name: error=%s status=%s message=%s",
                name,
                tostring(resp.error),
                tostring(resp.status),
                tostring(resp.message)
            ))
            return nil, nil
        end

        if not resp.data or not resp.data[1] then
            return nil, nil
        end

        local item = resp.data[1]
        return item.id, item.name
    end

    -- Helper: perform /helix/search/categories?query=...
    local function resolve_via_search_api(query, headers)
        local encoded = urlencode(query or "")
        local path = "/helix/search/categories?query=" .. encoded

        local function call()
            return http_get_json("api.twitch.tv", path, headers)
        end

        local resp = call()
        if resp and resp.status == 401 and resp.message == "Invalid OAuth token" then
            log(LOG_ERROR, "Twitch game resolve failed (search/categories): Invalid OAuth token. Trying to refresh...")
            if twitch_refresh_access_token() then
                headers["Authorization"] = "Bearer " .. twitch_oauth
                resp = call()
            end
        end

        if not resp then
            return nil, nil
        end

        if resp.error or (resp.status and resp.status ~= 200) then
            log(LOG_ERROR, string.format(
                "Twitch error while resolving game '%s' via search/categories: error=%s status=%s message=%s",
                query,
                tostring(resp.error),
                tostring(resp.status),
                tostring(resp.message)
            ))
            return nil, nil
        end

        if not resp.data or not resp.data[1] then
            return nil, nil
        end

        local item = resp.data[1]
        return item.id, item.name
    end

    ----------------------------------------------------------------
    -- Actual game-id resolution logic
    ----------------------------------------------------------------
    local original_name = game_name or ""
    local cache_key     = string.lower(original_name)

    if cache_key == "" then
        return nil
    end

    -- If the game is already flagged as unknown, skip all Twitch calls
    if is_unknown_game(original_name) then
        log(LOG_DEBUG, string.format(
            "Game '%s' is in cfg.unknown; skipping Twitch resolution.",
            original_name
        ))
        return nil
    end

    -- Simple cache based on original name
    if twitch_game_cache[cache_key] then
        log(LOG_DEBUG, "Using cached Twitch game ID for: " .. original_name)
        return twitch_game_cache[cache_key]
    end

    if twitch_client_id == "" then
        log(LOG_ERROR, "Cannot resolve Twitch game: Twitch Client ID is not set.")
        return nil
    end

    log(LOG_DEBUG, "Resolving Twitch game ID for: " .. original_name)

    local headers = {
        ["Client-Id"]    = twitch_client_id,
        ["Content-Type"] = "application/json",
    }
    if twitch_oauth ~= "" then
        headers["Authorization"] = "Bearer " .. twitch_oauth
    end

    ------------------------------------------------------------
    -- Step 1: try exact /helix/games?name= with original name
    ------------------------------------------------------------
    local game_id, resolved_name = resolve_via_games_api(original_name, headers)
    if game_id then
        log(LOG_INFO, string.format(
            "Twitch game '%s' resolved to ID %s via games?name (exact).",
            resolved_name or original_name,
            tostring(game_id)
        ))
        twitch_game_cache[cache_key] = game_id
        return game_id
    end

    ------------------------------------------------------------
    -- Step 2: normalize dashes + trademark symbols, retry games?name
    ------------------------------------------------------------
    local normalized = normalize_dashes_and_trademarks(original_name)
    if normalized ~= "" and normalized ~= original_name then
        log(LOG_DEBUG, string.format(
            "Retrying Twitch resolution with normalized name: '%s' -> '%s'",
            original_name,
            normalized
        ))

        local norm_id, norm_name = resolve_via_games_api(normalized, headers)
        if norm_id then
            log(LOG_INFO, string.format(
                "Twitch game '%s' resolved to ID %s via games?name (normalized).",
                norm_name or normalized,
                tostring(norm_id)
            ))
            twitch_game_cache[cache_key] = norm_id
            return norm_id
        end
    else
        normalized = original_name
    end

    ------------------------------------------------------------
    -- Step 3: remove special chars, use /helix/search/categories
    ------------------------------------------------------------
    local stripped = strip_special_chars(normalized)
    if stripped ~= "" then
        log(LOG_DEBUG, string.format(
            "Falling back to /helix/search/categories with stripped query: '%s' -> '%s'",
            normalized,
            stripped
        ))

        local search_id, search_name = resolve_via_search_api(stripped, headers)
        if search_id then
            log(LOG_INFO, string.format(
                "Twitch game '%s' resolved to ID %s via search/categories (fuzzy).",
                search_name or stripped,
                tostring(search_id)
            ))
            twitch_game_cache[cache_key] = search_id
            return search_id
        end
    end

    ------------------------------------------------------------
    -- All attempts failed → mark game as unknown and bail
    ------------------------------------------------------------
    log(LOG_ERROR, string.format(
        "Unable to resolve Twitch game for '%s' (games?name + normalized + search/categories all failed). Marking as unknown.",
        original_name
    ))

    mark_game_unknown(original_name)
    return nil
end

local function twitch_update_stream(game_name, title, tags)
    if twitch_client_id == "" then
        log(LOG_ERROR, "Twitch Client ID missing. Skipping update.")
        return false
    end

    if twitch_broadcaster_id == "" then
        log(LOG_ERROR, "Twitch Broadcaster ID missing. Skipping update.")
        return false
    end

    local game_id = get_twitch_game_id(game_name)
    if not game_id then
        log(LOG_ERROR, "Cannot update stream; game_id resolution failed.")
        return false
    end

    local payload_table = {
        game_id = game_id,
        title   = title,
        tags    = tags
    }

    local payload = json_encode(payload_table)

    local headers = {
        ["Client-Id"]    = twitch_client_id,
        ["Content-Type"] = "application/json",
    }
    if twitch_oauth ~= "" then
        headers["Authorization"] = "Bearer " .. twitch_oauth
    end

    log(LOG_INFO, string.format("Updating Twitch stream: game='%s' title='%s'", game_name, title))

    local function try_once()
        return http_patch_json(
            "api.twitch.tv",
            "/helix/channels?broadcaster_id=" .. twitch_broadcaster_id,
            payload,
            headers
        )
    end

    local resp = try_once()

    if resp and resp.status == 401 and resp.message == "Invalid OAuth token" then
        log(LOG_ERROR, "Twitch update failed: Invalid OAuth token. Trying to refresh...")
        if twitch_refresh_access_token() then
            headers["Authorization"] = "Bearer " .. twitch_oauth
            resp = try_once()
        end
    end

    if resp then
        if resp.error or (resp.status and resp.status ~= 200) then
            log(LOG_ERROR, string.format(
                "Twitch update error: error=%s status=%s message=%s",
                tostring(resp.error),
                tostring(resp.status),
                tostring(resp.message)
            ))
			return false
        else
            log(LOG_DEBUG, "Twitch update response: " .. json_encode(resp))
        end
    else
        log(LOG_ERROR, "Twitch update returned no parsed response (may still have succeeded).")
    end
	return true
end

local function twitch_get_channel_info()
    if twitch_client_id == "" then
        log(LOG_ERROR, "Cannot fetch channel info: Twitch Client ID is not set.")
        return nil
    end
    if twitch_broadcaster_id == "" then
        log(LOG_ERROR, "Cannot fetch channel info: Broadcaster ID is not set.")
        return nil
    end

    local headers = {
        ["Client-Id"]    = twitch_client_id,
        ["Content-Type"] = "application/json",
    }
    if twitch_oauth ~= "" then
        headers["Authorization"] = "Bearer " .. twitch_oauth
    end

    local path = "/helix/channels?broadcaster_id=" .. twitch_broadcaster_id

    local function try_once()
        return http_get_json("api.twitch.tv", path, headers)
    end

    local resp = try_once()

    if resp and resp.status == 401 and resp.message == "Invalid OAuth token" then
        log(LOG_ERROR, "Twitch channel fetch failed: Invalid OAuth token. Trying to refresh...")
        if twitch_refresh_access_token() then
            headers["Authorization"] = "Bearer " .. twitch_oauth
            resp = try_once()
        end
    end

    if not resp then
        log(LOG_ERROR, "No response from Twitch when fetching channel info.")
        return nil
    end

    if resp.error or (resp.status and resp.status ~= 200) then
        log(LOG_ERROR, string.format(
            "Twitch error while fetching channel info: error=%s status=%s message=%s",
            tostring(resp.error),
            tostring(resp.status),
            tostring(resp.message)
        ))
        return nil
    end

    if not resp.data or not resp.data[1] then
        log(LOG_ERROR, "Twitch channel info response has no data entry.")
        return nil
    end

    return resp.data[1]
end

-----------------------------------------------------
-- RULE MATCHING (MAPPINGS)
-----------------------------------------------------

local function proc_matches_mapping_entry(proc, mapping_str)
    local p_key = (proc.key or proc.exe or ""):gsub("\\", "/")
    local p_exe = proc.exe or ""
    local m_str = mapping_str or ""

    local norm_m = m_str:gsub("\\", "/"):lower()
    local has_sep = norm_m:find("/") ~= nil

    if has_sep then
        local norm_p = p_key:lower()
        return norm_p == norm_m
    else
        return p_exe:lower() == norm_m
    end
end

local function find_rule(processes)
    for _, proc in ipairs(processes) do
        local name_for_ignore = proc.key or proc.exe
        if not process_is_ignored_proc(proc) then
            log(LOG_DEBUG, "Checking process against rules: " .. name_for_ignore)
            for _, rule in ipairs(mappings.rules or {}) do
                for _, pname in ipairs(rule.processes or {}) do
                    if proc_matches_mapping_entry(proc, pname) then
                        log(LOG_DEBUG, string.format("Process '%s' matched rule '%s'", name_for_ignore, rule.id or "unknown"))
                        return rule
                    end
                end
            end
        else
            log(LOG_DEBUG, "Skipping process for rules (ignored): " .. name_for_ignore)
        end
    end
    return nil
end

-----------------------------------------------------
-- DISCORD DETECTABLE FALLBACK (WITH INDEX)
-----------------------------------------------------

local function build_discord_index()
    if not discord_cache_data then
        discord_index = nil
        return
    end

    log(LOG_DEBUG, "Building Discord detectable index...")
    local by_exe   = {}
    local by_alias = {}

    for i, app in ipairs(discord_cache_data) do
        local app_name    = app.name or "<unknown>"
        local aliases     = app.aliases or {}
        local executables = app.executables or {}

        for _, ex in ipairs(executables) do
            if ex.name and ex.os == "win32" then
                local base   = basename(ex.name)
                local base_l = base:lower()
                local norm = normalize_for_match(base)
                local list = by_exe[norm]
                if not list then
                    list = {}
                    by_exe[norm] = list
                end
                table.insert(list, {
                    app_index = i,
                    exe_raw   = ex.name,
                    exe_base  = base,
                })
            end
        end

        local function add_alias_entry(str, source)
            if not str or str == "" then return end
            local norm = normalize_for_match(str)
            local list = by_alias[norm]
            if not list then
                list = {}
                by_alias[norm] = list
            end
            table.insert(list, {
                app_index = i,
                source    = source,
                alias     = str,
            })
        end

        add_alias_entry(app.name, "name")
        for _, a in ipairs(aliases) do
            add_alias_entry(a, "alias")
        end
    end

    discord_index = {
        by_exe   = by_exe,
        by_alias = by_alias,
    }

    local function count_keys(tbl)
        local c = 0
        for _ in pairs(tbl) do c = c + 1 end
        return c
    end

    log(LOG_DEBUG, "Discord index built: "
        .. tostring(#discord_cache_data) .. " apps, "
        .. tostring(count_keys(by_exe)) .. " exe keys, "
        .. tostring(count_keys(by_alias)) .. " alias keys"
    )
end

local function fetch_discord_detectable()
    local now = os.time()
    if discord_cache_data and (now - discord_cache_ts) < discord_cache_ttl then
        log(LOG_DEBUG, "Using cached Discord detectable apps")
        if not discord_index then
            build_discord_index()
        end
        return discord_cache_data
    end

    log(LOG_INFO, "Fetching Discord detectable applications...")
    local resp = http_get_json("discord.com", "/api/v9/applications/detectable", nil)
    if resp then
        discord_cache_data = resp
        discord_cache_ts   = now
        build_discord_index()
        log(LOG_INFO, string.format("Fetched %d Discord detectable applications", #resp))
    else
        log(LOG_ERROR, "Failed to fetch Discord detectable applications")
    end
    return resp
end

-- Helper: turn a Discord executable name into a comparable key
-- Examples:
--   "Gotham Impostors/engine.exe" -> "gotham impostors/engine.exe"
--   "engine.exe"                  -> "engine.exe"
local function discord_exe_to_key(exe_name)
    if not exe_name or exe_name == "" then
        return nil
    end

    local norm = exe_name:gsub("\\", "/"):lower()

    local dir, file = norm:match("([^/]+)/([^/]+)$")
    if dir and file then
        return dir .. "/" .. file
    end

    -- no folder part, just return the file name
    return basename(norm):lower()
end

local function find_in_discord(processes)
    local detectable = fetch_discord_detectable()
    if not detectable or not discord_index then
        return nil
    end

    local by_exe   = discord_index.by_exe   or {}
    local by_alias = discord_index.by_alias or {}

    -- Build candidate process list (non-ignored only)
    local proc_list = {}
    for _, proc in ipairs(processes) do
        local name_for_ignore = proc.key or proc.exe
        if not process_is_ignored_proc(proc) then
            local base = basename(proc.exe or name_for_ignore)
            local norm = normalize_for_match(base)
            local item = {
                raw  = name_for_ignore,  -- usually "Folder/file.exe"
                exe  = proc.exe,         -- plain exe, e.g. "Engine.exe"
                norm = norm,             -- normalized exe name, e.g. "engine"
            }
            table.insert(proc_list, item)
            log(LOG_DEBUG, string.format(
                "Discord candidate process: raw='%s', exe='%s', norm='%s'",
                name_for_ignore, proc.exe or "?", norm
            ))
        else
            log(LOG_DEBUG, "Discord: skipped ignored process: " .. name_for_ignore)
        end
    end

    ----------------------------------------------------------------
    -- 1) Try exe-based matches via index, but disambiguate by path
    ----------------------------------------------------------------
    for _, p in ipairs(proc_list) do
        local list = by_exe[p.norm]
        if list and #list > 0 then
            local chosen = nil

            if #list == 1 then
                -- Only one Discord app uses this exe name -> safe to use
                chosen = list[1]
            else
                -- Multiple Discord apps share the same exe name (e.g. Engine.exe).
                -- Try to disambiguate via path/folder.
                local p_key_l = (p.raw or p.exe or ""):gsub("\\", "/"):lower()

                local candidates = {}
                for _, entry in ipairs(list) do
                    local discord_key = discord_exe_to_key(entry.exe_raw)
                    if discord_key and discord_key ~= "" then
                        -- Example:
                        --   p_key_l     = "some other game/engine.exe"
                        --   discord_key = "gotham impostors/engine.exe"
                        --
                        -- They must match to be considered the same game.
                        if p_key_l == discord_key then
                            table.insert(candidates, entry)
                        end
                    end
                end

                if #candidates == 1 then
                    chosen = candidates[1]
                elseif #candidates > 1 then
                    -- Very unlikely, but pick the first if multiple path matches exist.
                    chosen = candidates[1]
                    log(LOG_DEBUG, string.format(
                        "Discord executable '%s' has multiple path matches for process '%s'; using first match.",
                        p.norm, p.raw or p.exe or "?"
                    ))
                else
                    -- Ambiguous exe name and no path match -> treat as unknown.
                    log(LOG_DEBUG, string.format(
                        "Discord executable '%s' is used by multiple apps but none match path '%s'; skipping Discord match.",
                        p.norm, p.raw or p.exe or "?"
                    ))
                    -- Do NOT return here; just move on to the next process.
                end
            end

            if chosen then
                local app      = detectable[chosen.app_index]
                local app_name = app and app.name or "<unknown>"

                -- Prefer bare executable name for the mapping entry
                local proc_name = chosen.exe_base or basename(p.exe or p.raw or "")

                log(LOG_INFO, string.format(
                    "Discord executable match via index: process='%s' <-> app='%s' (exe='%s', stored as '%s')",
                    p.raw, app_name, chosen.exe_raw or "?", proc_name
                ))

                return {
                    id               = tostring(app.id or "0"),
                    processes        = { proc_name },
                    twitch_game_name = app_name,
                    title            = app_name,
                    tags             = { "Gaming" },
                }
            end
        end
    end

    ----------------------------------------------------------------
    -- 2) Try alias/name-based matches
    ----------------------------------------------------------------
    for _, p in ipairs(proc_list) do
        local list = by_alias[p.norm]
        if list and #list > 0 then
            local entry = list[1]
            local app   = detectable[entry.app_index]
            local app_name = app and app.name or "<unknown>"

            log(LOG_INFO, string.format(
                "Discord alias/name match via index: process='%s' <-> app='%s' (via %s '%s')",
                p.raw, app_name, entry.source or "alias", entry.alias or "?"
            ))

            return {
                id               = tostring(app.id or "0"),
                processes        = { p.raw },
                twitch_game_name = app_name,
                title            = app_name,
                tags             = { "Gaming" },
            }
        end
    end

    log(LOG_INFO, "No Discord detectable match found for any process")
    return nil
end


-----------------------------------------------------
-- APPLY RULE / BACKPORTING
-----------------------------------------------------

local function build_stream_title(game_name, base_title)
    local title = base_title or ""
    if title == "" and game_name and game_name ~= "" then
        title = "Playing " .. game_name
    end

    -- Just the raw (cleaned uop/trimmed) title in case of non-pattern usage
    if not use_pattern then
        local result = (title or ""):gsub("%s+", " ")
        result = result:gsub("^%s+", "")
        result = result:gsub("%s+$", "")
        if result == "" then
            result = title
        end
        return result
    end

    -- Replace placeholders with actual values
    local prefix    = title_prefix    or ""
    local suffix    = title_suffix    or ""
    local delimiter = title_delimiter or ""
    local pattern   = title_pattern   or "{prefix}{delimiter}{title}{delimiter}{suffix}"

    log(LOG_DEBUG, string.format(
        "Building stream title | game: %s, base: %s, pref: %s, suff: %s, delim: %s, patt: %s",
        tostring(game_name), tostring(base_title), prefix, suffix, delimiter, pattern
    ))

    local result = pattern

    -- Replace Placeholders
    result = result:gsub("{prefix}",    prefix)
    result = result:gsub("{suffix}",    suffix)
    result = result:gsub("{delim}",     delimiter)
    result = result:gsub("{delimiter}", delimiter)
    result = result:gsub("{game}",      game_name or "")
    result = result:gsub("{title}",     title)

    -- Little cleanup (e.g. remove double spaces)
    result = result:gsub("%s+", " ")
    result = result:gsub("^%s+", "")
    result = result:gsub("%s+$", "")

    -- if still empty, fallback to just the title
    if result == "" then
        result = title
    end

    return result
end


local function build_tags_for_rule(rule)
    local tags = {}

    for _, t in ipairs(mappings.global_tags or {}) do
        table.insert(tags, t)
    end
    for _, t in ipairs(rule.tags or {}) do
        table.insert(tags, t)
    end

    return tags
end

local function tags_equal(a, b)
    if a == b then return true end
    a = a or {}
    b = b or {}
    if #a ~= #b then return false end
    for i = 1, #a do
        if a[i] ~= b[i] then
            return false
        end
    end
    return true
end


-- Try to strip prefix / delimiter / suffix from a fully formatted title
-- so we can store only the "base" rule title in the mapping.
local function extract_base_title_from_full(full_title)
    local base = full_title or ""
    if base == "" then
        return base
    end

    -- No pattern? Just trimm title and post
    if not use_pattern then
        base = base:gsub("^%s+", ""):gsub("%s+$", "")
        return base
    end

    local prefix    = title_prefix    or ""
    local suffix    = title_suffix    or ""
    local delimiter = title_delimiter or ""

    local result = base
    -- Outer trim
    result = result:gsub("^%s+", ""):gsub("%s+$", "")

    -- 1) remove prefix (and possible delimiter)
    if prefix ~= "" and result:sub(1, #prefix) == prefix then
        result = result:sub(#prefix + 1)
        if delimiter ~= "" then
            local patt = "^" .. escape_lua_pattern(delimiter)
            result = result:gsub(patt, "", 1)
        end
    end

    -- 2) Remove suffix (and possibly delimiter)
    if suffix ~= "" and #result >= #suffix and result:sub(-#suffix) == suffix then
        result = result:sub(1, #result - #suffix)
        if delimiter ~= "" then
            local patt = escape_lua_pattern(delimiter) .. "$"
            result = result:gsub(patt, "", 1)
        end
    end

    -- final cleanup
    result = result:gsub("%s+", " ")
    result = result:gsub("^%s+", ""):gsub("%s+$", "")

    return result
end


local function backport_rule(rule)
    if not rule then return end
    if (not backport_title) and (not backport_tags) then
        return
    end

    local max_attempts = 3
    local info = nil

    for attempt = 1, max_attempts do
        info = twitch_get_channel_info()
        if info then
            break
        end

        log(LOG_ERROR, string.format(
            "Backport: failed to fetch channel info (attempt %d/%d), retrying.",
            attempt, max_attempts
        ))
    end

    if not info then
        log(LOG_ERROR, "Backport: giving up after multiple failed attempts to fetch channel info.")
        return
    end

    local changed = false

    -- Backport title
    if backport_title and info.title and info.title ~= rule.title then
        local new_title = extract_base_title_from_full(info.title)

        log(LOG_INFO, string.format(
            "Backporting title from Twitch to rule '%s': '%s' -> '%s' (stored base title: '%s')",
            rule.id or "?", tostring(rule.title), info.title, new_title
        ))

        rule.title      = new_title
        -- last_set_title nil -> next run will build title froms cratch
        last_set_title  = nil
        changed         = true
    end

    -- Backport tags (but keep global_tags out of per-game tags)
    if backport_tags and info.tags then
        local current_tags = info.tags or {}

        local global_lookup = {}
        for _, gt in ipairs(mappings.global_tags or {}) do
            global_lookup[gt] = true
        end

        local per_game_tags = {}
        for _, t in ipairs(current_tags) do
            if not global_lookup[t] then
                table.insert(per_game_tags, t)
            end
        end

        if not tags_equal(rule.tags, per_game_tags) then
            log(LOG_INFO, string.format(
                "Backporting tags from Twitch to rule '%s'",
                rule.id or "?"
            ))
            rule.tags = {}
            for _, t in ipairs(per_game_tags) do
                table.insert(rule.tags, t)
            end

            build_tags_for_rule(rule)
            changed       = true
        end
    end

    if changed then
        if rule.id=="just_chatting" then
            mappings.just_chatting.title = rule.title
            mappings.tags               = rule.tags
        end
        save_mappings()
    end
end


local function apply_rule(rule)
    local game_name  = rule.twitch_game_name or "Just Chatting"
    local base_title = rule.title or ("Playing " .. game_name)
    local title      = build_stream_title(game_name, base_title)
    local tags       = build_tags_for_rule(rule)

    -- If nothing changed compared to the last applied values, skip the Twitch update.
    if last_set_game
        and last_set_game  == game_name
        and last_set_title == title
        and tags_equal(last_set_tags, tags)
    then
        log(LOG_INFO, string.format(
            "Rule '%s' would set the same game/title/tags as last time; skipping Twitch update.",
            rule.id or "?"
        ))
        return
    end

	-- Backport latest Tags and title
	backport_rule(last_applied_rule)
    
	-- Actually update Twitch
	local success = nil
	for attempt = 1, 3 do
		success = twitch_update_stream(game_name, title, tags)
        if success then
			break
        end
    end

	if success then
		-- Update local state
		last_applied_rule = rule
		last_set_game     = game_name
		last_set_title    = title
		last_set_tags     = tags
	end
end


-----------------------------------------------------
-- MERGE / REGISTER RULES (Discord)
-----------------------------------------------------

local function merge_or_add_rule(new_rule)
    if not new_rule or not new_rule.id then
        return new_rule
    end

    mappings.rules = mappings.rules or {}

    -- Try to find existing rule with the same ID
    for _, r in ipairs(mappings.rules) do
        if r.id == new_rule.id then
            -- Merge processes case-insensitively
            r.processes = r.processes or {}
            local existing = {}

            for _, p in ipairs(r.processes) do
                existing[string.lower(p)] = true
            end

            for _, p in ipairs(new_rule.processes or {}) do
                local lp = string.lower(p)
                if not existing[lp] then
                    table.insert(r.processes, p)
                    existing[lp] = true
                    log(LOG_INFO, string.format(
                        "Merged new process '%s' into existing rule '%s'.",
                        p, r.id or "?"
                    ))
                end
            end

            -- Keep existing title/tags/twitch_game_name (no override).
            return r
        end
    end

    -- No existing rule with same ID found: append as new rule
    table.insert(mappings.rules, new_rule)
    log(LOG_INFO, string.format(
        "Registered new rule with id '%s' (new rule).",
        new_rule.id
    ))
    return new_rule
end

-----------------------------------------------------
-- MAIN EXECUTION
-----------------------------------------------------

local function execute_once()
    load_mappings()
    if not mappings then
        log(LOG_ERROR, "Mappings not available; aborting tick")
        return
    end

    log(LOG_INFO, "=== AutoCategory tick starting ===")
    local processes = scan_processes()

    if #processes == 0 then
        log(LOG_ERROR, "No processes found; skipping logic")
        return
    end

    local rule = find_rule(processes)
    if rule then
        log(LOG_DEBUG, "Applying mapped rule: " .. (rule.id or "unknown"))
        apply_rule(rule)
        log(LOG_INFO, "=== AutoCategory tick done (rule matched) ===")
        return
    end

    log(LOG_DEBUG, "No mapping rule matched; checking Discord detectable apps (indexed)...")
    local d_rule = find_in_discord(processes)
    if d_rule then
        log(LOG_INFO, "Applying Discord-detected rule: " .. d_rule.id)
        local merged = merge_or_add_rule(d_rule)
        save_mappings()
        apply_rule(merged)
        log(LOG_INFO, "=== AutoCategory tick done (Discord matched) ===")
        return
    end

    log(LOG_INFO, "No process matched; updating cfg.unknown and falling back to Just Chatting...")
    update_unknown_bucket(processes)

    local jc = mappings.just_chatting or {
        twitch_game_name = "Just Chatting",
        title = "Just chatting",
        tags = { "Chatting" }
    }
	mappings.just_chatting=jc
	
    local jc_rule = {
        id               = "just_chatting",
        processes        = {},
        twitch_game_name = jc.twitch_game_name,
        title            = jc.title,
        tags             = jc.tags or {}
    }

    apply_rule(jc_rule)
    log(LOG_INFO, "=== AutoCategory tick done (Just Chatting fallback) ===")
end

-----------------------------------------------------
-- TIMER HANDLER
-----------------------------------------------------

local function on_timer()
    execute_once()
end

-----------------------------------------------------
-- OBS SCRIPT INTERFACE
-----------------------------------------------------

-- Small helper so we do not repeat the tooltip call everywhere.
local function set_tooltip(prop, text)
    if prop ~= nil then
        obs.obs_property_set_long_description(prop, text)
    end
end


function script_description()
    return [[
Automatic Twitch Category / Title / Tags switcher for Twitch (Windows only).

On every tick the script scans your running Windows processes and tries to match them against rules in "game_mappings.lua" (Will be created if not existent).
It falls back to discords "detectable applications"-API if neededand sends an update to /helix/channels for your broadcaster_id.

If backporting is enabled, it also pulls the title/tags from Twitch directly on next game switch and stores the latest data.
(For when you manually adjusted them after auto category set them already)

There is a full step by step setup guide for required tokens and IDs in the header comments at the top of this file.

Notes:
- If multiple rules match different processes, the first successful onewins. (Make your rules as specific as you need.)
- Polling too often and/or logging too much can spam your log and also annoy the Twitch API. Try to stay at ≥ 2 seconds when auto polling. (≥ 5 seconds recommended)
]]
end


function script_defaults(settings)
    -- Logging / Polling
    obs.obs_data_set_default_int(settings,  "log_level",        LOG_INFO)
    obs.obs_data_set_default_bool(settings, "auto_polling",     false)
    obs.obs_data_set_default_int(settings,  "poll_interval_ms", poll_interval_ms)

    -- Title pattern defaults
    obs.obs_data_set_default_bool(settings,  "use_pattern",      false)
    obs.obs_data_set_default_string(settings, "title_prefix",    "")
    obs.obs_data_set_default_string(settings, "title_suffix",    "")
    obs.obs_data_set_default_string(settings, "title_delimiter", " | ")
    obs.obs_data_set_default_string(settings, "title_pattern",   "{prefix}{delimiter}{title}{delimiter}{suffix}")

    -- Backport defaults
    obs.obs_data_set_default_bool(settings, "backport_title", true)
    obs.obs_data_set_default_bool(settings, "backport_tags",  true)
end


function script_properties()
    local props = obs.obs_properties_create()

    -------------------------------------------------
    -- Twitch auth / identity
    -------------------------------------------------
    local client_id_prop = obs.obs_properties_add_text(
        props,
        "client_id",
        "Twitch Client ID",
        obs.OBS_TEXT_DEFAULT
    )
    set_tooltip(client_id_prop, "Client ID of your Twitch application from dev.twitch.tv.")

    local oauth_prop = obs.obs_properties_add_text(
        props,
        "oauth",
        "Twitch OAuth Token",
        obs.OBS_TEXT_PASSWORD
    )
    set_tooltip(oauth_prop, "Access token with channel:manage:broadcast scope. Used for Twitch API calls.")

    local broadcaster_prop = obs.obs_properties_add_text(
        props,
        "broadcaster_id",
        "Twitch Broadcaster ID",
        obs.OBS_TEXT_DEFAULT
    )
    set_tooltip(broadcaster_prop, "Your numeric Twitch user ID (not your username).")

    local client_secret_prop = obs.obs_properties_add_text(
        props,
        "client_secret",
        "Twitch Client Secret",
        obs.OBS_TEXT_PASSWORD
    )
    set_tooltip(client_secret_prop, "Client Secret that belongs to the Client ID. Needed for token refresh.")

    local refresh_token_prop = obs.obs_properties_add_text(
        props,
        "refresh_token",
        "Twitch Refresh Token",
        obs.OBS_TEXT_PASSWORD
    )
    set_tooltip(refresh_token_prop, "Long‑lived refresh_token used to automatically refresh the OAuth token.")

    -------------------------------------------------
    -- Logging / polling
    -------------------------------------------------
    local log_prop = obs.obs_properties_add_list(
        props,
        "log_level",
        "Log Level",
        obs.OBS_COMBO_TYPE_LIST,
        obs.OBS_COMBO_FORMAT_INT
    )
    obs.obs_property_list_add_int(log_prop, "Off",   LOG_OFF)
    obs.obs_property_list_add_int(log_prop, "Error", LOG_ERROR)
    obs.obs_property_list_add_int(log_prop, "Info",  LOG_INFO)
    obs.obs_property_list_add_int(log_prop, "Debug", LOG_DEBUG)
    obs.obs_property_list_add_int(log_prop, "Trace", LOG_TRACE)
    set_tooltip(log_prop, "How chatty the script should be in the OBS log. Use Debug/Info while testing, Error/Off for normal use.")

    local auto_polling_prop = obs.obs_properties_add_bool(
        props,
        "auto_polling",
        "Enable Auto Polling"
    )
    set_tooltip(auto_polling_prop, "If enabled, the script will run automatically on a timer. If disabled, use the 'Execute Once' button.")

    local interval_prop = obs.obs_properties_add_int(
        props,
        "poll_interval_ms",
        "Polling Interval (ms)",
        1000, 60000, 1000
    )
    set_tooltip(interval_prop, "How often to scan processes and update Twitch while auto polling is enabled. Keep this at or above 2000 ms.")

    local exec_prop = obs.obs_properties_add_button(
        props,
        "exec_once",
        "Execute Once",
        function()
            execute_once()
            return true
        end
    )
    set_tooltip(exec_prop, "Run one detection + Twitch update cycle right now.")

    -- Toggle visibility of polling fields depending on auto_polling
    obs.obs_property_set_visible(interval_prop, auto_polling)
    obs.obs_property_set_visible(exec_prop, not auto_polling)

    local function auto_polling_modified(props_inner, prop, settings)
        local ap = obs.obs_data_get_bool(settings, "auto_polling")
        obs.obs_property_set_visible(interval_prop, ap)
        obs.obs_property_set_visible(exec_prop, not ap)
        return true
    end
    obs.obs_property_set_modified_callback(
        obs.obs_properties_get(props, "auto_polling"),
        auto_polling_modified
    )

    -------------------------------------------------
    -- Mapping file helper
    -------------------------------------------------
    local open_mappings_prop = obs.obs_properties_add_button(
        props,
        "open_mappings",
        "Open Mapping File",
        function()
            os.execute(string.format('start "" "%s"', map_file_path))
            return true
        end
    )
    set_tooltip(open_mappings_prop, "Open game_mappings.lua in your default editor. This is where the rules live.")

    -------------------------------------------------
    -- Title pattern options
    -------------------------------------------------
    local use_pattern_prop = obs.obs_properties_add_bool(
        props,
        "use_pattern",
        "Use Title Pattern"
    )
    set_tooltip(use_pattern_prop, "Enable this to build the Twitch title from prefix/title/suffix using the pattern below.")

    local prefix_prop = obs.obs_properties_add_text(
        props,
        "title_prefix",
        "Title Prefix",
        obs.OBS_TEXT_DEFAULT
    )
    set_tooltip(prefix_prop, "Optional static text that will be placed before the base rule title.")

    local suffix_prop = obs.obs_properties_add_text(
        props,
        "title_suffix",
        "Title Suffix",
        obs.OBS_TEXT_DEFAULT
    )
    set_tooltip(suffix_prop, "Optional static text that will be placed after the base rule title.")

    local delimiter_prop = obs.obs_properties_add_text(
        props,
        "title_delimiter",
        "Title Delimiter",
        obs.OBS_TEXT_DEFAULT
    )
    set_tooltip(delimiter_prop, "Text that separates prefix, base title and suffix (for example: ' | ').")

    local pattern_prop = obs.obs_properties_add_text(
        props,
        "title_pattern",
        "Title Pattern",
        obs.OBS_TEXT_DEFAULT
    )
    set_tooltip(pattern_prop, "Pattern for building the final title. Use {prefix}, {suffix}, {delimiter}, {title} and {game} as placeholders.")

    local function use_pattern_modified(props_inner, prop, settings)
        local up = obs.obs_data_get_bool(settings, "use_pattern")
        obs.obs_property_set_visible(prefix_prop,    up)
        obs.obs_property_set_visible(suffix_prop,    up)
        obs.obs_property_set_visible(delimiter_prop, up)
        obs.obs_property_set_visible(pattern_prop,   up)
        return true
    end
    obs.obs_property_set_modified_callback(
        use_pattern_prop,
        use_pattern_modified
    )

    -- Initialize visibility based on current state on load
    obs.obs_property_set_visible(prefix_prop,    use_pattern)
    obs.obs_property_set_visible(suffix_prop,    use_pattern)
    obs.obs_property_set_visible(delimiter_prop, use_pattern)
    obs.obs_property_set_visible(pattern_prop,   use_pattern)

    -------------------------------------------------
    -- Backport options
    -------------------------------------------------
    local backport_title_prop = obs.obs_properties_add_bool(
        props,
        "backport_title",
        "Backport Stream Title"
    )
    set_tooltip(backport_title_prop, "If enabled, the script will occasionally read the live Twitch title and write it back into the matching rule.")

    local backport_tags_prop = obs.obs_properties_add_bool(
        props,
        "backport_tags",
        "Backport Tags"
    )
    set_tooltip(backport_tags_prop, "If enabled, the script will occasionally read the live Twitch tags and write them back into the matching rule.")

    return props
end

function script_update(settings)
    twitch_client_id      = obs.obs_data_get_string(settings, "client_id")
    twitch_oauth          = obs.obs_data_get_string(settings, "oauth")
    twitch_broadcaster_id = obs.obs_data_get_string(settings, "broadcaster_id")
    twitch_client_secret  = obs.obs_data_get_string(settings, "client_secret")
    twitch_refresh_token  = obs.obs_data_get_string(settings, "refresh_token")

    log_level             = obs.obs_data_get_int(settings,  "log_level")
    auto_polling          = obs.obs_data_get_bool(settings, "auto_polling")
    poll_interval_ms      = obs.obs_data_get_int(settings,  "poll_interval_ms")

    -- Title pattern configuration
    use_pattern           = obs.obs_data_get_bool(settings,  "use_pattern")
    title_prefix          = obs.obs_data_get_string(settings, "title_prefix")
    title_suffix          = obs.obs_data_get_string(settings, "title_suffix")
    title_delimiter       = obs.obs_data_get_string(settings, "title_delimiter")
    title_pattern         = obs.obs_data_get_string(settings, "title_pattern")

    -- Simple fallback defaults in case OBS returns empty strings
    if title_delimiter == nil or title_delimiter == "" then
        title_delimiter = " | "
    end
    if title_pattern == nil or title_pattern == "" then
        title_pattern = "{prefix}{delimiter}{title}{delimiter}{suffix}"
    end

    backport_title        = obs.obs_data_get_bool(settings, "backport_title")
    backport_tags         = obs.obs_data_get_bool(settings, "backport_tags")

    log(LOG_DEBUG, string.format(
        "Settings updated (auto_polling=%s, interval=%d ms, log_level=%d, use_pattern=%s, pattern=%s)",
        tostring(auto_polling),
        poll_interval_ms,
        log_level,
        tostring(use_pattern),
        tostring(title_pattern)
    ))

    -- Reset last-set cache so changes to the pattern / title handling
    -- trigger a fresh update on the next rule application.
    last_set_game  = nil
    last_set_title = nil
    last_set_tags  = nil

    if auto_polling then
        obs.timer_remove(on_timer)
        obs.timer_add(on_timer, poll_interval_ms)
        timer_active = true
        log(LOG_INFO, "Auto polling enabled")
    else
        if timer_active then
            obs.timer_remove(on_timer)
            log(LOG_INFO, "Auto polling disabled")
        end
        timer_active = false
    end

end

function script_load(settings)
    log(LOG_INFO, "Script loaded; initializing mappings...")
    load_mappings()
end
