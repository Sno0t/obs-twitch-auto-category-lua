# Auto Twitch Category Switcher (OBS Lua Script)

## 🎮 Overview

**Auto Twitch Category Switcher** is an advanced OBS Lua script for **Windows**, designed to automatically adjust your **Twitch game/category**, **stream title**, and **tags** based on the currently running application on your system.

It provides:

- Process detection via WinAPI (no shell popups, no focus stealing)
- Rule-based mapping through `game_mappings.lua`
- Discord Detectable Applications fallback
- Optional title pattern builder (prefix/suffix/custom pattern)
- Automatic Twitch token refresh
- Backporting of title/tags into your rules
- One-shot or timed auto polling

---

## ✨ Features

### 🖥 Windows-native Process Detection (FFI)
Uses **LuaJIT FFI** to call WinAPI functions directly:

- `CreateToolhelp32Snapshot`
- `Process32FirstW`
- `Process32NextW`
- `QueryFullProcessImageNameW`

This eliminates:
- Shell windows that pop up every few seconds  
- Focus stealing  
- Localized command output issues  
- Slow process parsing from CLI tools  

### 🧩 Rule-based Mapping
Your rules are defined inside `game_mappings.lua`.  
Each rule can include:

- Executable name
- Folder filter
- Category override
- Title override
- Tags
- Optional default states

Unknown processes are added to `cfg.unknown` so you can quickly integrate them.

### 🔍 Discord Detectable Applications Fallback
If no rule matches:

1. Fetches Discord's detectable apps list (cached)
2. Performs fuzzy matching
3. Auto-generates new rules
4. Saves them into your mapping file

### 📝 Title Pattern Support
Supports placeholders:

```
{prefix}
{title}
{suffix}
{delimiter}
{game}
```

You can fully control how your final Twitch title is constructed.

### 🔄 Token Refresh Support
The script refreshes your Twitch token using your **refresh_token**:
- No manual reauthentication required
- Only needed again if you reset your Client Secret

### 🔧 OBS Properties With Tooltips
All UI fields inside OBS have descriptive tooltips to make setup easier.

---

## 📦 Why Custom JSON?

OBS Lua cannot install external modules.  
Many systems lack a JSON library or ship a broken one.

**Solution:**  
A lightweight custom JSON encoder/decoder is embedded.  
This ensures consistent behavior on every OBS installation without dependencies.

---

## ⚙️ Why FFI and WinAPI Instead of Shell Commands?

Other scripts use:

- `tasklist.exe`
- `wmic.exe`
- `powershell Get-Process`
- Hidden CMD shells

These cause:

- Window flashes  
- OBS losing window focus  
- Slow enumeration  
- Incorrect parsing on localized systems  

With FFI + WinAPI:
- Zero popups  
- Zero external processes  
- Better performance  
- Accurate Unicode paths  
- Native integration  

This is the cleanest, most stable approach for OBS + Lua.

---

## 🚀 Installation

### 1. Download the Files

Place these files in:

```
OBS/scripts/
```

- `auto_twitch_category.lua`
- `game_mappings.lua` (auto-created on first run)

### 2. Add Script to OBS

1. Open OBS  
2. Tools → Scripts  
3. Press **+**  
4. Select `auto_twitch_category.lua`  
5. Configure the script properties

---

## 🔑 Twitch Setup (Tokens & IDs)

Full instructions are in the script header.  
Short version:

### 1. Create a Twitch Application  
https://dev.twitch.tv/console/apps  

Collect:
- Client ID  
- Client Secret  

### 2. Obtain Authorization Code

Open:

```
https://id.twitch.tv/oauth2/authorize?client_id=YOUR_ID&redirect_uri=http://localhost&response_type=code&scope=channel:manage:broadcast
```

Copy code after `?code=`.

### 3. Exchange Code for Tokens

Run in browser console:

```js
fetch("https://id.twitch.tv/oauth2/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    client_id: "YOUR_CLIENT_ID",
    client_secret: "YOUR_CLIENT_SECRET",
    code: "THE_CODE",
    grant_type: "authorization_code",
    redirect_uri: "http://localhost"
  })
}).then(r => r.json()).then(console.log);
```

Copy:

- `access_token`
- `refresh_token`

### 4. Get Broadcaster ID

Use:

```
https://api.twitch.tv/helix/users?login=YOUR_USERNAME
```

### 5. Enter Everything in OBS Script Settings

| Field | Description |
|-------|-------------|
| Twitch Client ID | Your application Client ID |
| Twitch Client Secret | Needed for token refresh |
| Twitch OAuth Token | `access_token` |
| Twitch Refresh Token | `refresh_token` |
| Twitch Broadcaster ID | Your numeric Twitch ID |
| Auto Polling | Enables automatic detection loop |
| Polling Interval | Recommended 3000–5000 ms |
| Title Pattern Options | Prefix/suffix/delimiter/pattern builder |
| Backport Settings | Writes live data back to mappings |

---

## 📁 About `game_mappings.lua`

Contains:

- `cfg.global_tags`  
- `cfg.just_chatting`  
- `cfg.unknown` (auto-generated)  
- `cfg.rules` (your detection rules)

⚠️ **When the script saves mappings, these sections are fully rewritten.**  
Do **not** place comments inside those blocks.

Comments above them are safe.

---

## 🧪 Auto Polling vs Execute Once

### Execute Once
Runs detection + Twitch update exactly once.

### Auto Polling
Runs repeatedly at the defined interval.

Recommended:
```
Auto Polling: ON
Interval: 3000–5000 ms
```

---

## 📝 Changelog (Excerpt)

```
2025.11.18    M.Stahl    - Initial version
2025.11.19    M.Stahl    - Added fuzzy search + unicode-safe Twitch name handling
2025.11.20    M.Stahl    - Added title pattern options, tooltips, and full header documentation
```

---

## 🤝 Contributing

PRs are welcome — feel free to improve:

- Fuzzy matching  
- WinAPI detection  
- Title pattern logic  
- Twitch API handling  
- Mapping helper logic 
- Linux support (as in, create one, because currently only windows is supported) 

---

## ❤️ Special Thanks

Thanks to *OpenAI*'s *ChatGPT* for making the documentation and Readme as i ABSOLUTELY hate these. (And also for support on some of the stuff that was completely new for me, e.g. FFI)

---

## 📜 License

MIT License  
Use freely for personal or commercial purposes.
