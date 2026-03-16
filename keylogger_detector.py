import os
import sys
import time
import ctypes
import winreg
import datetime
import psutil

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
RESET  = "\033[0m"


def print_banner():
    print(CYAN)
    print("=" * 55)
    print("   Keylogger Detection Tool - Windows")
    print("   made by gajanan")
    print("=" * 55)
    print(RESET)


def show(level, msg):
    if level == "HIGH":
        print(f"  {RED}[HIGH]    {msg}{RESET}")
    elif level == "MED":
        print(f"  {YELLOW}[MEDIUM]  {msg}{RESET}")
    elif level == "LOW":
        print(f"  {GREEN}[LOW]     {msg}{RESET}")
    else:
        print(f"  {CYAN}[INFO]    {msg}{RESET}")


def divider(title):
    print(f"\n{BLUE}--- {title} ---{RESET}\n")


# check 1
# keyloggers on windows install a keyboard hook using SetWindowsHookEx
# to do that the process needs user32.dll loaded
# so we find non system processes that have it loaded
def check1_keyboard_hooks():
    divider("CHECK 1 - Keyboard Hook Detection")

    show("INFO", "scanning processes for keyboard hook capability...")

    kernel32 = ctypes.windll.kernel32
    flagged = []

    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            pid  = proc.info["pid"]
            name = proc.info["name"]
            exe  = proc.info["exe"] or ""

            handle = kernel32.OpenProcess(0x0410, False, pid)
            if not handle:
                continue

            try:
                p = psutil.Process(pid)
                mods = p.memory_maps()
                mod_names = [os.path.basename(m.path).lower() for m in mods]

                if "user32.dll" in mod_names:
                    # skip windows system stuff
                    if "system32" not in exe.lower() and "syswow64" not in exe.lower():
                        flagged.append((pid, name, exe))
            except Exception:
                pass

            kernel32.CloseHandle(handle)

        except Exception:
            continue

    if flagged:
        show("MED", f"found {len(flagged)} non-system process(es) with hook capability:")
        for pid, name, exe in flagged[:15]:
            show("MED", f"  pid {pid}  |  {name}  |  {exe}")
        show("INFO", "note - this doesnt mean they ARE keyloggers, just that they could be")
    else:
        show("LOW", "nothing suspicious found in hook check")


# check 2
# look for processes with known keylogger names
# also check if anything is running from temp or downloads
# legit software doesnt usually run from those folders
def check2_suspicious_processes():
    divider("CHECK 2 - Suspicious Process Names and Locations")

    bad_names = [
        "keylog", "spyware", "spy", "hookdump", "ratool",
        "ardamax", "revealer", "refog", "kidlogger",
        "pykeylogger", "winhook", "logkeys", "allinhack"
    ]

    # places where legit software doesnt usually run from
    bad_paths = [
        os.environ.get("TEMP", "").lower(),
        os.path.join(os.environ.get("APPDATA", ""), "").lower(),
        os.path.join(os.environ.get("USERPROFILE", ""), "downloads").lower(),
    ]

    by_name = []
    by_path = []

    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            name = (proc.info["name"] or "").lower()
            exe  = (proc.info["exe"]  or "").lower()

            for bad in bad_names:
                if bad in name:
                    by_name.append((proc.pid, proc.info["name"], exe))
                    break

            for bp in bad_paths:
                if bp and exe.startswith(bp):
                    by_path.append((proc.pid, proc.info["name"], exe))
                    break

        except Exception:
            continue

    if by_name:
        show("HIGH", f"processes with sketchy names ({len(by_name)} found):")
        for pid, name, exe in by_name:
            show("HIGH", f"  pid {pid}  |  {name}  |  {exe}")
    else:
        show("LOW", "no processes with known keylogger names")

    if by_path:
        show("MED", f"processes running from temp/downloads ({len(by_path)} found):")
        for pid, name, exe in by_path:
            show("MED", f"  pid {pid}  |  {name}  |  {exe}")
    else:
        show("LOW", "nothing running from suspicious locations")


# check 3
# keyloggers need to survive reboots so they write to registry autorun keys
# we check the most common ones and flag anything pointing to temp
# or anything where the file doesnt even exist on disk anymore
def check3_registry():
    divider("CHECK 3 - Registry Autorun Keys")

    run_keys = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    bad_locations = ["temp", "appdata\\local\\temp", "downloads", "tmp"]

    total     = 0
    flagged   = []

    for hive, key_path in run_keys:
        hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    total += 1

                    value_lower = value.lower()
                    in_bad_spot = any(b in value_lower for b in bad_locations)

                    # try to get the actual exe path and check it exists
                    exe_path = value.strip('"').split('"')[0].split(" ")[0]
                    exists   = os.path.exists(exe_path)

                    if in_bad_spot or not exists:
                        reasons = []
                        if in_bad_spot: reasons.append("running from temp folder")
                        if not exists:  reasons.append("file doesnt exist on disk")
                        flagged.append({
                            "hive":   hive_name,
                            "name":   name,
                            "value":  value,
                            "why":    ", ".join(reasons)
                        })

                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            continue

    show("INFO", f"scanned {total} autorun entries total")

    if flagged:
        show("HIGH", f"suspicious autorun entries ({len(flagged)} found):")
        for f in flagged:
            show("HIGH", f"  [{f['hive']}] {f['name']}")
            show("HIGH", f"    value  : {f['value'][:80]}")
            show("HIGH", f"    reason : {f['why']}")
    else:
        show("LOW", "no dodgy autorun registry entries found")


# check 4
# keyloggers save what they record to a file somewhere
# we look for hidden files with log extensions in user folders
# also flag anything with a .klg or .keylog extension - very suspicious
def check4_hidden_files():
    divider("CHECK 4 - Hidden Log Files")

    scan_these = [
        os.environ.get("TEMP", ""),
        os.environ.get("APPDATA", ""),
        os.environ.get("LOCALAPPDATA", ""),
        os.environ.get("USERPROFILE", ""),
    ]

    log_exts  = {".txt", ".log", ".dat", ".kl", ".klg", ".keylog"}
    now       = time.time()
    one_day   = 86400

    hidden_found = []
    recent_found = []

    for folder in scan_these:
        if not folder or not os.path.exists(folder):
            continue
        try:
            for root, dirs, files in os.walk(folder):
                # dont go too deep or itll take forever
                depth = root.replace(folder, "").count(os.sep)
                if depth > 3:
                    dirs[:] = []
                    continue

                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        ext = os.path.splitext(fname)[1].lower()

                        # check windows hidden attribute
                        attrs = ctypes.windll.kernel32.GetFileAttributesW(fpath)
                        is_hidden = bool(attrs & 2) if attrs != -1 else False

                        mtime     = os.path.getmtime(fpath)
                        is_recent = (now - mtime) < one_day
                        has_size  = os.path.getsize(fpath) > 0

                        if is_hidden and ext in log_exts:
                            hidden_found.append(fpath)

                        if is_recent and ext in log_exts and has_size:
                            recent_found.append(
                                (fpath, datetime.datetime.fromtimestamp(mtime))
                            )

                    except Exception:
                        continue
        except Exception:
            continue

    if hidden_found:
        show("HIGH", f"hidden log files found ({len(hidden_found)}):")
        for f in hidden_found[:10]:
            show("HIGH", f"  {f}")
    else:
        show("LOW", "no hidden log files found")

    if recent_found:
        show("MED", f"recently changed log files ({len(recent_found)}):")
        for path, mtime in recent_found[:10]:
            show("MED", f"  [{mtime.strftime('%H:%M')}]  {path}")
    else:
        show("LOW", "no recently modified suspicious files")


# check 5
# if a keylogger is running it needs to send the data somewhere
# we check outbound connections for known bad ports
# like 4444 which metasploit uses, 1337, 31337 etc
def check5_network():
    divider("CHECK 5 - Network Connections")

    normal_ports  = {80, 443, 53, 8080, 8443, 22, 25, 587, 993, 995, 143}
    sketchy_ports = {1337, 4444, 5555, 6666, 7777, 8888, 9999, 31337, 1234, 12345}

    flagged   = []
    total_out = 0

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                ip   = conn.raddr.ip
                port = conn.raddr.port

                # skip localhost
                if ip.startswith("127.") or ip == "::1":
                    continue

                total_out += 1

                try:
                    p    = psutil.Process(conn.pid) if conn.pid else None
                    pname = p.name() if p else "unknown"
                    pexe  = p.exe()  if p else ""
                except Exception:
                    pname = "unknown"
                    pexe  = ""

                is_sketchy = port in sketchy_ports
                is_weird   = port not in normal_ports and port < 1024
                is_sys     = "system32" in pexe.lower() or "syswow64" in pexe.lower()

                if (is_sketchy or is_weird) and not is_sys:
                    flagged.append({
                        "pid":    conn.pid,
                        "name":   pname,
                        "ip":     ip,
                        "port":   port,
                        "reason": "known bad port" if is_sketchy else "weird non-standard port"
                    })

        show("INFO", f"total outbound connections: {total_out}")

        if flagged:
            show("HIGH", f"suspicious connections ({len(flagged)}):")
            for c in flagged:
                show("HIGH", f"  pid {c['pid']}  {c['name']}  ->  {c['ip']}:{c['port']}  ({c['reason']})")
        else:
            show("LOW", "no dodgy outbound connections found")

    except Exception as e:
        show("INFO", f"network scan error: {e}")


# check 6
# some keyloggers dont use hooks at all
# they just loop and call GetAsyncKeyState on every key really fast
# this causes the process to always use a small but consistent amount of cpu
# between 0.5 and 5 percent - not enough to notice but enough for us to catch
def check6_cpu():
    divider("CHECK 6 - CPU Polling Check")

    show("INFO", "sampling cpu for 3 seconds...")
    time.sleep(3)

    windows_system = {
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
        "explorer.exe", "spoolsv.exe", "taskhost.exe"
    }

    flagged = []

    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            name = (proc.info["name"] or "").lower()
            if name in windows_system:
                continue

            cpu = proc.cpu_percent(interval=1)

            # the sweet spot for polling keyloggers is 0.5 to 5 percent
            if 0.5 <= cpu <= 5.0:
                exe = proc.info.get("exe") or ""
                if "system32" not in exe.lower():
                    flagged.append((proc.pid, proc.info["name"], cpu, exe))

        except Exception:
            continue

    if flagged:
        show("MED", f"processes with suspicious background cpu usage ({len(flagged)}):")
        for pid, name, cpu, exe in sorted(flagged, key=lambda x: x[2], reverse=True)[:15]:
            show("MED", f"  pid {pid}  |  {name}  |  cpu {cpu:.1f}%")
        show("INFO", "could be legit apps too - cross check with other findings")
    else:
        show("LOW", "no suspicious cpu patterns found")


def print_summary(start):
    elapsed = round(time.time() - start, 2)
    print(f"\n{BLUE}--- DONE ---{RESET}\n")
    print(f"  {CYAN}finished in {elapsed} seconds{RESET}\n")
    print("  what to do if you got HIGH findings:")
    print("    1. open task manager > details > find the pid")
    print("    2. right click > open file location")
    print("    3. upload the exe to virustotal.com")
    print("    4. if registry entry is bad > delete it from regedit")
    print("    5. run a full antivirus scan to be safe\n")
    print(f"  {CYAN}defensive use only - gajanan raveendranathan{RESET}\n")


def main():
    if sys.platform != "win32":
        print(f"{RED}this tool only works on windows{RESET}")
        sys.exit(1)

    print_banner()
    start = time.time()

    print(f"  {CYAN}started  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"  {CYAN}user     : {os.environ.get('USERNAME', 'unknown')}{RESET}")
    print(f"  {CYAN}machine  : {os.environ.get('COMPUTERNAME', 'unknown')}{RESET}\n")

    check1_keyboard_hooks()
    check2_suspicious_processes()
    check3_registry()
    check4_hidden_files()
    check5_network()
    check6_cpu()
    print_summary(start)


if __name__ == "__main__":
    main()
