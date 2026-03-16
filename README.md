# keylogger detection tool - windows

i made this as part of my cybersecurity research to understand how keyloggers work on windows
and then build something that can actually detect them. the idea was simple - if i know how
they attack, i can figure out how to catch them.

runs on windows 10 and 11. python 3.8 or higher.

---

## what it does

basically scans your windows system and checks 6 things that keyloggers tend to leave behind
or need to function. it doesnt touch anything, just reads and reports.

**check 1 - keyboard hook detection**
keyloggers use a windows api called SetWindowsHookEx to intercept keystrokes before they reach
any app. to do that they need user32.dll loaded in their process. so i check which non-system
processes have that dll loaded - those are the ones capable of hooking keyboards.

**check 2 - suspicious process names and locations**
cross checks all running processes against a list of known keylogger software names.
also flags anything running from temp or downloads folders because legit software doesnt
usually run from there.

**check 3 - registry autorun keys**
keyloggers need to survive reboots so they write themselves to the windows registry run keys.
i scan HKCU and HKLM run and runonce keys and flag anything pointing to temp folders or
where the file doesnt even exist on disk anymore.

**check 4 - hidden log files**
whatever a keylogger captures has to be saved somewhere. i scan user directories for hidden
files with extensions like .log .dat .klg .keylog that were recently modified. those are
classic keylogger output files.

**check 5 - network connections**
once a keylogger has data it needs to send it somewhere. i check all active outbound
connections for known bad ports like 4444 (metasploit default), 1337, 31337 and other
non-standard ports that could be c2 traffic.

**check 6 - cpu polling**
some keyloggers skip hooks entirely and just call GetAsyncKeyState in a loop checking every
key really fast. this causes a consistent low cpu usage between 0.5 and 5 percent. not
enough to notice normally but enough to catch if youre looking for it.

---

## how to run it

first install the dependency:
```
pip install psutil
pip install pywin32
```

then just run it:
```
python keylogger_detector.py
```

for best results run as administrator so it can access all process info and network
connections. some checks will be limited without it.

---

## output explained

```
[HIGH]    something needs immediate attention
[MEDIUM]  worth looking into, might be fine
[LOW]     nothing suspicious here
[INFO]    just information
```

if you get a HIGH finding:
1. open task manager, go to details tab, find the pid it mentioned
2. right click the process and click open file location
3. upload that file to virustotal.com and check it
4. if its a registry entry thats bad, open regedit and delete it
5. run a full antivirus scan just to be safe

---

## what i learned from building this

the most interesting part was understanding that there are actually two different ways
keyloggers work on windows. the hook method using SetWindowsHookEx is more powerful because
it catches everything system wide. but the polling method using GetAsyncKeyState is simpler
to write and harder to detect because it looks like any normal background process.

the registry check was eye opening too - i didnt realise how many legitimate programs also
use those run keys. so the tool has to be smart about what it flags and why, not just
dump everything.

---

## stuff to note

- this is for defensive research and learning only
- only run it on your own machine or one you have permission to test
- some checks might flag legitimate apps especially the hook and cpu ones
- always cross check findings with each other before assuming something is malicious
- the network check works better with admin privileges

---

## built with

- python 3.11
- psutil - for process and network inspection
- winreg - for reading windows registry
- ctypes - for calling windows api directly

---

made by gajanan raveendranathan
