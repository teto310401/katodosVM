import ctypes, subprocess, time

EnumWindows = ctypes.windll.user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.POINTER(ctypes.c_int))
GetWindowText = ctypes.windll.user32.GetWindowTextW
GetWindowTextLength = ctypes.windll.user32.GetWindowTextLengthW
IsWindowVisible = ctypes.windll.user32.IsWindowVisible

results = []

def foreach(hwnd, extra):
    if IsWindowVisible(hwnd):
        length = GetWindowTextLength(hwnd)
        if length > 0:
            title = ctypes.create_unicode_buffer(length + 1)
            GetWindowText(hwnd, title, length + 1)
            results.append((hwnd, title.value))
    return True

print("Starting katodos.exe...")
p = subprocess.Popen(r"dist\katodos.exe")
time.sleep(5)
EnumWindows(EnumWindowsProc(foreach), 0)
print("Visible windows after 5s:")
for hwnd, title in results:
    print("  hwnd=%s title=%r" % (hwnd, title))
print("katoDoS windows:", [t for _, t in results if 'katoDoS' in t or 'katodos' in t.lower()])
print("term.html windows:", [t for _, t in results if 'term.html' in t])
print("terminating exe")
p.terminate()
time.sleep(1)
try:
    p.kill()
except Exception:
    pass
