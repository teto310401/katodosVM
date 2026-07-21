import sys, time, subprocess
sys.path.insert(0, r"C:\Users\Administrator\.workbuddy\binaries\python\envs\default\Lib\site-packages")
from PIL import ImageGrab

exe = r"dist\katodos.exe"
p = subprocess.Popen(exe)
print("launched, pid=", p.pid)
time.sleep(5)   # 应处于开机自检 (POST) 阶段
ImageGrab.grab().save("shot_post.png")
print("saved shot_post.png")
time.sleep(9)   # 进入终端
ImageGrab.grab().save("shot_term.png")
print("saved shot_term.png")
p.terminate()
time.sleep(1)
try:
    p.kill()
except Exception:
    pass
print("done")
