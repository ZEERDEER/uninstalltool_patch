import shutil, os, sys, hashlib, base64

EXE = r"D:\App\Uninstall Tool\UninstallTool.exe"
BAK = r"D:\App\Uninstall Tool\UninstallTool.exe.orig"

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest().upper()

if not os.path.exists(BAK):
    shutil.copy2(EXE, BAK)
    print("backup created")

data = bytearray(open(EXE, "rb").read())

# Patch 1: 0x1400336FA  je +0xBE  ->  six NOPs
#   (skips the "portable license.dat" branch so the registry RN/RC path is always used)
off1 = 0x32AFA
print("p1 before:", data[off1:off1+6].hex(" ").upper())
data[off1:off1+6] = bytes([0x90]*6)

# Patch 2: 0x140009DB0  license-state getter -> return 3 (licensed)
off2 = 0x91B0
print("p2 before:", data[off2:off2+6].hex(" ").upper())
data[off2:off2+6] = bytes([0xB8, 0x03, 0x00, 0x00, 0x00, 0xC3])

open(EXE, "wb").write(data)
print("p1 after :", data[off1:off1+6].hex(" ").upper())
print("p2 after :", data[off2:off2+6].hex(" ").upper())
print("patched sha256:", sha(EXE))
print("original sha256:", sha(BAK))

# --- registry payload encoder: base64( utf16le(text) XOR 0x89 ) ---
def enc(text):
    raw = text.encode("utf-16-le")
    return base64.b64encode(bytes(b ^ 0x89 for b in raw)).decode()

print("check VH:", enc("3"), "(expected uok=)")
print("RN:", enc("YG"))
print("RC:", enc("AAAA-BBBB-CCCC-DDDD"))
