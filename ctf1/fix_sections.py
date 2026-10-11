import struct

path = "challenge"
data = open(path, "rb").read()

# Locate the section-header array using a known entry's byte signature
sig = bytes.fromhex("0b00000001000000020000000000000018030000")
idx = data.find(sig)
assert idx != -1, "signature not found — paste the full hex dump here and I'll adjust"

shdr_start = idx - 64            # NULL (index 0) header precedes the first real one
strtab_offset = 0x3018           # where the appended block begins (end of real segments)
strtab = data[strtab_offset:shdr_start]

shnum = (len(data) - shdr_start) // 64
print("Detected", shnum, "section headers, starting at offset", hex(shdr_start))

def getname(n):
    end = strtab.find(b"\x00", n)
    return strtab[n:end].decode(errors="replace")

entries = []
off = shdr_start
for i in range(shnum):
    chunk = data[off:off+64]
    if len(chunk) < 64:
        break
    name, stype, flags, addr, offset, size, link, info, align, entsize = struct.unpack("<IIQQQQIIQQ", chunk)
    entries.append((name, stype, offset, size))
    off += 64

print(f"\n{'name':20}{'offset':12}{'size':8}")
for name, stype, offset, size in entries:
    print(f"{getname(name):20}{hex(offset):12}{size:<8}")

# Dump the raw bytes of likely flag-bearing sections
for name, stype, offset, size in entries:
    nm = getname(name)
    if nm in (".rodata", ".data", ".bss"):
        chunk = data[offset:offset+size]
        print(f"\n--- {nm}  (offset {hex(offset)}, size {size}) ---")
        print("hex:", chunk.hex())
        print("raw:", chunk)