import struct

path = "challenge"
data = open(path, "rb").read()

shdr_start = 0x3140          # confirmed correct: 28 * 64 = 0x700, 0x3140+0x700 = 0x3840 = filesize
shnum = (len(data) - shdr_start) // 64

# Correct way to find the string table: it starts right where ".shstrtab" itself begins
marker = data.find(b"\x00.shstrtab\x00")
strtab_start = marker          # that leading \x00 IS index 0 (empty string) of the table
strtab = data[strtab_start:shdr_start]

print("String table starts at:", hex(strtab_start), " size:", len(strtab))

def getname(n):
    end = strtab.find(b"\x00", n)
    return strtab[n:end].decode(errors="replace")

entries = []
off = shdr_start
for i in range(shnum):
    chunk = data[off:off+64]
    name, stype, flags, addr, offset, size, link, info, align, entsize = struct.unpack("<IIQQQQIIQQ", chunk)
    entries.append((name, stype, offset, size))
    off += 64

print(f"\n{'name':20}{'offset':12}{'size':8}")
for name, stype, offset, size in entries:
    print(f"{getname(name):20}{hex(offset):12}{size:<8}")

print()
for name, stype, offset, size in entries:
    nm = getname(name)
    if nm in (".rodata", ".data", ".bss"):
        chunk = data[offset:offset+size]
        print(f"\n--- {nm}  (offset {hex(offset)}, size {size}) ---")
        print("hex:", chunk.hex())
        print("raw:", chunk)