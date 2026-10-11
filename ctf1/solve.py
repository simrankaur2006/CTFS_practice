import struct

data = open("challenge", "rb").read()
phoff = 0x40
phentsize = 56
phnum = 13

phdrs = []
for i in range(phnum):
    off = phoff + i * phentsize
    p_type, p_flags = struct.unpack_from("<II", data, off)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<QQQQQQ", data, off + 8)
    phdrs.append(dict(type=p_type, flags=p_flags, paddr=p_paddr, align=p_align))

# Step 1: rebuild the 56-byte key buffer from p_paddr of entries 6..12
local_68 = b"".join(struct.pack("<Q", phdrs[i]['paddr']) for i in range(6, 13))

# Step 2: checksum over PT_LOAD entries (type==1), iVar7 = index+3
uVar15 = 0x9a
for i in range(phnum):
    if phdrs[i]['type'] == 1:
        iVar7 = i + 3
        flags = phdrs[i]['flags'] & 0xff
        align_shifted = (phdrs[i]['align'] >> 12) & 0xffffffff
        uVar15 = (uVar15 ^ ((flags * iVar7) & 0xffffffff) ^ align_shifted) & 0xffffffff

# Step 3: derive length
first4 = struct.unpack_from("<I", local_68, 0)[0]
uVar2 = (uVar15 ^ 0xffffffa5 ^ first4 ^ 0x5a) & 0xff
print("checksum:", hex(uVar15), " length:", uVar2)

if not (1 <= uVar2 <= 0x37):
    print("length out of range — something's off, paste this output for me")
else:
    K = (uVar15 ^ 0xffffffa5) & 0xff
    bVar5 = 0x29
    decoded = bytearray(uVar2)
    for s in range(uVar2):
        rot_n = s & 7
        rot = ((K << rot_n) & 0xff) | (K >> (8 - rot_n) if rot_n else 0)
        decoded[s] = (local_68[s + 1] ^ bVar5) ^ rot
        bVar5 = (bVar5 + 0x13) & 0xff
    result = bytes(reversed(decoded))
    print("RESULT:", result)