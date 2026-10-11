import struct

data = open("challenge", "rb").read()

print("=== ELF HEADER (first 64 bytes) ===")
ehdr = data[0:64]
print("e_ident (16 bytes):", ehdr[0:16].hex(), repr(ehdr[0:16]))
for i, b in enumerate(ehdr[0:16]):
    print(f"  byte[{i}] = {hex(b)} ({chr(b) if 32<=b<127 else '.'})")

print("\n=== PROGRAM HEADERS: p_paddr field of each entry ===")
phoff = struct.unpack_from("<Q", ehdr, 0x20)[0]
phentsize = struct.unpack_from("<H", ehdr, 0x36)[0]
phnum = struct.unpack_from("<H", ehdr, 0x38)[0]
print(f"phoff={hex(phoff)} phentsize={phentsize} phnum={phnum}")

paddr_bytes = b""
for i in range(phnum):
    off = phoff + i * phentsize
    entry = data[off:off+phentsize]
    p_type, p_flags = struct.unpack_from("<II", entry, 0)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<QQQQQQ", entry, 8)
    print(f"[{i}] type={p_type} vaddr={hex(p_vaddr)} paddr={hex(p_paddr)} <-- offset in header: {hex(off+0x18)}")
    paddr_bytes += struct.pack("<Q", p_paddr)

print("\nAll p_paddr bytes concatenated:")
print(paddr_bytes.hex())
print(paddr_bytes)