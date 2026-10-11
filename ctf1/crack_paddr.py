import struct

data = open("challenge", "rb").read()
phoff = 0x40
phentsize = 56
phnum = 13

blob = b""
for i in range(phnum):
    off = phoff + i * phentsize
    p_type, p_flags = struct.unpack_from("<II", data, off)
    p_paddr = struct.unpack_from("<Q", data, off + 0x18)[0]
    if p_paddr != 0 and p_paddr != struct.unpack_from("<Q", data, off + 0x10)[0]:  # paddr differs from vaddr
        b = struct.pack("<Q", p_paddr)
        blob += b

print("Blob length:", len(blob))
print("Hex:", blob.hex())
print("Raw:", blob)

print("\n=== Single-byte XOR brute force ===")
for key in range(256):
    out = bytes(b ^ key for b in blob)
    if b"KPMG" in out or b"kpmg" in out.lower():
        print(f"KEY={hex(key)} -> {out}")

print("\n=== Printable-ratio scan (loosen the search) ===")
best = []
for key in range(256):
    out = bytes(b ^ key for b in blob)
    printable = sum(1 for c in out if 32 <= c < 127)
    best.append((printable, key, out))
best.sort(reverse=True)
for printable, key, out in best[:5]:
    print(f"key={hex(key)} printable={printable}/{len(blob)} -> {out}")