from elftools.elf.elffile import ELFFile

path = "challenge"
filesize = __import__("os").path.getsize(path)
print("File size:", filesize)

with open(path, "rb") as f:
    elf = ELFFile(f)
    print("\n=== PROGRAM HEADERS (segments) ===")
    max_end = 0
    for seg in elf.iter_segments():
        h = seg.header
        off, size = h.p_offset, h.p_filesz
        end = off + size
        max_end = max(max_end, end)
        print(f"type={h.p_type:15} offset={hex(off):10} filesz={size:<8} vaddr={hex(h.p_vaddr)} flags={h.p_flags}")

    print("\nEnd of last segment data:", hex(max_end), max_end)
    print("Actual file size:        ", hex(filesize), filesize)
    if filesize > max_end:
        print(f"\n>>> {filesize - max_end} EXTRA BYTES APPENDED AFTER THE ELF CONTENT <<<")

# dump whatever trails the file, if any
with open(path, "rb") as f:
    data = f.read()
trailing = data[max_end:] if filesize > max_end else b""
if trailing:
    print("\n--- TRAILING DATA (hex) ---")
    print(trailing.hex())
    print("\n--- TRAILING DATA (raw) ---")
    print(trailing)