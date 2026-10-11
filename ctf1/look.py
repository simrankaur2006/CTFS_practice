import re
from elftools.elf.elffile import ELFFile

data = open("challenge", "rb").read()
print("File size:", len(data))

# 1. Direct flag search
print("Flag matches:", re.findall(rb"KPMG_CTF\{[^}]*\}", data))

# 2. List all ELF sections
print("\n--- SECTIONS ---")
with open("challenge", "rb") as f:
    elf = ELFFile(f)
    for s in elf.iter_sections():
        print(f"{s.name:25} size={s['sh_size']:<8} offset={hex(s['sh_offset'])}")

# 3. Readable strings (like the 'strings' command)
print("\n--- STRINGS ---")
for m in re.findall(rb"[ -~]{6,}", data)[:150]:
    print(m.decode())