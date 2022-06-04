from struct import pack, unpack
import io, sys

# This is a slightly modified version of this https://github.com/ihaveamac/pyctr/blob/master/pyctr/type/exefs.py#L69. Massive props to the author
def decompress_code(code: bytes):
    off_size_comp = int.from_bytes(code[-8:-4], 'little')
    add_size = int.from_bytes(code[-4:], 'little')
    comp_start = 0
    code_len = len(code)

    code_comp_size = off_size_comp & 0xFFFFFF
    code_comp_end = code_comp_size - ((off_size_comp >> 24) % 0xFF)
    code_dec_size = code_len + add_size

    if code_len < 8:
        return -1
    if code_len > 0x2300000:
        return -1

    if code_comp_size <= code_len:
        comp_start = code_len - code_comp_size

    if code_comp_end < 0:
        return -1
    if code_dec_size > 0x2300000:
        return -1

    dec = bytearray(code)
    dec.extend(b'\0' * add_size)

    data_end = comp_start + code_dec_size
    ptr_in = comp_start + code_comp_end
    ptr_out = code_dec_size

    while ptr_in > comp_start and ptr_out > comp_start:
        if ptr_out < ptr_in:
            return -1

        ptr_in -= 1
        ctrl_byte = dec[ptr_in]
        for i in range(7, -1, -1):
            if ptr_in <= comp_start or ptr_out <= comp_start:
                break

            if (ctrl_byte >> i) & 1:
                ptr_in -= 2
                seg_code = int.from_bytes(dec[ptr_in:ptr_in + 2], 'little')
                if ptr_in < comp_start:
                   return -1
                seg_off = (seg_code & 0x0FFF) + 2
                seg_len = ((seg_code >> 12) & 0xF) + 3

                if ptr_out - seg_len < comp_start:
                    return -1

                if ptr_out + seg_off >= data_end:
                    return -1

                c = 0
                while c < seg_len:
                    byte = dec[ptr_out + seg_off]
                    ptr_out -= 1
                    dec[ptr_out] = byte
                    c += 1
            else:
                if ptr_out == comp_start:
                    return -1
                if ptr_in == comp_start:
                    return -1

                ptr_out -= 1
                ptr_in -= 1
                dec[ptr_out] = dec[ptr_in]

    if ptr_in != comp_start:
        return -1
    if ptr_out != comp_start:
        return -1

    return bytes(dec)

if len(sys.argv) != 2:
    print("{} filename".format(sys.argv[0]))
    exit(-1)
f = open(sys.argv[1], "rb")
f.seek(0x118)

pid = unpack("Q", f.read(8))[0]
print("Program ID: {}".format(hex(pid)))
f.seek(0x180, 0)

ext_size = unpack("i", f.read(4))[0]
print("Extended header size: {}".format(hex(ext_size)))
f.seek(0x1A0, 0)

exefs_offset = unpack("i", f.read(4))[0] * 0x200
print("Exefs offset: {}".format(hex(exefs_offset)))

exefs_size = unpack("i", f.read(4))[0] * 0x200
print("Exefs size: {}".format(exefs_size))

f.seek(0x200, 0)
extheader = io.BytesIO(f.read(ext_size))

# Check if code is compressed and will require decompressing
extheader.seek(0xD)
is_compressed = int.from_bytes(unpack("c", extheader.read(1))[0], "little") & 1
extheader.seek(0x0)
# Parse exefs and locate code.bin
f.seek(exefs_offset, 0)
code_offset = 0
code_size = 0
for _ in range(0, 10):
    name = f.read(8).decode('utf-8').strip('\x00')
    if name == '.code':
        code_offset = unpack("i", f.read(4))[0] + 0x200
        code_size = unpack("i", f.read(4))[0]
        print("Code offset: {}".format(hex(code_offset)))
        print("Code size: {}".format(code_size))
        break
    else:
        f.seek(exefs_offset + (0x10 * _) , 0)

if code_size == 0:
    print("Invalid code size. Aborting.")
    exit(-1)

f.seek(exefs_offset + code_offset, 0)
code_comp = f.read(code_size)
code = 0
if is_compressed == 1:
    code = decompress_code(code_comp)
    if code == -1:
        print("Failure while decompressing code.bin. Aborting.")
        exit(-1)
else:
    code = code_comp

print("Decompressed code size: {}".format(len(code)))
code = io.BytesIO(code)

# This code has been taken from https://github.com/NWPlayer123/ctr-elf2. Massive props to the author.
name = extheader.read(8).decode('utf-8').strip("\x00")
data = unpack("<5xBH12I", extheader.read(0x38))

print("Name: " + name)
print("Flag: %02x " % data[0] + ["", "[compressed]"][data[0] & 1] + ["", "[sd app]"][(data[0] & 2) >> 1])
print("Rev.: %04x" % data[1])
print

info = [".text addr: ", ".text page: ", ".text size: ", "stack size: ",
        ".read addr: ", ".read page: ", ".read size: ", "PleaseDoNotP",
	".data addr: ", ".data page: ", ".data size: ", ".bss size:  "]
it = 0
for i in info: #Don't do this kids it's bad form
    if it != 7: #Don't print, it's zero
        print(i + "%08X" % data[2 + it])
    if it in [3, 7]: print #Pretty print
    it += 1

if data[2] != 0x100000: print("WARNING: base address wrong, might be encrypted")

data1 = code.read(data[4])  #Textc
code.seek(data[3] * 0x1000)
data2 = code.read(data[8])  #Read
code.seek((data[3] + data[7]) * 0x1000)
data3 = code.read(data[12]) #Data

table = b"\x00.shstrtab\x00.text\x00.fini\x00.rodata\x00.memregion\x00.data\x00.bss\x00"
#Please never create an ELF file from scratch you will hate yourself like me
with open("{}.elf".format(name), "wb") as f:
    f.write(b"\x7FELF\x01\x01\x01\x61" + b"\x00" * 8) #magic
    f.write(pack("<HHI", 2, 0x28, 1)) #Executable, ARM, ver 1
    off = [];base = 0x10000
    for size in [len(data1), len(data2), len(data3)]:
        off.append(base)
        base += size
    off.append(base)
    off.append(base + (0x100 - (base % 0x100))) #text, read, data, end, end+pad
    f.write(pack("<III", data[2], 0x34, off[4]+len(table))) #Start addr, program offset, section offset
    f.write(pack("<I6H", 0, 0x34, 0x20, 4, 0x28, 8, 7)) #Up to 52/0x34, time for sections
    #Type (Load), ELF offset, Virt and Phys offset, file and mem size, flags, align
    f.write(pack("<8I", 1, off[0],  data[2],   data[2], len(data1), len(data1), 5, 4)) #text
    f.write(pack("<8I", 1, off[1],  data[6],   data[6], len(data2), len(data2), 4, 4)) #read
    f.write(pack("<8I", 1, off[2], data[10],  data[10], len(data3), len(data3), 6, 4)) #data
    f.write(pack("<8I", 1, off[3], data[10]+len(data3), data[10]+len(data3), 0, data[-1], 6, 4)) #.bss
    #Now to write actual section data
    f.write(b"\x00" * 0xFF4C) #Hardcoded to pad 0x10000
    f.write(data1)
    f.write(data2)
    f.write(data3)
    f.write(b"\x00" * (off[4] - off[3])) #Align to 0x100
    f.write(table)
    # str | type | flag | addr | offset | size | link | info | align | entsize
    f.write(b"\x00" * 0x28) #.null
    f.write(pack("<10I", 11, 1, 6,  1 << 20, off[0], len(data1), 0, 0, 0x1000, 0)) #.text
    f.write(pack("<10I", 17, 1, 7,  data[6], off[3], 0, 0, 0, 1, 0)) #.fini
    f.write(pack("<10I", 23, 1, 3,  data[6], off[1], len(data2), 0, 0, 1, 0)) #.rodata
    f.write(pack("<10I", 31, 1, 1, data[10], off[3], 0, 0, 0, 1, 0)) #.memregion
    f.write(pack("<10I", 42, 1, 3, data[10], off[2], len(data3), 0, 0, 1, 0)) #.data
    f.write(pack("<10I", 48, 8, 3, data[10]+len(data3), size, data[-1], 0, 0, 1, 0)) #.bss
    f.write(pack("<10I", 1, 3, 0, 0, off[4],len(table), 0, 0, 1, 0)) #.shstrtab