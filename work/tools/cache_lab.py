"""Selective index for Grim Fandango LABN archives (no payload extraction)."""
import struct


def index(read_at, size):
    header = read_at(0, 16)
    magic, version, count, names_size = struct.unpack("<4sIII", header)
    if magic != b"LABN" or version != 0x10000 or count > 100000:
        raise ValueError("unsupported LABN header")
    strings_start = 16 + count * 16
    if strings_start + names_size > size:
        raise ValueError("LABN index exceeds archive")
    table = read_at(16, count * 16)
    strings = read_at(strings_start, names_size)
    result = {}
    for n in range(count):
        name_offset, offset, length, reserved = struct.unpack_from("<IIII", table, n * 16)
        if name_offset >= names_size or offset + length > size:
            raise ValueError("LABN entry out of bounds")
        name = strings[name_offset:strings.index(b"\0", name_offset)].decode("cp1252")
        if name in result:
            raise ValueError("duplicate LABN name")
        result[name] = {"path": name, "offset": offset, "size": length, "reserved": reserved}
    return result
