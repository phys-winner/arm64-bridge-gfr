"""Russian language-slot, font cmap and MP4 track evidence; bounded reads only."""
from collections import Counter
import json
from pathlib import Path
import struct
import sys
import zipfile
from cache_fat32 import Fat32
from cache_lab import index


def boxes(read_at, size):
    cursor = 0
    while cursor < size:
        if size - cursor < 8:
            raise ValueError("short MP4 box header")
        length, kind = struct.unpack(">I4s", read_at(cursor, 8))
        header = 8
        if length == 1:
            length = struct.unpack(">Q", read_at(cursor + 8, 8))[0]
            header = 16
        elif length == 0:
            length = size - cursor
        if length < header or length > size - cursor:
            raise ValueError("MP4 box exceeds container")
        yield kind.decode("ascii"), cursor + header, length - header
        cursor += length


def mp4(read_at, size):
    result = []
    for kind, start, length in boxes(read_at, size):
        if kind != "moov":
            continue
        moov = read_at(start, length)
        def children(data):
            return {kind: data[offset:offset + length] for kind, offset, length in boxes(lambda o, n: data[o:o + n], len(data))}
        for kind, offset, length in boxes(lambda o, n: moov[o:o + n], len(moov)):
            if kind != "trak":
                continue
            trak = children(moov[offset:offset + length])
            mdia = children(trak["mdia"])
            mdhd = mdia["mdhd"]
            if mdhd[0] == 0:
                timescale, duration, language = struct.unpack_from(">IIH", mdhd, 12)
            elif mdhd[0] == 1:
                timescale, duration, language = struct.unpack_from(">IQH", mdhd, 20)
            else:
                raise ValueError("unsupported mdhd version")
            lang = "".join(chr(((language >> shift) & 31) + 0x60) for shift in (10, 5, 0))
            stsd = children(children(mdia["minf"])["stbl"])["stsd"]
            handler = mdia["hdlr"][8:12].decode("ascii")
            sample = stsd[8:]
            track = {"type": handler, "language": lang, "duration": duration, "timescale": timescale,
                     "duration_seconds": duration / timescale, "codec": sample[4:8].decode("ascii")}
            if handler == "vide":
                track["width"], track["height"] = struct.unpack_from(">HH", sample, 32)
            elif handler == "soun":
                track["channels"] = struct.unpack_from(">H", sample, 24)[0]
                track["sample_rate"] = struct.unpack_from(">I", sample, 32)[0] >> 16
            result.append(track)
    return result


def font_cmap(data):
    tables = {}
    for n in range(struct.unpack_from(">H", data, 4)[0]):
        tag, checksum, start, length = struct.unpack_from(">4sIII", data, 12 + n * 16)
        if start + length > len(data):
            raise ValueError("TTF table exceeds font")
        tables[tag] = (start, length)
    start, length = tables[b"cmap"]
    cmap = data[start:start + length]
    result = {}
    for n in range(struct.unpack_from(">H", cmap, 2)[0]):
        platform, encoding, offset = struct.unpack_from(">HHI", cmap, 4 + n * 8)
        if platform not in (0, 3):
            continue
        table = cmap[offset:]
        fmt = struct.unpack_from(">H", table)[0]
        if fmt != 4:
            continue
        count = struct.unpack_from(">H", table, 6)[0] // 2
        ends = struct.unpack_from(">" + "H" * count, table, 14)
        starts = struct.unpack_from(">" + "H" * count, table, 16 + count * 2)
        deltas = struct.unpack_from(">" + "h" * count, table, 16 + count * 4)
        ranges_start = 16 + count * 6
        ranges = struct.unpack_from(">" + "H" * count, table, ranges_start)
        for i, (first, last) in enumerate(zip(starts, ends)):
            for char in range(first, min(last, 0xfffe) + 1):
                if ranges[i]:
                    address = ranges_start + i * 2 + ranges[i] + (char - first) * 2
                    if address + 2 > len(table):
                        raise ValueError("TTF glyph reference out of bounds")
                    glyph = struct.unpack_from(">H", table, address)[0]
                    if glyph:
                        glyph = (glyph + deltas[i]) & 0xffff
                else:
                    glyph = (char + deltas[i]) & 0xffff
                if glyph:
                    result[char] = glyph
    return result


def font_aliases(data, cmap):
    tables = {tag: (start, length) for tag, _, start, length in
              (struct.unpack_from(">4sIII", data, 12 + n * 16)
               for n in range(struct.unpack_from(">H", data, 4)[0]))}
    long_offsets = struct.unpack_from(">h", data, tables[b"head"][0] + 50)[0]
    if long_offsets not in (0, 1):
        raise ValueError("unsupported TTF loca format")
    count = struct.unpack_from(">H", data, tables[b"maxp"][0] + 4)[0]
    def glyph(char):
        gid = cmap.get(char, 0)
        if not gid or gid >= count:
            raise ValueError("missing or invalid Cyrillic glyph")
        width = 4 if long_offsets else 2
        location = tables[b"loca"][0] + gid * width
        if (gid + 2) * width > tables[b"loca"][1]:
            raise ValueError("TTF loca exceeds table")
        start, end = struct.unpack_from(">II" if long_offsets else ">HH", data, location)
        if not long_offsets:
            start *= 2
            end *= 2
        if not 0 <= start <= end <= tables[b"glyf"][1]:
            raise ValueError("TTF glyph exceeds glyf table")
        offset = tables[b"glyf"][0]
        return data[offset + start:offset + end]
    return {"cp1251_C0_FF_exact_glyf_aliases": sum(
        glyph(b) == glyph(ord(bytes([b]).decode("cp1251"))) for b in range(0xc0, 0x100)),
        "tested_aliases": 64}


def main():
    root = Path(sys.argv[1]).resolve()
    out = root / "work/cache_analysis"
    fss = {"original_main": Fat32(root / "com.doublefine.grimfandangoremastered/main.150.com.doublefine.grimfandangoremastered.obb"),
           "rus_main": Fat32(root / "rus/main.150.com.doublefine.grimfandangoremastered.obb"),
           "original_patch": Fat32(root / "com.doublefine.grimfandangoremastered/patch.1512.com.doublefine.grimfandangoremastered.obb"),
           "rus_patch": Fat32(root / "rus/patch.1512.com.doublefine.grimfandangoremastered.obb")}
    voice = {}
    for lab in ("VOX000" + str(i) + ".LAB" for i in range(5)):
        indexes = {n: index(lambda o, size, fs=fs: fs.read(lab, o, size), fs.entries[lab]["size"])
                   for n, fs in fss.items() if n.endswith("main")}
        original = {n[3:].lower(): e for n, e in indexes["original_main"].items() if n.lower().startswith("en_")}
        rus = {n.lower(): e for n, e in indexes["rus_main"].items()}
        same, changed, added = [], [], []
        for name, entry in rus.items():
            if name not in original:
                added.append(name)
                continue
            old = original[name]
            equal = entry["size"] == old["size"] and fss["rus_main"].read(lab, entry["offset"], entry["size"]) == fss["original_main"].read(lab, old["offset"], old["size"])
            (same if equal else changed).append(name)
        voice[lab] = {"original_member_count": len(indexes["original_main"]), "original_english_count": len(original),
                      "rus_member_count": len(rus), "same_normalized_english": same, "changed_normalized_english": changed,
                      "added_normalized_english": added, "missing_normalized_english": sorted(set(original) - set(rus)),
                      "original_languages": dict(Counter(n.split("_")[0] for n in indexes["original_main"])),
                      "rus_extensions": dict(Counter(Path(n).suffix.lower() for n in rus))}
    delta = json.loads((out / "obb_delta.json").read_text())
    movie = {}
    for e in delta["patch"]["changed"]:
        name = e["path"]
        movie[name] = {label: mp4(lambda o, size, fs=fs: fs.read(name, o, size), fs.entries[name]["size"])
                       for label, fs in fss.items() if label.endswith("patch")}
    with zipfile.ZipFile(root / "rus/Grim_Fandango_Remastered-v1.5.19.apk") as apk:
        mappings = {n: apk.read(n).decode("ascii") for n in apk.namelist() if n.endswith(".LAF.txt")}
        fonts = {}
        for n in apk.namelist():
            if not n.endswith("-ENPY.ttf") and not n.endswith("FuturaStd-Heavy.ttf"):
                continue
            font = apk.read(n)
            cmap = font_cmap(font)
            fonts[n] = {"map_size": len(cmap), "glyph_A": cmap.get(0x41), "glyph_Latin_C0": cmap.get(0xc0),
                        "glyph_Cyrillic_A": cmap.get(0x410),
                        "cp1251_slots_present": sum(ord(bytes([b]).decode("cp1251", errors="replace")) >= 0x400 and b in cmap for b in range(128, 256)),
                        "unicode_cyrillic_present": sum(char in cmap for char in range(0x410, 0x450)),
                        **font_aliases(font, cmap)}
        table = apk.read("assets/grim.en.tab")
        text = {"encoding": "CP1251 slots with 0xBF relocated lowercase ya in shipped fonts",
                "raw_cp1251_sample": table.decode("cp1251").splitlines()[:12],
                "sample": table.decode("cp1251").replace("\u0457", "я").splitlines()[:12],
                "extended_byte_mapping_evidence": "work/cache_analysis/russian_yo_glyphs.json",
                "laf_font_mapping": mappings, "fonts": fonts}
    # Checks exercise parsers against the real inventories and known language-slot contract.
    assert all(not item["added_normalized_english"] and not item["missing_normalized_english"] for item in voice.values())
    assert all(t["cp1251_C0_FF_exact_glyf_aliases"] == 64 for t in fonts.values())
    assert len(movie) == 30 and all(len(item["original_patch"]) == 7 and len(item["rus_patch"]) == 2 for item in movie.values())
    (out / "russian_language_details.json").write_text(json.dumps({"voice": voice, "video": movie, "text": text}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Russian details PASSED:", len(voice), "voice LABs,", len(movie), "movies,", len(fonts), "fonts")
    print("Normalized English voice delta:", sum(len(v["changed_normalized_english"]) for v in voice.values()), "changed WAVs,",
          sum(len(v["same_normalized_english"]) for v in voice.values()), "identical LIPs; no added/missing IDs")
    print("All fonts have 64 exact CP1251-to-Unicode glyf aliases; MP4 track counts 7 original / 2 Russian")


if __name__ == "__main__":
    main()
