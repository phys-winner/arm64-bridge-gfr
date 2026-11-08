"""Read-only FAT32 OBB inventory and bounded streaming; Python stdlib only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


class Fat32:
    def __init__(self, path):
        self.path = Path(path)
        self.fp = self.path.open("rb")
        b = self.read_at(0, 512)
        if b[510:512] != b"\x55\xaa":
            raise ValueError("missing FAT boot signature")
        self.sector = struct.unpack_from("<H", b, 11)[0]
        self.spc = b[13]
        self.reserved = struct.unpack_from("<H", b, 14)[0]
        self.nfat = b[16]
        self.sectors, self.fat_sectors = struct.unpack_from("<II", b, 32)
        self.root = struct.unpack_from("<I", b, 44)[0]
        if (self.sector not in (512, 1024, 2048, 4096) or self.spc == 0
                or self.spc & (self.spc - 1) or self.nfat not in (1, 2)
                or struct.unpack_from("<H", b, 17)[0] != 0):
            raise ValueError("invalid/unsupported FAT32 geometry")
        self.cluster_size = self.sector * self.spc
        self.data_offset = (self.reserved + self.nfat * self.fat_sectors) * self.sector
        self.volume_size = self.sectors * self.sector
        self.cluster_count = (self.volume_size - self.data_offset) // self.cluster_size
        if self.volume_size > self.path.stat().st_size:
            raise ValueError("truncated FAT32 volume")
        self.fat = self.read_at(self.reserved * self.sector, self.fat_sectors * self.sector)
        if len(self.fat) // 4 < self.cluster_count + 2:
            raise ValueError("short FAT table")
        self.footer = self.read_at(self.volume_size, self.path.stat().st_size - self.volume_size)
        self.entries = {}
        self.directories = {}
        self._extents = {}
        self._directory(self.root, "", set())

    def read_at(self, offset, size):
        if offset < 0 or size < 0:
            raise ValueError("negative range")
        self.fp.seek(offset)
        b = self.fp.read(size)
        if len(b) != size:
            raise ValueError("truncated read")
        return b

    def chain(self, first):
        seen = set()
        cluster = first
        while cluster < 0x0ffffff8:
            if cluster < 2 or cluster > self.cluster_count + 1 or cluster in seen:
                raise ValueError(f"invalid/cyclic chain at {cluster}")
            seen.add(cluster)
            yield cluster
            cluster = struct.unpack_from("<I", self.fat, cluster * 4)[0] & 0x0fffffff

    def offset(self, cluster):
        return self.data_offset + (cluster - 2) * self.cluster_size

    def extents(self, entry):
        if isinstance(entry, str):
            entry = self.entries[entry]
        name = entry["path"]
        if entry["size"] == 0:
            return []
        if name not in self._extents:
            spans = []
            remaining = entry["size"]
            previous = None
            logical = 0
            for cluster in self.chain(entry["cluster"]):
                count = min(remaining, self.cluster_size)
                if not count:
                    break
                if spans and cluster == previous + 1:
                    spans[-1]["length"] += count
                else:
                    spans.append({"logical_offset": logical, "offset": self.offset(cluster), "length": count})
                previous = cluster
                remaining -= count
                logical += count
            if remaining:
                raise ValueError("file exceeds chain length")
            self._extents[name] = spans
        return self._extents[name]

    def stream(self, entry, start=0, length=None):
        """Yield contiguous runs, bounded to file size (no whole-cache extraction)."""
        if isinstance(entry, str):
            entry = self.entries[entry]
        size = entry["size"]
        if start < 0 or start > size or (length is not None and length < 0):
            raise ValueError("invalid file range")
        left = size - start if length is None else min(length, size - start)
        for span in self.extents(entry):
            end = span["logical_offset"] + span["length"]
            if start >= end:
                continue
            within = max(start - span["logical_offset"], 0)
            available = min(left, span["length"] - within)
            while available:
                count = min(available, 1024 * 1024)
                yield self.read_at(span["offset"] + within, count)
                within += count
                available -= count
                left -= count
            if not left:
                return
        if left:
            raise ValueError("file exceeds chain length")

    def read(self, name, start=0, length=None):
        return b"".join(self.stream(name, start, length))

    def digest(self, name):
        h = hashlib.sha256()
        for b in self.stream(name):
            h.update(b)
        return h.hexdigest()

    def _directory(self, first, prefix, ancestors):
        if first in ancestors:
            raise ValueError("cyclic directory")
        ancestors = ancestors | {first}
        lfn = {}
        spans = []
        self.directories[prefix] = spans
        for cluster in self.chain(first):
            spans.append({"offset": self.offset(cluster), "length": self.cluster_size})
            b = self.read_at(self.offset(cluster), self.cluster_size)
            for i in range(0, len(b), 32):
                e = b[i:i + 32]
                if e[0] == 0:
                    return
                if e[0] == 0xe5:
                    lfn.clear()
                    continue
                if e[11] == 0x0f:
                    seq = e[0] & 0x1f
                    if e[0] & 0x40:
                        lfn.clear()
                    lfn[seq] = (e[13], e[1:11] + e[14:26] + e[28:32])
                    continue
                checksum = 0
                for char in e[:11]:
                    checksum = (((checksum & 1) << 7) + (checksum >> 1) + char) & 255
                if lfn and sorted(lfn) == list(range(1, max(lfn) + 1)) and all(v[0] == checksum for v in lfn.values()):
                    raw = b"".join(lfn[k][1] for k in sorted(lfn))
                    name = raw.decode("utf-16le").split("\0", 1)[0].rstrip("\uffff")
                else:
                    base = e[:8].decode("cp437").rstrip()
                    ext = e[8:11].decode("cp437").rstrip()
                    if e[12] & 8:
                        base = base.lower()
                    if e[12] & 16:
                        ext = ext.lower()
                    name = base + ("." + ext if ext else "")
                lfn.clear()
                if e[11] & 8 or name in (".", ".."):
                    continue
                if not name or any(c in name for c in "/\\\0"):
                    raise ValueError("invalid entry name")
                path = prefix + name
                first_cluster = (struct.unpack_from("<H", e, 20)[0] << 16) | struct.unpack_from("<H", e, 26)[0]
                if e[11] & 16:
                    self._directory(first_cluster, path + "/", ancestors)
                else:
                    if path in self.entries:
                        raise ValueError("duplicate path")
                    self.entries[path] = {"path": path, "cluster": first_cluster,
                                          "size": struct.unpack_from("<I", e, 28)[0]}

    def metadata(self):
        return {"path": str(self.path.resolve()), "bytes": self.path.stat().st_size,
                "format": "FAT32 + Android JOBB footer", "sector_bytes": self.sector,
                "cluster_bytes": self.cluster_size, "reserved_sectors": self.reserved,
                "fat_count": self.nfat, "fat_sectors": self.fat_sectors,
                "volume_bytes": self.volume_size, "data_offset": self.data_offset,
                "cluster_count": self.cluster_count, "root_cluster": self.root,
                "footer_hex": self.footer.hex(), "file_count": len(self.entries),
                "payload_bytes": sum(e["size"] for e in self.entries.values())}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("obb")
    p.add_argument("--output", required=True)
    p.add_argument("--hash-files", action="store_true")
    args = p.parse_args()
    fs = Fat32(args.obb)
    entries = list(fs.entries.values())
    if args.hash_files:
        for e in entries:
            e["sha256"] = fs.digest(e["path"])
    result = {"metadata": fs.metadata(), "entries": entries}
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(fs.metadata(), ensure_ascii=False))


if __name__ == "__main__":
    main()
