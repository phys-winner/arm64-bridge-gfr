"""Verify the actual four signed Grim data APKs without extracting containers."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def zip32_extra(extra):
    offset = 0
    while offset + 4 <= len(extra):
        kind, size = struct.unpack_from('<HH', extra, offset)
        assert kind != 1, 'ZIP64 extra field'
        offset += 4 + size
        assert offset <= len(extra), 'Truncated extra field'
    assert not any(extra[offset:]), 'Nonzero truncated extra field'


def main():
    inputs = json.loads((ROOT/'work/evidence/research_cache_20261007/input_hashes.json').read_text())
    pins = {r['path'].replace('\\', '/'): r for r in inputs['records']}
    rows = []
    for name in ('obb_main', 'obb_patch', 'rus_text', 'rus_voice'):
        apk = ROOT/'arm64_bridge/out/splits'/f'{name}.apk'
        meta = json.loads((ROOT/'arm64_bridge/out/build-cache'/name/'cache.json').read_text())
        with apk.open('rb') as stream:
            signed = hashlib.file_digest(stream, 'sha256').hexdigest()
        assert signed == meta['artifact_sha256']
        assert apk.stat().st_size < 0xffffffff
        with zipfile.ZipFile(apk) as archive:
            entries = [i for i in archive.infolist() if i.filename.startswith('assets/obb/') and i.filename.endswith('.obb')]
            assert len(entries) == 1
            entry = entries[0]
            assert entry.extract_version < 45 and entry.compress_type == zipfile.ZIP_STORED
            assert entry.file_size == entry.compress_size < 0xffffffff
            assert entry.header_offset < 0xffffffff and archive.start_dir < 0xffffffff
            zip32_extra(entry.extra)
            with apk.open('rb') as stream:
                stream.seek(entry.header_offset)
                fields = struct.unpack('<4s5H3I2H', stream.read(30))
                assert fields[0] == b'PK\x03\x04' and fields[3] == 0
                assert fields[7] == fields[8] == entry.file_size
                assert stream.read(fields[-2]).decode() == entry.filename
                zip32_extra(stream.read(fields[-1]))
                offset = stream.tell()
                assert offset % 4 == 0 and offset + entry.file_size <= archive.start_dir
            with archive.open(entry) as stream:
                payload = hashlib.file_digest(stream, 'sha256').hexdigest()
            expected = pins[f'arm64_bridge/app/splits/{name}/{entry.filename}']
            assert expected['bytes'] == entry.file_size and expected['sha256'] == payload
            rows.append(dict(split=name, artifact_sha256=signed, apk_bytes=apk.stat().st_size,
                             entry=entry.filename, payload_bytes=entry.file_size,
                             payload_sha256=payload, data_offset=offset, stored=True, zip64=False,
                             certificate=meta['certificate'], identity=meta['identity']))
            print(name, 'PASS', entry.file_size, offset, payload, flush=True)
    (ROOT/'work/evidence/resume_20261007/data_packaging.json').write_text(json.dumps(rows, indent=2))
    print('PASS all four signed-container identity/STORED/ZIP32/alignment gates')


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-check']:
        zip32_extra(b'\0\0')
        zip32_extra(struct.pack('<HH', 0xffff, 1) + b'x' + b'\0')
        for extra in (b'\1\0\0\0', b'\xff', b'\xff\xff\x01\0'):
            try:
                zip32_extra(extra)
            except AssertionError:
                continue
            raise AssertionError('Accepted ZIP64 or malformed extra')
        print('PASS ZIP32 fields and zipalign zero padding')
    else:
        main()
