"""Build the integrated bridge and its isolated APK with existing pinned tools."""
import argparse
import ast
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

BRIDGE = Path(__file__).resolve().parent
ROOT = BRIDGE.parent
sys.path.insert(0, str(ROOT / 'work/tools'))
from process_tools import run_process
from apk_build import ApkBuilder


def pin(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return dict(path=path.as_posix(), bytes=path.stat().st_size, sha256=digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['native', 'package'])
    parser.add_argument('--tests', action='store_true')
    parser.add_argument('--allow-network', action='store_true')
    parser.add_argument('--dynarmic-source', type=Path)
    parser.add_argument('--boost-source', type=Path)
    parser.add_argument('--tool-root', type=Path)
    parser.add_argument('--java', default=shutil.which('java'))
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    evidence = ROOT / 'work/evidence/bridge_start/builds' / (stamp + '_' + args.stage)
    evidence.mkdir(parents=True, exist_ok=False)
    source_paths = sorted((BRIDGE / 'src').rglob('*'))
    source_paths += [BRIDGE / 'CMakeLists.txt', BRIDGE / 'build_arm64.ps1']
    if args.tests:
        source_paths += sorted((BRIDGE / 'tests').glob('*'))
    inputs = [pin(path) for path in source_paths if path.is_file()]
    (evidence / 'source_pins.json').write_text(json.dumps(inputs, indent=2) + '\n', encoding='utf8')
    if args.stage == 'native':
        argv = [str(Path(shutil.which('pwsh')).resolve()), '-NoLogo', '-NoProfile', '-File',
                str(BRIDGE / 'build_arm64.ps1'), '-BridgeTarget', 'GrimFandango']
        if args.allow_network:
            argv.append('-AllowNetwork')
        if args.dynarmic_source:
            argv += ['-DynarmicSourceDirectory', str(args.dynarmic_source.resolve())]
        if args.boost_source:
            argv += ['-BoostSourceDirectory', str(args.boost_source.resolve())]
        if args.tests:
            argv.append('-BuildTests')
        result = run_process(argv, cwd=BRIDGE, output_dir=evidence, timeout_s=900, summary_bytes=6000)
        record = asdict(result)
        if result.outcome == 'succeeded':
            assert inputs == [pin(Path(item['path'])) for item in inputs], 'Native inputs changed during build'
            record['library'] = pin(BRIDGE / 'dist/libGrimFandango.so')
    else:
        ast.parse((ROOT / 'work/tools/apk_build.py').read_text(encoding='utf8'))
        library = BRIDGE / 'dist/libGrimFandango.so'
        assert library.is_file()
        destination = BRIDGE / 'app/lib/arm64-v8a/libGrimFandango.so'
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(library, destination)
        assert pin(destination)['sha256'] == pin(library)['sha256']
        assert not (BRIDGE / 'app/lib/armeabi-v7a').exists()
        if not args.tool_root or not args.java:
            parser.error('package requires --tool-root and Java on PATH or --java')
        builder = ApkBuilder(BRIDGE, args.tool_root, Path(args.java),
                             arm64_bridge=True, framework_path=ROOT / 'work/tool-cache/apktool-framework', timeout_s=180)
        record = builder.build('base')
        record['library'] = pin(library)
        record['guest'] = pin(BRIDGE / 'app/assets/guest_libs/libGrimFandango.so')
        record['obb_splits'] = 'Existing accepted signed splits; not rebuilt in base iteration'
    (evidence / 'result.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf8')
    print(json.dumps(dict(stage=args.stage, result=record.get('outcome'), evidence=evidence.as_posix(),
                          stdout=record.get('stdout'), stderr=record.get('stderr')), ensure_ascii=False), flush=True)
    if record.get('outcome') not in {'succeeded', 'packaging_validated'}:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
