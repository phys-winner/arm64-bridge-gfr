"""Bounded standalone AArch64/ART checks on the explicitly selected bridge target."""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
from pathlib import Path
import re
import sys

BRIDGE = Path(__file__).resolve().parent
ROOT = BRIDGE.parent
sys.path.insert(0, str(ROOT / 'work/tools'))
from process_tools import adb_shell_argv, run_process, start_adb_server

SDK = Path(os.environ.get('ANDROID_SDK_ROOT', Path(os.environ.get('LOCALAPPDATA', '.')) / 'Android/Sdk'))
ADB = SDK / 'platform-tools/adb.exe'
JDK = Path(shutil.which('java') or 'java').parent
D8 = SDK / 'build-tools/37.0.0/lib/d8.jar'


def pin(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return dict(path=path.as_posix(), bytes=path.stat().st_size, sha256=digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['probe', 'regression'])
    parser.add_argument('--serial', required=True)
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    evidence = ROOT / 'work/evidence/bridge_start/device_tests' / (stamp + '_' + args.stage)
    evidence.mkdir(parents=True, exist_ok=False)
    record = dict(serial=args.serial, stage=args.stage, operations={},
                  scope='Standalone boundary checks; not game or final 16KiB acceptance')

    def run(name, argv, timeout=15):
        result = run_process(argv, cwd=ROOT, output_dir=evidence, timeout_s=timeout, summary_bytes=100000)
        record['operations'][name] = asdict(result)
        print(f'{name}: {result.outcome}', flush=True)
        if result.outcome != 'succeeded':
            raise RuntimeError(f'{name}: {result.outcome}; logs {Path(result.stdout_log).parent}')
        return result.stdout.replace('\r', '')

    def shell(name, argv, timeout=15):
        return run(name, adb_shell_argv(ADB, args.serial, argv), timeout)

    try:
        server = start_adb_server(ADB, cwd=ROOT, output_dir=evidence, timeout_s=15)
        record['operations']['adb_server'] = asdict(server)
        assert server.outcome == 'succeeded'
        assert run('get_state', [str(ADB), '-s', args.serial, 'get-state']).strip() == 'device'
        props = dict(re.findall(r'^\[([^]]+)\]: \[([^]]*)\]$', shell('getprop', ['getprop']), re.M))
        assert props.get('ro.boot.serialno', props.get('ro.serialno')) == args.serial, 'Selected device identity mismatch'
        assert 'arm64-v8a' in props['ro.product.cpu.abilist64'].split(',')
        page_size = int(shell('page_size', ['getconf', 'PAGESIZE']).strip())
        record['identity'] = dict(device=props['ro.product.device'], sdk=props['ro.build.version.sdk'],
                                  abi64=props['ro.product.cpu.abilist64'], abi32=props['ro.product.cpu.abilist32'],
                                  runtime_page_size=page_size)
        assert page_size in (4096, 16384), 'Unexpected runtime page size; review identity before continuing'
        battery = shell('battery', ['dumpsys', 'battery'])
        level = int(re.search(r'^\s*level: (\d+)$', battery, re.M).group(1))
        temperature = int(re.search(r'^\s*temperature: (\d+)$', battery, re.M).group(1)) / 10
        record['battery'] = dict(level=level, temperature_c=temperature)
        shell('window', ['dumpsys', 'window', 'displays'])
        if args.stage == 'regression':
            assert level >= 20 and temperature < 40, 'Battery/thermal prerequisite not met'
            shell('timeout_probe', ['/system/bin/timeout', '1', '/system/bin/true'])
            shell('art64_present', ['ls', '-l', '/system/bin/app_process64'])
            build = BRIDGE / 'build_arm64'
            binary = build / 'bridge_regression'
            library = build / 'libbridge_jni_regression.so'
            source = BRIDGE / 'tests/BridgeJniRegression.java'
            record['inputs'] = [pin(path) for path in [binary, library, source, D8]]
            java = evidence / 'java'
            java.mkdir()
            run('javac', [str(JDK / 'javac.exe'), '--release', '8', '-Xlint:-options',
                          '-d', str(java), str(source)], 30)
            run('d8', [str(JDK / 'java.exe'), '-cp', str(D8), 'com.android.tools.r8.D8',
                       '--min-api', '26', '--output', str(java), str(java / 'BridgeJniRegression.class')], 30)
            remote = '/data/local/tmp/grim-bridge-' + stamp.replace('.', '-')
            record['owned_remote_files'] = [remote, remote + '-jni.so', remote + '.dex']
            for name, local, destination in [('push_core', binary, remote),
                                              ('push_jni', library, remote + '-jni.so'),
                                              ('push_dex', java / 'classes.dex', remote + '.dex')]:
                run(name, [str(ADB), '-s', args.serial, 'push', str(local), destination], 30)
            shell('chmod_core', ['chmod', '755', remote])
            core = shell('core', ['/system/bin/timeout', '-k', '1', '50', remote], 60)
            assert re.search(r'PASS all \d+ checks', core), 'Core completion marker missing'
            art = shell('art', ['/system/bin/timeout', '-k', '1', '50', '/system/bin/env',
                                'CLASSPATH=' + remote + '.dex', '/system/bin/app_process64', '/system/bin',
                                'BridgeJniRegression', remote + '-jni.so'], 60)
            assert 'PASS real ART JNI regression' in art, 'ART completion marker missing'
            assert 'JNI FAIL' not in art and 'FAIL ' not in core
        record['outcome'] = 'probe_complete' if args.stage == 'probe' else 'standalone_passed'
    except BaseException as error:
        record['outcome'] = 'incomplete'
        record['error'] = str(error)
        raise
    finally:
        (evidence / 'result.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
        print(json.dumps(dict(outcome=record['outcome'], evidence=evidence.as_posix(),
                              identity=record.get('identity'), battery=record.get('battery')), ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
