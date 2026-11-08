"""Compile bridge-owned Java helpers with pinned tools; never contacts a device."""
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

JAVA = Path(shutil.which('java') or 'java')
JAVAC = Path(shutil.which('javac') or 'javac')
SDK = Path(os.environ.get('ANDROID_SDK_ROOT', Path(os.environ.get('LOCALAPPDATA', '.')) / 'Android/Sdk'))
ANDROID = SDK / 'platforms/android-36/android.jar'
TOOLS = Path(os.environ.get('ANDROID_TOOLS_ROOT', ROOT.parent / 'tools/android'))
PACKAGE = Path('com/doublefine/grimfandangoremastered')


def pin(path):
    data = path.read_bytes()
    return dict(path=path.as_posix(), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def method_bodies(text):
    """Ignore debug metadata, retain opcodes/registers and descriptors for review."""
    result = {}
    for block in text.split('.method ')[1:]:
        block = block.split('.end method', 1)[0]
        lines = [line.strip() for line in block.splitlines() if line.strip()
                 and not line.strip().startswith(('.line ', '.prologue', '.local ', '.end local ', '.restart local ', '#'))]
        result[lines[0]] = '\n'.join(lines[1:])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', action='store_true')
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    evidence = ROOT / 'work/evidence/qa_menu_back_20261005/java_builds' / (stamp + ('_baseline' if args.baseline else '_candidate'))
    evidence.mkdir(parents=True, exist_ok=False)
    classes, dex, smali = [evidence / name for name in ('classes', 'dex', 'smali')]
    for path in (classes, dex, smali):
        path.mkdir()
    stub = evidence / 'stubs/org/libsdl/app/SDLActivity.java'
    stub.parent.mkdir(parents=True)
    stub.write_text('''package org.libsdl.app;
public class SDLActivity extends android.app.Activity {
    public static SDLActivity mSingleton;
    public static boolean mHasFocus, mIsPaused, mIsSurfaceReady;
    protected static Thread mSDLThread;
    public static native void onNativeKeyDown(int key);
    public static native void onNativeKeyUp(int key);
}
''', encoding='utf8')
    cache = (ROOT / 'work/evidence/qa_menu_back_20261005/implementation/baseline_java' if args.baseline else BRIDGE / 'java') / PACKAGE / 'CacheReader.java'
    registry = BRIDGE / 'java' / PACKAGE / 'RegistryPreflight.java'
    sources = [cache, registry, BRIDGE / 'java' / PACKAGE / 'PortLauncher.java', stub]
    if not args.baseline:
        sources.append(BRIDGE / 'java/org/libsdl/app/PortBack.java')
    inputs = [pin(path) for path in sources + [JAVAC, JAVA, ANDROID, TOOLS / 'baksmali.jar', TOOLS / 'sdk/build-tools/37.0.0/lib/d8.jar']]
    (evidence / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n', encoding='utf8')
    commands = []

    def run(argv):
        operation = run_process([str(value) for value in argv], cwd=ROOT, output_dir=evidence / 'commands', timeout_s=180, summary_bytes=3000)
        commands.append(asdict(operation))
        if operation.outcome != 'succeeded':
            (evidence / 'failed.json').write_text(json.dumps(commands, indent=2) + '\n', encoding='utf8')
            raise RuntimeError(operation.stderr + operation.stdout)

    run([JAVAC, '-encoding', 'UTF-8', '--release', '8', '-classpath', ANDROID, '-d', classes, *sources])
    class_files = sorted((classes / PACKAGE).glob('*.class'))
    if not args.baseline:
        class_files += sorted((classes / 'org/libsdl/app').glob('PortBack*.class'))
    assert class_files
    run([JAVA, '-cp', TOOLS / 'sdk/build-tools/37.0.0/lib/d8.jar', 'com.android.tools.r8.D8',
         '--min-api', '24', '--lib', ANDROID, '--output', dex, *class_files])
    run([JAVA, '-jar', TOOLS / 'baksmali.jar', 'disassemble', dex / 'classes.dex', '-o', smali])
    outputs = sorted(smali.rglob('*.smali'))
    for path in outputs:
        relative = path.relative_to(smali).as_posix()
        assert (relative.startswith('com/doublefine/grimfandangoremastered/CacheReader')
                or relative.startswith('com/doublefine/grimfandangoremastered/RegistryPreflight')
                or relative.startswith('com/doublefine/grimfandangoremastered/PortLauncher')
                or relative.startswith('org/libsdl/app/PortBack')
                or relative.startswith('com/android/tools/r8/')), relative
    live = BRIDGE / 'app/smali'
    changes = {}
    for path in outputs:
        destination = live / path.relative_to(smali)
        new_methods = method_bodies(path.read_text(encoding='utf8'))
        old_methods = method_bodies(destination.read_text(encoding='utf8')) if destination.exists() else {}
        changes[path.relative_to(smali).as_posix()] = dict(
            added=sorted(new_methods.keys() - old_methods.keys()), removed=sorted(old_methods.keys() - new_methods.keys()),
            changed=sorted(k for k in old_methods.keys() & new_methods.keys() if old_methods[k] != new_methods[k]))
    if not args.baseline:
        protected = [live / 'org/libsdl/app/SDLActivity.smali', live / 'org/libsdl/app/SDLSurface.smali']
        protected_pins = [pin(path) for path in protected]
        prior = sorted((live / PACKAGE).glob('CacheReader*.smali')) + sorted((live / PACKAGE).glob('RegistryPreflight*.smali')) + sorted((live / PACKAGE).glob('PortLauncher*.smali')) + sorted((live / 'org/libsdl/app').glob('PortBack*.smali'))
        for path in prior:
            backup = evidence / 'before' / path.relative_to(live)
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, backup)
        # Only these explicit helper files are owned by this compiler.
        output_relatives = {path.relative_to(smali) for path in outputs}
        for path in prior:
            if path.relative_to(live) not in output_relatives:
                assert path.resolve().is_relative_to(live.resolve())
                path.unlink()
        for path in outputs:
            destination = live / path.relative_to(smali)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
        assert protected_pins == [pin(path) for path in protected]
        outer = (live / PACKAGE / 'CacheReader.smali').read_text(encoding='utf8')
        assert 'const-string v0, "GrimFandango"' in outer
        assert 'configureSurfaceGeometry(Landroid/view/Surface;II)I' in outer
        assert 'configureSurface(Landroid/view/Surface;II)V' in outer
    assert inputs == [pin(Path(item['path'])) for item in inputs], 'Input changed during Java build'
    result = dict(outcome='BASELINE_COMPILED' if args.baseline else 'JAVA_HELPERS_COMPILED_AND_APPLIED',
                  device_operations=False, inputs=inputs, outputs=[pin(path) for path in outputs],
                  dex=pin(dex / 'classes.dex'), commands=commands, method_changes=changes)
    (evidence / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    print(json.dumps(dict(outcome=result['outcome'], evidence=evidence.as_posix(), method_changes=changes), ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
