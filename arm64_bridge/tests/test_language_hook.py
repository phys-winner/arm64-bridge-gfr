"""Compile the production language mapping against startup and restore invariants."""
import json
import os
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def main():
    source = (ROOT / 'arm64_bridge/src/grim_hooks.cpp').read_text(encoding='utf-8')
    hook = re.search(r'^void language_hook\(Jit& jit, Host&\) \{\n(.*?)^\}',
                     source, flags=re.MULTILINE | re.DOTALL)
    assert hook, 'language_hook source shape changed; review this regression'
    body = re.sub(r'^\s*//[^\n]*\n', '', hook[1], flags=re.MULTILINE)
    mapping = re.fullmatch(
        r'\s*const int selection = GrimCacheLanguageSelection\(\);\s*'
        r'jit\.Regs\(\)\[0\] = call\("zg_SetLanguage", \{([^{};\n]+)\}\);\s*', body)
    assert mapping, 'language_hook body changed; review this regression'
    expression = mapping[1].replace('jit.Regs()[0]', 'requested')
    program = (
        'using uint32_t = unsigned int;\n'
        'static_assert(sizeof(uint32_t) == 4);\n'
        'constexpr uint32_t language(int selection, bool language_bootstrap, uint32_t requested) {\n'
        f'    return {expression};\n'
        '}\n')
    checks = 0
    for selection in range(-1, 7):
        for requested in range(6):
            for bootstrap in (False, True):
                expected = requested
                if selection == 6:
                    expected = 0  # Russian resources occupy English for the entire process.
                elif bootstrap and selection >= 0:
                    expected = selection
                program += (f'static_assert(language({selection}, {str(bootstrap).lower()}, '
                            f'{requested}) == {expected});\n')
                checks += 1
    config = {'ndk_version': os.environ.get('ANDROID_NDK_VERSION', '27.2.12479018')}
    sdk = Path(os.environ.get('ANDROID_SDK_ROOT') or Path(os.environ['LOCALAPPDATA']) / 'Android/Sdk')
    compiler = sdk / 'ndk' / config['ndk_version'] / 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe'
    result = subprocess.run([str(compiler), '--target=aarch64-linux-android26', '-std=c++17',
                             '-Wall', '-Wextra', '-Werror', '-fsyntax-only', '-x', 'c++', '-'],
                            input=program, capture_output=True, text=True, encoding='utf-8', timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    print(f'PASS: {checks} production language mappings, Russian restore and original hot switching')


if __name__ == '__main__':
    main()
