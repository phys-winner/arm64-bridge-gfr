"""Exercise the compiled language-file parser without loading the native game."""
from datetime import datetime, timezone
import hashlib
import json
import shutil
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'work/tools'))
from process_tools import run_process


def main():
    builds = ROOT / 'work/evidence/qa_menu_back_20261005/java_builds'
    build = sorted(builds.glob('*_candidate/result.json'))[-1].parent
    pins = json.loads((build / 'inputs.json').read_text(encoding='utf-8'))
    source = ROOT / 'arm64_bridge/java/com/doublefine/grimfandangoremastered/CacheReader.java'
    assert next(p['sha256'] for p in pins if p['path'] == source.as_posix()) == hashlib.sha256(source.read_bytes()).hexdigest()
    output = ROOT / 'work/evidence/locale_menu_20261011' / ('unit_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
    fixture = output / 'com/doublefine/grimfandangoremastered/LanguageFixture.java'
    fixture.parent.mkdir(parents=True)
    fixture.write_text('''package com.doublefine.grimfandangoremastered;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
public final class LanguageFixture {
    static int checks;
    static void check(boolean value) {
        checks++; if (!value) throw new AssertionError("check " + checks);
    }
    public static void main(String[] args) throws Exception {
        for (int i = 0; i <= 6; i++)
            check(CacheReader.LanguageSetting.read(new ByteArrayInputStream(new byte[]{(byte)('0'+i)})) == i);
        for (String invalid : new String[]{"", "-1", "7", "99", "6\\n", "0x", "English", "Русский"}) {
            try {
                CacheReader.LanguageSetting.read(new ByteArrayInputStream(invalid.getBytes(StandardCharsets.UTF_8)));
                throw new AssertionError("Accepted " + invalid);
            } catch (IOException expected) { checks++; }
        }
        try {
            CacheReader.LanguageSetting.read(new InputStream() {
                public int read() throws IOException { throw new IOException("unreadable"); }
            });
            throw new AssertionError("Ignored read failure");
        } catch (IOException expected) { checks++; }
        check(Arrays.equals(CacheReader.LanguageSetting.ISO3,
            new String[]{"eng", "deu", "spa", "fra", "ita", "por", "eng"}));
        System.out.println("PASS: " + checks + " language parsing, failure and native-slot checks");
    }
}
''', encoding='utf-8')
    classes = build / 'classes'
    java = Path(shutil.which('java') or 'java')
    compile_result = run_process([str(java.with_name('javac.exe')), '-encoding', 'UTF-8', '--release', '8',
        '-classpath', str(classes), '-d', str(output), str(fixture)], cwd=ROOT, output_dir=output/'compile', timeout_s=20)
    assert compile_result.outcome == 'succeeded', compile_result.stderr
    result = run_process([str(java), '-cp', str(output)+';'+str(classes),
        'com.doublefine.grimfandangoremastered.LanguageFixture'], cwd=ROOT, output_dir=output/'run', timeout_s=10)
    assert result.outcome == 'succeeded', result.stderr
    print(result.stdout.strip())
    print('Evidence:', output)


if __name__ == '__main__':
    main()
