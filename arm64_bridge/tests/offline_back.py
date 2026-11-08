"""Run the actual Back helper against desktop JVM lifecycle/dispatcher fixtures."""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import shutil
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'work/tools'))
from process_tools import run_process

FIXTURES = {
    'android/os/Build.java': '''package android.os;
public class Build { public static class VERSION { public static int SDK_INT; } }
''',
    'android/window/OnBackInvokedCallback.java': '''package android.window;
public interface OnBackInvokedCallback { void onBackInvoked(); }
''',
    'android/window/OnBackInvokedDispatcher.java': '''package android.window;
public class OnBackInvokedDispatcher {
    public static final int PRIORITY_DEFAULT = 0;
    public OnBackInvokedCallback callback;
    public int registered, unregistered, priority;
    public void registerOnBackInvokedCallback(int p, OnBackInvokedCallback c) {
        if (callback != null) throw new AssertionError("duplicate callback");
        priority = p; callback = c; registered++;
    }
    public void unregisterOnBackInvokedCallback(OnBackInvokedCallback c) {
        if (callback != c) throw new AssertionError("wrong callback removed");
        callback = null; unregistered++;
    }
}
''',
    'org/libsdl/app/SDLActivity.java': '''package org.libsdl.app;
import java.util.ArrayList;
import android.window.OnBackInvokedDispatcher;
public class SDLActivity {
    public static SDLActivity mSingleton;
    public static boolean mHasFocus, mIsPaused, mIsSurfaceReady;
    protected static Thread mSDLThread;
    public static final ArrayList<Integer> events = new ArrayList<>();
    public boolean finishing, destroyed;
    public final OnBackInvokedDispatcher dispatcher = new OnBackInvokedDispatcher();
    public boolean isFinishing() { return finishing; }
    public boolean isDestroyed() { return destroyed; }
    public OnBackInvokedDispatcher getOnBackInvokedDispatcher() { return dispatcher; }
    public static void onNativeKeyDown(int key) { events.add(key); }
    public static void onNativeKeyUp(int key) { events.add(-key); }
}
''',
    'org/libsdl/app/BackFixture.java': '''package org.libsdl.app;
import android.os.Build;
import android.window.OnBackInvokedCallback;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
public final class BackFixture {
    static int checks;
    static void check(boolean value, String message) {
        checks++; if (!value) throw new AssertionError(message);
    }
    static void blocked(PortBack back, String label) {
        SDLActivity.events.clear(); back.commit();
        check(SDLActivity.events.isEmpty(), label);
    }
    static void pair(PortBack back, String label) {
        SDLActivity.events.clear(); back.commit();
        check(SDLActivity.events.equals(Arrays.asList(111, -111)), label);
    }
    public static void main(String[] args) throws Exception {
        Build.VERSION.SDK_INT = Integer.parseInt(args[0]);
        SDLActivity activity = new SDLActivity();
        SDLActivity.mSingleton = activity;
        PortBack back = PortBack.attach(activity);
        boolean modern = Build.VERSION.SDK_INT >= 33;
        check(activity.dispatcher.registered == (modern ? 1 : 0), "API registration boundary");
        check(SDLActivity.events.isEmpty(), "registration emits no game input");
        if (modern) check(activity.dispatcher.priority == 0, "default priority");
        blocked(back, "loading consumes Back without SDL calls");
        SDLActivity.mHasFocus = true; SDLActivity.mIsSurfaceReady = true;
        CountDownLatch released = new CountDownLatch(1), started = new CountDownLatch(1);
        Thread thread = new Thread(() -> {
            started.countDown();
            try { released.await(); } catch (InterruptedException e) { throw new AssertionError(e); }
        });
        thread.start(); started.await(); SDLActivity.mSDLThread = thread;
        OnBackInvokedCallback committed = activity.dispatcher.callback;
        try {
            if (modern) {
                committed.onBackInvoked();
                check(SDLActivity.events.equals(Arrays.asList(111, -111)), "one platform commit gives one Escape pair");
            }
            pair(back, "ready legacy/fallback commit");
            SDLActivity.mHasFocus = false; blocked(back, "dialog or other window focus"); SDLActivity.mHasFocus = true;
            SDLActivity.mIsPaused = true; blocked(back, "paused activity"); SDLActivity.mIsPaused = false;
            SDLActivity.mIsSurfaceReady = false; blocked(back, "lost surface"); SDLActivity.mIsSurfaceReady = true;
            activity.finishing = true; blocked(back, "finishing activity"); activity.finishing = false;
            activity.destroyed = true; blocked(back, "destroyed activity"); activity.destroyed = false;
            SDLActivity.mSingleton = new SDLActivity(); blocked(back, "replaced singleton"); SDLActivity.mSingleton = activity;
            SDLActivity.mSDLThread = null; blocked(back, "absent SDL thread"); SDLActivity.mSDLThread = thread;
            back.detach();
            check(activity.dispatcher.unregistered == (modern ? 1 : 0), "stored callback unregistered");
            blocked(back, "stale callback after detach");
            if (modern) {
                committed.onBackInvoked();
                check(SDLActivity.events.isEmpty(), "queued old callback ignored");
            }
            back.detach();
            check(activity.dispatcher.unregistered == (modern ? 1 : 0), "detach idempotent");
        } finally { released.countDown(); thread.join(1000); }
        check(!thread.isAlive(), "fixture thread closed");
        SDLActivity.mSDLThread = thread;
        PortBack ended = PortBack.attach(activity);
        blocked(ended, "terminated SDL thread"); ended.detach();
        System.out.println("PASS API=" + Build.VERSION.SDK_INT + " checks=" + checks);
    }
}
''',
}


def pin(path):
    data = path.read_bytes()
    return dict(path=path.as_posix(), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    evidence = ROOT / 'work/evidence/qa_menu_back_20261005/offline_back' / stamp
    evidence.mkdir(parents=True, exist_ok=False)
    fixture_paths = []
    for name, source in FIXTURES.items():
        path = evidence / 'fixtures' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding='utf8')
        fixture_paths.append(path)
    source = ROOT / 'arm64_bridge/java/org/libsdl/app/PortBack.java'
    classes = evidence / 'classes'
    classes.mkdir()
    operations = []
    source_pin = pin(source)

    def run(argv):
        result = run_process(argv, cwd=ROOT, output_dir=evidence / 'commands', timeout_s=30, summary_bytes=2000)
        operations.append(asdict(result))
        if result.outcome != 'succeeded':
            raise AssertionError(result.stdout + result.stderr)

    run([shutil.which('javac') or 'javac', '--release', '8', '-encoding', 'UTF-8', '-d', str(classes),
         *map(str, fixture_paths), str(source)])
    for api in (24, 32, 33, 37):
        run([shutil.which('java') or 'java', '-cp', str(classes), 'org.libsdl.app.BackFixture', str(api)])
    assert pin(source) == source_pin
    record = dict(outcome='DESKTOP_JVM_FIXTURES_PASSED', source=source_pin, operations=operations,
                  fixture_inputs=[pin(path) for path in fixture_paths], device_operations=False,
                  limits='Fixtures verify the actual Java helper only; Android/SDL gesture and dialog behavior is not hardware validated.')
    (evidence / 'result.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf8')
    print(json.dumps(dict(outcome=record['outcome'], evidence=evidence.as_posix(),
                         results=[r['stdout'].strip() for r in operations[1:]])), flush=True)


if __name__ == '__main__':
    main()
