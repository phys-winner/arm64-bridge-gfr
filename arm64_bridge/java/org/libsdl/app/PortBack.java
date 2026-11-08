package org.libsdl.app;

import android.os.Build;
import android.window.OnBackInvokedCallback;
import android.window.OnBackInvokedDispatcher;

/** One committed system Back becomes the game's existing Escape input. */
public final class PortBack {
    private final SDLActivity activity;
    private Object callback;
    private boolean attached = true;

    private PortBack(SDLActivity activity) { this.activity = activity; }

    public static PortBack attach(SDLActivity activity) {
        PortBack back = new PortBack(activity);
        if (usesDispatcher()) back.callback = Api33.register(activity, back);
        return back;
    }

    public static boolean usesDispatcher() { return Build.VERSION.SDK_INT >= 33; }

    public void detach() {
        attached = false;
        if (callback != null) {
            Api33.unregister(activity, callback);
            callback = null;
        }
    }

    public void commit() {
        if (!attached || SDLActivity.mSingleton != activity || activity.isFinishing()
                || activity.isDestroyed() || !SDLActivity.mHasFocus || SDLActivity.mIsPaused
                || !SDLActivity.mIsSurfaceReady || SDLActivity.mSDLThread == null
                || !SDLActivity.mSDLThread.isAlive()) return;
        SDLActivity.onNativeKeyDown(111);
        SDLActivity.onNativeKeyUp(111);
    }

    // Keep API33 types outside the class loaded on API24..32.
    private static final class Api33 {
        static Object register(SDLActivity activity, PortBack back) {
            OnBackInvokedCallback callback = back::commit;
            activity.getOnBackInvokedDispatcher().registerOnBackInvokedCallback(
                OnBackInvokedDispatcher.PRIORITY_DEFAULT, callback);
            return callback;
        }

        static void unregister(SDLActivity activity, Object callback) {
            activity.getOnBackInvokedDispatcher().unregisterOnBackInvokedCallback(
                (OnBackInvokedCallback) callback);
        }
    }
}
