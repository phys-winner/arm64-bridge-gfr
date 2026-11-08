package com.doublefine.grimfandangoremastered;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.res.AssetManager;
import android.media.MediaPlayer;
import android.media.AudioTrack;
import android.graphics.Color;
import android.graphics.Typeface;
import android.hardware.display.DisplayManager;
import android.widget.TextView;
import android.os.Build;
import android.os.Handler;
import android.util.Log;
import android.util.AtomicFile;
import android.view.Display;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import android.view.Surface;
import android.widget.FrameLayout;
import android.widget.Toast;
import java.io.File;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Locale;
import java.util.Arrays;

public final class CacheReader {
    private static Context context;
    private static QaMenu qaMenu;
    private static Surface gameSurface;
    private static AtomicFile languageFile;
    private static int selectedLanguage = -1;
    private static boolean usingRussian;
    private static long lastLanguage;
    static { System.loadLibrary("GrimFandango"); }
    private static final boolean observeAudio = audioProofEnabled();
    static native boolean audioProofEnabled();

    public static native String initialize(AssetManager assets, String[] obbDirs, String[] apkPaths);
    public static native void configureRussian(boolean text, boolean voice);
    private static native void configureLanguage(int selection);
    private static native void languageSaved(long sequence, boolean saved);
    public static native void setVideoSource(MediaPlayer player, String path) throws IOException;
    public static native String selfCheck();
    public static native void onTouch(int device, int pointer, int action, float x, float y, float pressure);
    public static native void resetInput();
    public static native void pauseQa();
    public static native long qaCommand(int command, long epoch, String pendingKey);
    public static native String[] qaState();
    private static native int framePacingState();
    private static native void publishFrameDisplay(Surface surface, float actualHz, int actualMode, boolean ready);
    private static native void audioAccepted(int requestedSamples, int acceptedSamples, int playbackHead, int underruns);

    public static void reportAudioWrite(int requestedSamples, int acceptedSamples, AudioTrack track) {
        if (observeAudio && track != null) audioAccepted(requestedSamples, acceptedSamples, track.getPlaybackHeadPosition(), track.getUnderrunCount());
    }

    public static String prepare(Context caller) {
        context = caller.getApplicationContext();
        Locale locale = context.getResources().getConfiguration().getLocales().get(0);
        boolean russian = "ru".equals(locale.getLanguage());
        String persistenceError = RegistryPreflight.check(context.getExternalFilesDir(null), russian);
        if (persistenceError != null) return persistenceError;
        languageFile = new AtomicFile(new File(context.getExternalFilesDir(null), "port_language.bin"));
        try (FileInputStream input = languageFile.openRead()) {
            selectedLanguage = LanguageSetting.read(input);
        } catch (FileNotFoundException missing) {
            if (languageFile.getBaseFile().exists()
                    || new File(languageFile.getBaseFile().getPath() + ".bak").exists())
                return "Could not read the saved language selection. The original file was kept.";
            selectedLanguage = -1;
        } catch (IOException | SecurityException failure) {
            return "Could not read the saved language selection. The original file was kept.";
        }
        if (selectedLanguage >= 0) russian = selectedLanguage == 6;
        usingRussian = russian;
        try {
            Log.i("CacheReader", "splits=" + Arrays.toString(context.getApplicationInfo().splitSourceDirs)
                + " assets/obb=" + Arrays.toString(context.getAssets().list("obb"))
                + " locales=" + context.getResources().getConfiguration().getLocales()
                + " languageSelection=" + selectedLanguage);
        } catch (IOException failure) {
            Log.w("CacheReader", "Asset inventory failed", failure);
        }
        configureRussian(russian, russian);
        configureLanguage(selectedLanguage);
        File[] dirs = context.getObbDirs();
        String[] paths = new String[dirs.length];
        for (int i = 0; i < dirs.length; i++) paths[i] = dirs[i] == null ? "" : dirs[i].getAbsolutePath();
        String[] splits = context.getApplicationInfo().splitSourceDirs;
        String[] apks = new String[splits == null ? 1 : splits.length + 1];
        apks[0] = context.getApplicationInfo().sourceDir;
        if (splits != null) System.arraycopy(splits, 0, apks, 1, splits.length);
        return initialize(context.getAssets(), paths, apks);
    }

    public static String language() {
        if (selectedLanguage >= 0) return LanguageSetting.ISO3[selectedLanguage];
        Locale locale = context == null ? Locale.getDefault()
            : context.getResources().getConfiguration().getLocales().get(0);
        return "ru".equals(locale.getLanguage()) ? "eng" : locale.getISO3Language();
    }

    static final class LanguageSetting {
        static final String[] ISO3 = {"eng", "deu", "spa", "fra", "ita", "por", "eng"};

        static int read(InputStream input) throws IOException {
            int value = input.read();
            if (value < '0' || value > '6' || input.read() != -1)
                throw new IOException("Invalid language selection");
            return value - '0';
        }
    }

    private static boolean saveLanguage(int selection) {
        if (selection < 0 || selection > 6 || languageFile == null) return false;
        FileOutputStream output = null;
        try {
            output = languageFile.startWrite();
            output.write('0' + selection);
            output.getFD().sync();
            languageFile.finishWrite(output);
            output = null;
            try (FileInputStream input = languageFile.openRead()) {
                return LanguageSetting.read(input) == selection;
            }
        } catch (IOException | SecurityException failure) {
            if (output != null) languageFile.failWrite(output);
            Log.w("CacheReader", "Language selection could not be saved", failure);
            return false;
        }
    }

    public static void configureWindow(Activity activity) {
        View decor = activity.getWindow().getDecorView();
        decor.setSystemUiVisibility(View.SYSTEM_UI_FLAG_LAYOUT_STABLE
            | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
            | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION | View.SYSTEM_UI_FLAG_FULLSCREEN
            | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY);
        if (qaMenu == null || qaMenu.activity != activity) {
            if (qaMenu != null) qaMenu.dispose();
            qaMenu = new QaMenu(activity);
        } else qaMenu.updateDisplay();
    }

    private static native int configureSurfaceGeometry(Surface surface, int width, int height);

    public static void configureSurface(Surface surface, int width, int height) {
        int result = configureSurfaceGeometry(surface, width, height);
        if (result != 0) Log.w("CacheReaderSurface", Integer.toString(result));
        configureSurface(surface);
    }

    public static void configureSurface(Surface surface) {
        gameSurface = surface;
        if (qaMenu != null) qaMenu.updateDisplay();
        else if (surface == null) publishFrameDisplay(null, 0, 0, false);
    }

    public static void detachQa(Activity activity) {
        if (qaMenu != null && qaMenu.activity == activity) {
            qaMenu.dispose();
            qaMenu = null;
            gameSurface = null;
        }
    }

    private static final class QaMenu implements Runnable, DisplayManager.DisplayListener, ViewTreeObserver.OnWindowFocusChangeListener {
        final Activity activity;
        final Handler handler = new Handler();
        final DisplayManager displays;
        final TextView overlay;
        final boolean ru;
        boolean closed;
        long ticket;
        long requestedAt;
        long requestedEpoch;
        String shownKey = "";
        AlertDialog confirmation;
        AlertDialog options;
        long optionsEpoch;
        long lastLaunch;
        float targetHz;
        int targetMode;
        int lastFpsState = -1;
        boolean focused;

        QaMenu(Activity activity) {
            this.activity = activity;
            displays = (DisplayManager) activity.getSystemService(Context.DISPLAY_SERVICE);
            ru = usingRussian;
            lastLaunch = Long.parseLong(qaState()[9]);
            overlay = new TextView(activity);
            overlay.setTextSize(12);
            overlay.setTypeface(Typeface.MONOSPACE);
            overlay.setTextColor(Color.WHITE);
            overlay.setBackgroundColor(0xa0000000);
            overlay.setPadding(dp(4), dp(2), dp(4), dp(2));
            overlay.setVisibility(View.GONE);
            FrameLayout.LayoutParams textLayout = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.TOP | Gravity.LEFT);
            textLayout.leftMargin = dp(8);
            textLayout.topMargin = dp(8);
            activity.addContentView(overlay, textLayout);
            overlay.setOnApplyWindowInsetsListener((view, insets) -> {
                int left = 0, top = 0;
                if (Build.VERSION.SDK_INT >= 28 && insets.getDisplayCutout() != null) {
                    left = insets.getDisplayCutout().getSafeInsetLeft();
                    top = insets.getDisplayCutout().getSafeInsetTop();
                }
                FrameLayout.LayoutParams textLayoutParams = (FrameLayout.LayoutParams) overlay.getLayoutParams();
                textLayoutParams.leftMargin = dp(8) + left;
                textLayoutParams.topMargin = dp(8) + top;
                overlay.setLayoutParams(textLayoutParams);
                return insets;
            });
            overlay.requestApplyInsets();
            focused = activity.hasWindowFocus();
            overlay.getViewTreeObserver().addOnWindowFocusChangeListener(this);
            displays.registerDisplayListener(this, handler);
            updateDisplay();
            handler.post(this);
        }

        static float capHz(int selection) {
            return selection == 0 ? 30f : selection == 1 ? 45f : 60f;
        }

        static boolean usableHz(float hz) { return hz > 0 && !Float.isInfinite(hz) && !Float.isNaN(hz); }

        static Display.Mode compatibleMode(Display.Mode current, Display.Mode[] supported, int selection) {
            Display.Mode fastest = current, compatible = null;
            float cap = capHz(selection);
            for (Display.Mode candidate : supported) {
                float hz = candidate.getRefreshRate();
                if (candidate.getPhysicalWidth() != current.getPhysicalWidth()
                    || candidate.getPhysicalHeight() != current.getPhysicalHeight() || !usableHz(hz)) continue;
                if (!usableHz(fastest.getRefreshRate()) || hz > fastest.getRefreshRate()) fastest = candidate;
                double multiple = hz / (double) cap;
                // Keep fractional nominal modes, e.g.59.94/89.91, compatible.
                // If no integer multiple exists, retain the selected cap and
                // request the fastest same-resolution mode; never coerce45.
                if (multiple >= 0.995 && Math.abs(multiple - Math.rint(multiple)) <= 0.005
                    && (compatible == null || hz < compatible.getRefreshRate())) compatible = candidate;
            }
            return selection == 3 || compatible == null ? fastest : compatible;
        }

        void updateDisplay() {
            if (closed) return;
            int fpsState = framePacingState();
            int selection = fpsState & 3;
            if (lastFpsState >= 0 && (fpsState >>> 2) != (lastFpsState >>> 2)) {
                notifyUser(label("Не удалось сохранить ограничение FPS. Предыдущее значение оставлено.",
                    "Could not save the FPS limit. The previous limit was kept."));
            }
            boolean selectionChanged = lastFpsState < 0 || selection != (lastFpsState & 3);
            lastFpsState = fpsState;
            Display display = activity.getWindowManager().getDefaultDisplay();
            Display.Mode current = display.getMode();
            Display.Mode requested = compatibleMode(current, display.getSupportedModes(), selection);
            WindowManager.LayoutParams attributes = activity.getWindow().getAttributes();
            if (attributes.preferredDisplayModeId != requested.getModeId()
                || attributes.preferredRefreshRate != requested.getRefreshRate()) {
                attributes.preferredDisplayModeId = requested.getModeId();
                attributes.preferredRefreshRate = requested.getRefreshRate();
                activity.getWindow().setAttributes(attributes);
            }
            // A request is not the active Hz. Publish the fresh actual reading,
            // including fractional changes and OS-imposed lower refresh rates.
            float hz = display.getRefreshRate();
            int mode = display.getMode().getModeId();
            if (!usableHz(hz)) { publishFrameDisplay(null, 0, mode, false); return; }
            float effective = selection == 3 ? hz : Math.min(capHz(selection), hz);
            if (hz != targetHz || mode != targetMode || selectionChanged) {
                targetHz = hz;
                targetMode = mode;
                Log.i("CacheReader", "fpsMode=" + selection + " activeMode=" + mode + " actualHz=" + hz
                    + " effectiveHz=" + effective + " requestedHz=" + requested.getRefreshRate());
            }
            boolean surfaceReady = gameSurface != null && gameSurface.isValid();
            if (Build.VERSION.SDK_INT >= 30 && surfaceReady) {
                try {
                    gameSurface.setFrameRate(effective, Surface.FRAME_RATE_COMPATIBILITY_DEFAULT);
                } catch (IllegalArgumentException | IllegalStateException failure) {
                    Log.w("CacheReader", "Surface frame-rate hint unavailable", failure);
                }
            }
            publishFrameDisplay(surfaceReady ? gameSurface : null, hz, mode,
                surfaceReady && focused && !activity.isFinishing() && !activity.isDestroyed());
        }

        @Override public void onWindowFocusChanged(boolean hasFocus) {
            focused = hasFocus;
            updateDisplay();
        }

        @Override public void onDisplayChanged(int displayId) {
            if (displayId == activity.getWindowManager().getDefaultDisplay().getDisplayId()) updateDisplay();
        }
        @Override public void onDisplayAdded(int displayId) { }
        @Override public void onDisplayRemoved(int displayId) {
            if (displayId == activity.getWindowManager().getDefaultDisplay().getDisplayId())
                publishFrameDisplay(null, 0, 0, false);
        }

        int dp(int value) { return Math.round(value * activity.getResources().getDisplayMetrics().density); }
        String label(String russian, String english) { return ru ? russian : english; }
        void notifyUser(String text) { Toast.makeText(activity, text, Toast.LENGTH_LONG).show(); }

        void showOptions() {
            if (closed || activity.isFinishing() || activity.isDestroyed()
                || ticket != 0 || confirmation != null || options != null) return;
            String[] state = qaState();
            final long openedEpoch = Long.parseLong(state[0]);
            optionsEpoch = openedEpoch;
            String[] choices = {
                label("Выбрать комнату…", "Choose a room…"),
                "1".equals(state[6]) ? label("Скрыть FPS", "Hide FPS") : label("Показывать FPS", "Show FPS"),
                "1".equals(state[7]) ? label("Скрыть нагрузку", "Hide performance data") : label("Показывать нагрузку", "Show performance data"),
                label("Сбросить дополнительные функции", "Reset additional features")
            };
            options = new AlertDialog.Builder(activity, android.R.style.Theme_Material_Dialog_Alert).setTitle(label("Дополнительные возможности", "Additional features"))
                .setItems(choices, (dialog, which) -> {
                    int command = which == 0 ? 0 : which == 1 ? ("1".equals(state[6]) ? 4 : 3)
                        : which == 2 ? ("1".equals(state[7]) ? 6 : 5) : 7;
                    request(command, "", openedEpoch);
                }).setNegativeButton(label("Закрыть", "Close"), null).create();
            options.setOnDismissListener(dialog -> options = null);
            options.show();
        }

        void request(int command, String key) {
            request(command, key, Long.parseLong(qaState()[0]));
        }

        void request(int command, String key, long expectedEpoch) {
            if (ticket != 0) return;
            long result = qaCommand(command, expectedEpoch, key);
            if (result <= 0) {
                notifyUser(label("Функция сейчас недоступна. Дождитесь игры и повторите.", "Feature unavailable. Wait for gameplay and try again."));
                return;
            }
            ticket = result;
            requestedEpoch = expectedEpoch;
            requestedAt = android.os.SystemClock.uptimeMillis();
        }

        void savePendingLanguage(String[] state) {
            long languageSequence = Long.parseLong(state[11]);
            if (languageSequence != lastLanguage) {
                lastLanguage = languageSequence;
                int selection = Integer.parseInt(state[12]);
                boolean saved = saveLanguage(selection);
                languageSaved(languageSequence, saved);
                notifyUser(saved ? (selection == 6 || usingRussian
                    ? label("Язык сохранён. Перезапустите игру, чтобы применить текст и озвучку.",
                        "Language saved. Restart the game to apply text and voices.")
                    : label("Язык сохранён.", "Language saved."))
                    : label("Не удалось сохранить язык. Предыдущее значение оставлено.",
                    "Could not save the language. The previous selection was kept."));
            }
        }

        @Override public void run() {
            if (closed || activity.isFinishing() || activity.isDestroyed()) return;
            String[] state = qaState();
            savePendingLanguage(state);
            if (framePacingState() != lastFpsState) updateDisplay();
            if (options != null && Long.parseLong(state[0]) != optionsEpoch) options.dismiss();
            long launch = Long.parseLong(state[9]);
            if (launch != lastLaunch) {
                lastLaunch = launch;
                if (state[0].equals(state[10]) && activity.hasWindowFocus()) showOptions();
            }
            if (!state[8].contentEquals(overlay.getText())) overlay.setText(state[8]);
            overlay.setVisibility(state[8].isEmpty() ? View.GONE : View.VISIBLE);
            if (ticket != 0 && (Long.parseLong(state[1]) == ticket || Long.parseLong(state[0]) != requestedEpoch || android.os.SystemClock.uptimeMillis() - requestedAt > 6000)) {
                if (Long.parseLong(state[1]) != ticket || !"0".equals(state[2])) {
                    notifyUser(label("Действие недоступно в текущем состоянии игры.", "Action unavailable in the current game state."));
                } else if (!state[3].isEmpty()) {
                    Log.i("GrimQA", state[3]);
                }
                ticket = 0;
            }
            if (!state[4].isEmpty() && !state[4].equals(shownKey) && confirmation == null) {
                shownKey = state[4];
                final String key = state[4];
                final long confirmationEpoch = Long.parseLong(state[0]);
                confirmation = new AlertDialog.Builder(activity, android.R.style.Theme_Material_Dialog_Alert)
                    .setTitle(label("Переход в комнату", "Room transition"))
                    .setMessage(label("Перейти в ", "Go to ") + state[5] + "?\n\n"
                        + label("Переход может изменить прохождение. Сохраните игру заранее.", "This may change your progress. Save your game beforehand."))
                    .setPositiveButton(label("Перейти", "Go"), (dialog, which) -> request(2, key, confirmationEpoch))
                    .setNegativeButton(label("Отмена", "Cancel"), (dialog, which) -> request(1, key, confirmationEpoch))
                    .setOnCancelListener(dialog -> request(1, key, confirmationEpoch)).create();
                confirmation.setOnDismissListener(dialog -> confirmation = null);
                confirmation.show();
            }
            if (state[4].isEmpty()) {
                shownKey = "";
                if (confirmation != null) confirmation.dismiss();
            }
            handler.postDelayed(this, 200);
        }

        void dispose() {
            savePendingLanguage(qaState());
            closed = true;
            publishFrameDisplay(null, 0, 0, false);
            ViewTreeObserver tree = overlay.getViewTreeObserver();
            if (tree.isAlive()) tree.removeOnWindowFocusChangeListener(this);
            displays.unregisterDisplayListener(this);
            handler.removeCallbacks(this);
            if (confirmation != null) confirmation.dismiss();
            if (options != null) options.dismiss();
            if (overlay.getParent() instanceof ViewGroup) ((ViewGroup) overlay.getParent()).removeView(overlay);
        }
    }
}
