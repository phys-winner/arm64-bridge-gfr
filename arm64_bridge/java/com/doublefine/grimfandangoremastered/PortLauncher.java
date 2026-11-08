package com.doublefine.grimfandangoremastered;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;

public final class PortLauncher extends Activity {
    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String error;
        try {
            System.loadLibrary("GrimFandango");
            error = CacheReader.prepare(this);
            if (error == null) error = CacheReader.selfCheck();
        } catch (RuntimeException | LinkageError failure) {
            error = failure.toString();
        }
        if (error == null) {
            startActivity(new Intent().setClassName(this,
                "com.doublefine.grimfandangoremastered.GrimFandango"));
            finish();
        } else {
            new AlertDialog.Builder(this, AlertDialog.THEME_DEVICE_DEFAULT_DARK).setTitle("Grim Fandango Remastered")
                .setMessage(error).setPositiveButton(android.R.string.ok, (dialog, which) -> finish())
                .setOnCancelListener(dialog -> finish()).show();
        }
    }
}
