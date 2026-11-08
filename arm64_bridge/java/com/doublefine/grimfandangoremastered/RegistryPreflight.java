package com.doublefine.grimfandangoremastered;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/** Read-only preflight before Main_Startup can fall back to registry defaults. */
public final class RegistryPreflight {
    private RegistryPreflight() {}

    public static String check(File filesDirectory, boolean russian) {
        if (filesDirectory == null) {
            return russian ? "Каталог сохранений недоступен. Повторите запуск после восстановления доступа."
                : "The save directory is unavailable. Restore access and try again.";
        }
        File registry = new File(filesDirectory, "registry.sav");
        try {
            // exists() can return false when the parent cannot be searched.
            // Verify directory access before interpreting absence as first launch.
            if (!filesDirectory.isDirectory() || !filesDirectory.canRead()
                    || !filesDirectory.canExecute()) return problem(registry, russian);
            if (!registry.exists()) return null; // legitimate first launch
            if (!registry.isFile()) return problem(registry, russian);
            try (FileInputStream input = new FileInputStream(registry)) {
                if (input.getChannel().size() != 17180) return problem(registry, russian);
                byte[] header = new byte[4];
                int used = 0;
                while (used < header.length) {
                    int read = input.read(header, used, header.length - used);
                    if (read <= 0) return problem(registry, russian);
                    used += read;
                }
                if (header[0] != 2 || header[1] != 0 || header[2] != 0 || header[3] != 0
                        || input.getChannel().size() != 17180) return problem(registry, russian);
            }
        } catch (IOException | SecurityException failure) {
            return problem(registry, russian);
        }
        return null;
    }

    private static String problem(File registry, boolean russian) {
        return russian
            ? "Настройки и прогресс не удалось безопасно прочитать. Исходный файл оставлен без изменений: "
                + registry.getAbsolutePath() + ". Восстановите этот файл из резервной копии или исправьте его и повторите запуск."
            : "Settings and progress could not be read safely. The original file was left unchanged: "
                + registry.getAbsolutePath() + ". Restore or repair this file and try again.";
    }
}
