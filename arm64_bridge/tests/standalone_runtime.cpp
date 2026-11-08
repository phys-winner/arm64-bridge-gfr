#include <jni.h>

// The standalone libc/ELF/GLES runner has no ART VM; JNI is exercised by the
// separate jni_regression fixture under the real Java test harness.
JavaVM* GetHostJavaVM() { return nullptr; }
