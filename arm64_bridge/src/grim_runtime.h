#pragma once
#include <jni.h>
#include <string>
class DynarmicHost;

// Load the single FD-mapped engine and initialize guest JNI once. No game loop.
bool EnsureGrimGuest(JNIEnv* env, std::string& error);
// Published only after guest JNI and BindGrimCacheGuest have completed.
DynarmicHost* GetGrimHost();
// Original setMountedPackage through scoped fake JNI; indices are main0/patch1.
bool MountGrimCache(JNIEnv* env, unsigned index, const char* root, std::string& error);
