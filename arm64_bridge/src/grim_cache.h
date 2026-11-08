#pragma once

#include <jni.h>
#include <cstdint>
#include <cstdio>
#include <dirent.h>
#include <string>
#include <sys/stat.h>

class DynarmicHost;

struct GrimCacheEntry {
    std::string name;
    uint32_t source = 0;
    uint64_t offset = 0, length = 0;
    uint32_t duration_ms = 0;
};

bool BindGrimCacheGuest(DynarmicHost& host, JNIEnv* env, std::string& error);
bool RegisterGrimCacheNatives(JNIEnv* env);
bool GrimCacheReady();
bool GrimCacheLookup(const char* path, GrimCacheEntry& entry);
bool GrimCacheLegacy();
bool GrimCacheSourcePresent(unsigned source);
bool GrimCacheRussianText();
int GrimCacheLanguageSelection();
FILE* GrimCacheOpen(const char* path, const char* mode);
int GrimCacheStat(const char* path, struct stat* result);
bool GrimCacheHasDirectory(const char* path);
DIR* GrimCacheOpenDir(const char* path);
struct dirent* GrimCacheReadDir(DIR* directory);
int GrimCacheCloseDir(DIR* directory);

extern "C" {
jstring GrimCache_initialize(JNIEnv*, jclass, jobject, jobjectArray, jobjectArray);
void GrimCache_configureRussian(JNIEnv*, jclass, jboolean, jboolean);
void GrimCache_configureLanguage(JNIEnv*, jclass, jint);
void GrimCache_languageSaved(JNIEnv*, jclass, jlong, jboolean);
jint GrimCache_configureSurfaceGeometry(JNIEnv*, jclass, jobject, jint, jint);
void GrimCache_setVideoSource(JNIEnv*, jclass, jobject, jstring);
jstring GrimCache_selfCheck(JNIEnv*, jclass);
void GrimCache_onTouch(JNIEnv*, jclass, jint, jint, jint, jfloat, jfloat, jfloat);
void GrimCache_resetInput(JNIEnv*, jclass);
void GrimCache_pauseQa(JNIEnv*, jclass);
jlong GrimCache_qaCommand(JNIEnv*, jclass, jint, jlong, jstring);
jobjectArray GrimCache_qaState(JNIEnv*, jclass);
void GrimCache_audioAccepted(JNIEnv*, jclass, jint, jint, jint, jint);
jboolean GrimCache_audioProofEnabled(JNIEnv*, jclass);
}
