#pragma once

#include <jni.h>
#include <cstdint>
#include <string>

class DynarmicHost;
struct GrimCacheEntry;

bool InstallGrimHooks(DynarmicHost& host, std::string& error);
// UI submission barrier; only the qualified owner loop can replay a lost quit.
bool GrimHooksBeginQuit();
void GrimHooksCommitQuit();
int GrimGuestLanguage();
std::string GrimGuestExternalRoot();
void GrimSelectVideoEntry(const GrimCacheEntry* entry);
void GrimHooksTouch(JNIEnv*, jint device, jint pointer, jint action, jfloat x, jfloat y, jfloat pressure);
void GrimHooksResetInput();
void GrimHooksPauseQa();
jlong GrimHooksQaCommand(JNIEnv*, jint command, jlong epoch, jstring key);
jobjectArray GrimHooksQaState(JNIEnv*);
void GrimHooksLanguageSaved(jlong sequence, bool saved);
