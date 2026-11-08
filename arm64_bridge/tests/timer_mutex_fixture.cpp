#include "../src/thunks_posix.cpp"
extern "C" pthread_mutex_t* TimerTestMutex(DynarmicHost& host, uint32_t address) {
    auto mutex = GetMutex(host, address);
    return mutex ? &mutex->value : nullptr;
}
