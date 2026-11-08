#pragma once
#include <cstdint>
#include <cstdio>
#include <sys/stat.h>

class DynarmicHost;

// Transfers stream ownership to the active POSIX FILE registry. A failed
// allocation closes the stream; the guest receives a 32-bit token, never FILE*.
uint32_t AdoptHostFile(DynarmicHost& host, FILE* stream);
bool WriteHostStat32(DynarmicHost& host, uint32_t output, const struct stat& value);
