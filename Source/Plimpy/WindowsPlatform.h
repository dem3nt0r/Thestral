#pragma once

#if !defined(_M_IX86) && !defined(_M_X64) && !defined(__i386__) && !defined(__x86_64__)
#error Plimpy supports x86 and x64 builds only.
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
