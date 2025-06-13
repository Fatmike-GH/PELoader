#pragma once
#include <Windows.h>

void NTAPI TlsCallbackProxy(PVOID hModule, DWORD dwReason, PVOID pContext);

#ifdef _WIN64

#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_func = (PIMAGE_TLS_CALLBACK)TlsCallbackProxy;
#pragma const_seg()

#else

#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback_func")
#pragma data_seg(".CRT$XLB")
EXTERN_C PIMAGE_TLS_CALLBACK tls_callback_func = (PIMAGE_TLS_CALLBACK)TlsCallbackProxy;
#pragma data_seg()

#endif