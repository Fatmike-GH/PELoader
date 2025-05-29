#pragma once
#include <Windows.h>

void TlsCallbackProxy(PVOID hModule, DWORD dwReason, PVOID pContext);

#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")

#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_func = (PIMAGE_TLS_CALLBACK)TlsCallbackProxy;

#pragma const_seg()