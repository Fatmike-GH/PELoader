#pragma once
#include <Windows.h>

namespace PELoader
{
  class PEImage;
}

namespace PELoader
{
  class TlsResolver
  {
  public:
    TlsResolver();
    ~TlsResolver();

    void InitializeTlsIndex(PEImage* peImage);
    void InitializeTlsData(PEImage* peImage);
    void ClearTlsData();
    void ExecuteCallbacks(PEImage* peImage, DWORD reason, PVOID context);

  private:
    PIMAGE_TLS_DIRECTORY GetTlsDirectory(PEImage* peImage);

    BOOL HasTlsData(PIMAGE_TLS_DIRECTORY tlsDirectory);
    BOOL HasTlsCallbacks(PIMAGE_TLS_DIRECTORY tlsDirectory);

    ULONG GetTlsIndex(PEImage* peImage);
    void SetTlsIndex(PIMAGE_TLS_DIRECTORY tlsDirectory, ULONG tlsIndex);

    LPVOID CreateTlsData(PIMAGE_TLS_DIRECTORY tlsDirectory);
    void SetTlsData(ULONG tlsIndex, LPVOID tlsData);
    LPVOID GetTlsData(ULONG tlsIndex);

  private:
    ULONG _tlsIndex;
  };
}
