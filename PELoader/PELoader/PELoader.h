#pragma once
#include <Windows.h>
#include "..\TypeDefs\peb.h"

namespace PELoader
{
  class TlsResolver;
  class PEFile;
  class PEImage;
}

namespace PELoader
{
  class PELoader
  {
  public:
    PELoader();
    ~PELoader();

    LPVOID LoadPE(TlsResolver* tlsResolver, LPVOID fileBuffer);

  private:
    LPVOID MapSections(PEFile* pefile);
    void ApplyRelocations(PEImage* peImage, ULONGLONG originalImageBase);
    void UpdatePEB(PEImage* peImage);
    void InitializeTlsIndex(TlsResolver* tlsResolver, PEImage* peImage);
    void InitializeTlsData(TlsResolver* tlsResolver, PEImage* peImage);
    void ResolveImports(PEImage* peImage);
    void ResolveDelayImports(PEImage* peImage);
    void ResolveDelayImport(PEImage* peImage, const IMAGE_DELAYLOAD_DESCRIPTOR* delayDesc);
    void SetupExceptionHandling(PEImage* peImage);
    void ExecuteTlsCallbacks(TlsResolver* tlsResolver, PEImage* peImage);
    void ApplySectionMemoryProtection( PEImage* peImage);
    PLDR_DATA_TABLE_ENTRY GetOwnLdrEntry(PPEB peb);
  };
}