#pragma once
#include <windows.h>

namespace PELoader
{
  class PEImage
  {
  public:
    PEImage(LPVOID imageBase);
    ~PEImage();

    const PIMAGE_DOS_HEADER DOS_HEADER() { return _PIMAGE_DOS_HEADER; }
    const PIMAGE_NT_HEADERS NT_HEADERS() { return _PIMAGE_NT_HEADERS; }
    const PIMAGE_SECTION_HEADER SECTION_HEADER() { return _PIMAGE_SECTION_HEADER; }
    const LPVOID GetImageBase() { return _imageBase; }
    const LPVOID GetEntryPoint() { return _entryPoint; }

  private:
    PIMAGE_DOS_HEADER _PIMAGE_DOS_HEADER;
    PIMAGE_NT_HEADERS _PIMAGE_NT_HEADERS;
    PIMAGE_SECTION_HEADER _PIMAGE_SECTION_HEADER;
    LPVOID _imageBase;
    LPVOID _entryPoint;
  };
}