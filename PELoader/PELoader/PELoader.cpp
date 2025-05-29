#include <Windows.h>
#include "PELoader.h"
#include "PEFile.h"
#include "PEImage.h"
#include "TlsResolver.h"
#include "..\TypeDefs\peb.h"

namespace PELoader
{
  PELoader::PELoader()
  {
  }

  PELoader::~PELoader()
  {
  }

  LPVOID PELoader::LoadPE(TlsResolver* tlsResolver, LPVOID fileBuffer)
  {
    PEFile pefile(fileBuffer);
    LPVOID imageBase = MapSections(&pefile);

    PEImage peImage(imageBase); // Using the mapped pe file at actual imageBase
    ApplyRelocations(&peImage, pefile.NT_HEADERS()->OptionalHeader.ImageBase);
    UpdatePEB(&peImage);
    InitializeTlsIndex(tlsResolver, &peImage);
    InitializeTlsData(tlsResolver, &peImage);
    ResolveImports(&peImage);
    ResolveDelayImports(&peImage);
    SetupExceptionHandling(&peImage);
    ApplySectionMemoryProtection(&peImage);
    ExecuteTlsCallbacks(tlsResolver, &peImage);

    return imageBase;
  }

  LPVOID PELoader::MapSections(PEFile* pefile)
  {
    LPVOID imageBase = VirtualAlloc((LPVOID)pefile->NT_HEADERS()->OptionalHeader.ImageBase, pefile->NT_HEADERS()->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (imageBase == nullptr)
    {
      imageBase = VirtualAlloc(nullptr, pefile->NT_HEADERS()->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      if (imageBase == nullptr) return nullptr;
    }

    memcpy(imageBase, pefile->GetBuffer(), pefile->NT_HEADERS()->OptionalHeader.SizeOfHeaders);

    for (int i = 0; i < pefile->NT_HEADERS()->FileHeader.NumberOfSections; i++)
    {
      LPVOID sectionDest = (BYTE*)imageBase + pefile->SECTION_HEADER()[i].VirtualAddress;
      LPVOID sectionSrc = pefile->GetBuffer() + pefile->SECTION_HEADER()[i].PointerToRawData;
      SIZE_T sectionSize = min(pefile->SECTION_HEADER()[i].SizeOfRawData, pefile->SECTION_HEADER()[i].Misc.VirtualSize);

      memcpy(sectionDest, sectionSrc, sectionSize);
    }

    return imageBase;
  }

  void PELoader::ApplyRelocations(PEImage* peImage, ULONGLONG originalImageBase)
  {
    ULONGLONG baseDelta = (ULONGLONG)peImage->GetImageBase() - originalImageBase;
    if (baseDelta == 0) return;

    PIMAGE_DATA_DIRECTORY relocDir = &peImage->NT_HEADERS()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir->Size == 0) return;

    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)peImage->GetImageBase() + relocDir->VirtualAddress);
    while (reloc->VirtualAddress && reloc->SizeOfBlock)
    {
      int numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
      PWORD relocEntries = (PWORD)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));

      for (int i = 0; i < numEntries; i++)
      {
        WORD type = relocEntries[i] >> 12;
        WORD offset = relocEntries[i] & 0xFFF;

        switch (type)
        {
        case IMAGE_REL_BASED_ABSOLUTE:
          break;

        case IMAGE_REL_BASED_DIR64:
        {
          ULONGLONG* patchAddr = (ULONGLONG*)((BYTE*)peImage->GetImageBase() + reloc->VirtualAddress + offset);
          *patchAddr += baseDelta;
          break;
        }

        case IMAGE_REL_BASED_HIGHLOW:
        {
          DWORD* patchAddr = (DWORD*)((BYTE*)peImage->GetImageBase() + reloc->VirtualAddress + offset);
          *patchAddr += (DWORD)baseDelta;
          break;
        }

        case IMAGE_REL_BASED_HIGH:
        {
          WORD* patchAddr = (WORD*)((BYTE*)peImage->GetImageBase() + reloc->VirtualAddress + offset);
          *patchAddr += HIWORD((DWORD)baseDelta);
          break;
        }

        case IMAGE_REL_BASED_LOW:
        {
          WORD* patchAddr = (WORD*)((BYTE*)peImage->GetImageBase() + reloc->VirtualAddress + offset);
          *patchAddr += LOWORD((DWORD)baseDelta);
          break;
        }
        }
      }

      reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
    }
  }

  void PELoader::UpdatePEB(PEImage* peImage)
  {
    PEB* peb = (PEB*)__readgsqword(0x60); // Get PEB in x64

    // Required to get specific APIs like GetModuleFileName work
    PLDR_DATA_TABLE_ENTRY entry = GetOwnLdrEntry(peb);
    entry->DllBase = (PVOID)peImage->GetImageBase();
    entry->SizeOfImage = peImage->NT_HEADERS()->OptionalHeader.SizeOfImage;
    entry->EntryPoint = (PVOID)peImage->GetEntryPoint();
    entry->TlsIndex = (USHORT)TLS_OUT_OF_INDEXES; // Do not use the actual tls index here! entry->TlsIndex is TLS_OUT_OF_INDEXES by default, we leave it as is.

    // Set new image base in peb (After calling GetOwnLdrEntry!)
    peb->ImageBaseAddress = (PVOID)peImage->GetImageBase();
  }

  void PELoader::InitializeTlsIndex(TlsResolver* tlsResolver, PEImage* peImage)
  {
    tlsResolver->InitializeTlsIndex(peImage);
  }

  void PELoader::InitializeTlsData(TlsResolver* tlsResolver, PEImage* peImage)
  {
    tlsResolver->InitializeTlsData(peImage);
  }

  void PELoader::ResolveImports(PEImage* peImage)
  {
    PIMAGE_DATA_DIRECTORY importDir = &peImage->NT_HEADERS()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size == 0) return;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)peImage->GetImageBase() + importDir->VirtualAddress);
    while (importDesc->Name)
    {
      LPCSTR moduleName = (LPCSTR)((BYTE*)peImage->GetImageBase() + importDesc->Name);

      HMODULE moduleHandle = LoadLibraryA(moduleName);
      if (!moduleHandle) return; // Error

      PIMAGE_THUNK_DATA origFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)peImage->GetImageBase() + importDesc->OriginalFirstThunk);
      PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((BYTE*)peImage->GetImageBase() + importDesc->FirstThunk);

      while (origFirstThunk->u1.AddressOfData)
      {
        FARPROC functionAddress = nullptr;
        if (origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
        {
          // Import by ordinal
          WORD ordinal = (WORD)(origFirstThunk->u1.Ordinal & 0xFFFF);
          functionAddress = GetProcAddress(moduleHandle, (LPCSTR)(ULONG_PTR)ordinal);
        }
        else
        {
          // Import by name
          PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)peImage->GetImageBase() + origFirstThunk->u1.AddressOfData);
          functionAddress = GetProcAddress(moduleHandle, importByName->Name);
        }
        if (!functionAddress)
        {
          // Error
          return;
        }

        firstThunk->u1.Function = (ULONGLONG)functionAddress;

        origFirstThunk++;
        firstThunk++;
      }
      importDesc++;
    }
  }

  void PELoader::ResolveDelayImports(PEImage* peImage)
  {
    IMAGE_DATA_DIRECTORY* delayImportDirectory = &peImage->NT_HEADERS()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (delayImportDirectory->VirtualAddress == 0) return;

    IMAGE_DELAYLOAD_DESCRIPTOR* delayDesc = (IMAGE_DELAYLOAD_DESCRIPTOR*)((BYTE*)peImage->GetImageBase() + delayImportDirectory->VirtualAddress);
    while (delayDesc->DllNameRVA)
    {
      ResolveDelayImport(peImage, delayDesc);
      ++delayDesc;
    }
  }

  void PELoader::SetupExceptionHandling(PEImage* peImage)
  {
    auto exceptionDir = peImage->NT_HEADERS()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exceptionDir.VirtualAddress == 0 || exceptionDir.Size == 0) return;

    auto exceptionTable = reinterpret_cast<RUNTIME_FUNCTION*>((BYTE*)peImage->GetImageBase() + exceptionDir.VirtualAddress);
    DWORD count = exceptionDir.Size / sizeof(RUNTIME_FUNCTION);

    RtlAddFunctionTable(exceptionTable, count, reinterpret_cast<DWORD64>(peImage->GetImageBase()));
  }

  void PELoader::ApplySectionMemoryProtection(PEImage* peImage)
  {
    for (int i = 0; i < peImage->NT_HEADERS()->FileHeader.NumberOfSections; i++)
    {
      DWORD protection = PAGE_READWRITE; // Default protection

      DWORD characteristics = peImage->SECTION_HEADER()[i].Characteristics;
      if (characteristics & IMAGE_SCN_MEM_EXECUTE)
      {
        if (characteristics & IMAGE_SCN_MEM_WRITE)
        {
          protection = PAGE_EXECUTE_READWRITE;
        }
        else if (characteristics & IMAGE_SCN_MEM_READ)
        {
          protection = PAGE_EXECUTE_READ;
        }
        else
        {
          protection = PAGE_EXECUTE;
        }
      }
      else
      {
        if (characteristics & IMAGE_SCN_MEM_WRITE)
        {
          protection = PAGE_READWRITE;
        }
        else if (characteristics & IMAGE_SCN_MEM_READ)
        {
          protection = PAGE_READONLY;
        }
        else
        {
          protection = PAGE_NOACCESS;
        }
      }

      // Apply memory protection
      LPVOID sectionAddress = (BYTE*)peImage->GetImageBase() + peImage->SECTION_HEADER()[i].VirtualAddress;
      SIZE_T sectionSize = peImage->SECTION_HEADER()[i].Misc.VirtualSize;

      if (sectionSize > 0)
      {
        DWORD oldProtect = 0;
        VirtualProtect(sectionAddress, sectionSize, protection, &oldProtect);
      }
    }
  }

  void PELoader::ExecuteTlsCallbacks(TlsResolver* tlsResolver, PEImage* peImage)
  {
    tlsResolver->ExecuteCallbacks(peImage, DLL_PROCESS_ATTACH, nullptr);
  }

  void PELoader::ResolveDelayImport(PEImage* peImage, const IMAGE_DELAYLOAD_DESCRIPTOR* delayDesc)
  {
    const char* dllName = (const char*)((BYTE*)peImage->GetImageBase() + delayDesc->DllNameRVA);

    HMODULE moduleHandle = LoadLibraryA(dllName);
    if (!moduleHandle) return; // Error

    BYTE* imageBase = (BYTE*)peImage->GetImageBase();

    IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)(imageBase + delayDesc->ImportAddressTableRVA);
    IMAGE_THUNK_DATA* intt = (IMAGE_THUNK_DATA*)(imageBase + delayDesc->ImportNameTableRVA);
    IMAGE_THUNK_DATA* boundIat = (IMAGE_THUNK_DATA*)(imageBase + delayDesc->BoundImportAddressTableRVA);
    IMAGE_THUNK_DATA* unloadIat = (IMAGE_THUNK_DATA*)(imageBase + delayDesc->UnloadInformationTableRVA);

    while (intt->u1.AddressOfData)
    {
      FARPROC func = nullptr;

      if (intt->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
      {
        // Import by ordinal
        WORD ordinal = (WORD)(intt->u1.Ordinal & 0xFFFF);
        func = GetProcAddress(moduleHandle, (LPCSTR)(ULONG_PTR)ordinal);
      }
      else
      {
        // Import by name
        const IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)((BYTE*)peImage->GetImageBase() + intt->u1.AddressOfData);
        func = GetProcAddress(moduleHandle, (LPCSTR)importByName->Name);
      }

      if (!func)
      {
        // Error
        return;
      }

      // Update IAT and optionally Bound IAT and Unload IAT
      iat->u1.Function = (ULONGLONG)func;
      if (delayDesc->BoundImportAddressTableRVA)
      {
        boundIat->u1.Function = (ULONGLONG)func;
      }
      if (delayDesc->UnloadInformationTableRVA)
      {
        unloadIat->u1.Function = (ULONGLONG)func;
      }

      ++iat;
      ++intt;
      if (boundIat) ++boundIat;
      if (unloadIat) ++unloadIat;
    }
  }

  PLDR_DATA_TABLE_ENTRY PELoader::GetOwnLdrEntry(PPEB peb)
  {
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* list = &ldr->InLoadOrderModuleList;

    for (LIST_ENTRY* e = list->Flink; e != list; e = e->Flink)
    {
      PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
      if ((PBYTE)entry->DllBase == (PBYTE)GetModuleHandle(nullptr))
      {
        return entry;
      }
    }
    return nullptr;
  }
}
