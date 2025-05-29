#include "TlsResolver.h"
#include "PEFile.h"
#include "PEImage.h"
#include "..\TypeDefs\peb.h"

namespace PELoader
{
  TlsResolver::TlsResolver()
  {
    PEImage peLoaderImage(GetModuleHandle(nullptr));
    _tlsIndex = GetTlsIndex(&peLoaderImage); // Get tls index of pe loader. It has been initialized by windows loader. Since we do not use tls data (only one tls callback (TlsCallbackProxy)) we can use this index.
  }

  TlsResolver::~TlsResolver()
  {
  }

  void TlsResolver::InitializeTlsIndex(PEImage* peImage)
  {
    PIMAGE_TLS_DIRECTORY tlsDirectory = GetTlsDirectory(peImage);
    if (tlsDirectory == nullptr || !HasTlsData(tlsDirectory)) return;
    SetTlsIndex(tlsDirectory, _tlsIndex);
  }

  void TlsResolver::InitializeTlsData(PEImage* peImage)
  {
    PIMAGE_TLS_DIRECTORY tlsDirectory = GetTlsDirectory(peImage);
    if (tlsDirectory == nullptr || !HasTlsData(tlsDirectory)) return;

    LPVOID tlsData = CreateTlsData(tlsDirectory);
    if (tlsData == nullptr) return;

    SetTlsData(_tlsIndex, tlsData);
  }

  void TlsResolver::ClearTlsData()
  {
    if (_tlsIndex == TLS_OUT_OF_INDEXES) return;
    LPVOID tlsData = GetTlsData(_tlsIndex);
    if (tlsData != nullptr)
    {
      VirtualFree(tlsData, 0, MEM_RELEASE);
    }
    SetTlsData(_tlsIndex, nullptr);
  }

  void TlsResolver::ExecuteCallbacks(PEImage* peImage, DWORD reason, PVOID context)
  {
    // AddressOfCallBacks points to an array of function pointers (VAs).
    // These VAs are absolute addresses and can be used after relocation.

    PIMAGE_TLS_DIRECTORY tlsDirectory = GetTlsDirectory(peImage);
    if (tlsDirectory == nullptr || !HasTlsCallbacks(tlsDirectory)) return;

    PIMAGE_TLS_CALLBACK* tlsCallbacks = (PIMAGE_TLS_CALLBACK*)(tlsDirectory->AddressOfCallBacks);
    while (*tlsCallbacks)
    {
      (*tlsCallbacks)(peImage->GetImageBase(), reason, context);
      tlsCallbacks++;
    }
  }

  PIMAGE_TLS_DIRECTORY TlsResolver::GetTlsDirectory(PEImage* peImage)
  {
    PIMAGE_DATA_DIRECTORY tlsDataDir = &peImage->NT_HEADERS()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDataDir->Size == 0 || tlsDataDir->VirtualAddress == 0) return nullptr;

    PIMAGE_TLS_DIRECTORY tlsDirectory = (PIMAGE_TLS_DIRECTORY)((BYTE*)peImage->GetImageBase() + tlsDataDir->VirtualAddress);
    return tlsDirectory;
  }

  BOOL TlsResolver::HasTlsData(PIMAGE_TLS_DIRECTORY tlsDirectory)
  {
    if (tlsDirectory != nullptr && tlsDirectory->AddressOfIndex != 0 && tlsDirectory->StartAddressOfRawData != 0 && tlsDirectory->EndAddressOfRawData != 0)
    {
      return TRUE;
    }
    return FALSE;
  }

  BOOL TlsResolver::HasTlsCallbacks(PIMAGE_TLS_DIRECTORY tlsDirectory)
  {
    if (tlsDirectory != nullptr && tlsDirectory->AddressOfCallBacks != 0)
    {
      PIMAGE_TLS_CALLBACK* tlsCallbacks = (PIMAGE_TLS_CALLBACK*)(tlsDirectory->AddressOfCallBacks);
      return (*tlsCallbacks != nullptr);
    }
    return FALSE;
  }

  ULONG TlsResolver::GetTlsIndex(PEImage* peImage)
  {
    PIMAGE_TLS_DIRECTORY tlsDirectory = GetTlsDirectory(peImage);
    if (tlsDirectory == nullptr) return 0;
    ULONG* tlsIndexAddress = (ULONG*)(tlsDirectory->AddressOfIndex); // This is an absolute VA after relocations
    if (tlsIndexAddress == nullptr) return 0;

    return *tlsIndexAddress;
  }

  void TlsResolver::SetTlsIndex(PIMAGE_TLS_DIRECTORY tlsDirectory, ULONG tlsIndex)
  {
    ULONG* tlsIndexAddress = (ULONG*)(tlsDirectory->AddressOfIndex); // This is an absolute VA after relocations
    if (tlsIndexAddress == nullptr) return;
    *tlsIndexAddress = tlsIndex;
  }

  LPVOID TlsResolver::CreateTlsData(PIMAGE_TLS_DIRECTORY tlsDirectory)
  {
    size_t rawDataSize = (BYTE*)tlsDirectory->EndAddressOfRawData - (BYTE*)tlsDirectory->StartAddressOfRawData;
    size_t totalDataSize = rawDataSize + tlsDirectory->SizeOfZeroFill;

    // Allocate memory for the TLS data for the current thread
    LPVOID tlsDataBlock = VirtualAlloc(nullptr, totalDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!tlsDataBlock) return nullptr;

    // Copy the default TLS data to the thread specific memory
    if (rawDataSize > 0 && tlsDirectory->StartAddressOfRawData != 0)
    {
      // StartAddressOfRawData is a VA, it should be an absolute pointer after relocations.
      memcpy(tlsDataBlock, (void*)tlsDirectory->StartAddressOfRawData, rawDataSize);
    }

    if (tlsDirectory->SizeOfZeroFill > 0)
    {
      memset((BYTE*)tlsDataBlock + rawDataSize, 0, tlsDirectory->SizeOfZeroFill);
    }

    return tlsDataBlock;
  }

  void TlsResolver::SetTlsData(ULONG tlsIndex, LPVOID tlsData)
  {
    // Update the TEB directly, because TlsSetValue will NOT set it in TEB.
    PTEB teb = NtCurrentTeb();
    if (teb)
    {
      if (tlsIndex < 64)
      {
        // DWORD64* ThreadLocalStoragePointer = (DWORD64*)__readgsqword(0x58);
        // Directly set the TEB slot
        ((ULONG_PTR*)teb->ThreadLocalStoragePointer)[tlsIndex] = (ULONG_PTR)tlsData;
      }
      else
      {
        PEB* peb = teb->ProcessEnvironmentBlock;
        PVOID* tlsArray = (PVOID*)peb->TlsExpansionSlots;
        if (!tlsArray)
        {
          peb->TlsExpansionSlots = (PVOID*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PVOID) * 1024);
        }
        if (peb->TlsExpansionSlots)
        {
          peb->TlsExpansionSlots[tlsIndex - 64] = tlsData;
        }
      }
    }
  }

  LPVOID TlsResolver::GetTlsData(ULONG tlsIndex)
  {
    PTEB teb = NtCurrentTeb();
    if (teb)
    {
      if (tlsIndex < 64)
      {
        return (LPVOID)((ULONG_PTR*)teb->ThreadLocalStoragePointer)[tlsIndex];
      }
      else
      {
        PEB* peb = teb->ProcessEnvironmentBlock;
        if (peb->TlsExpansionSlots)
        {
          return peb->TlsExpansionSlots[tlsIndex - 64];
        }
      }
    }
    return nullptr;
  }
}

