
#include "Manifest\manifest.h"
#include <Windows.h>
#include "PELoader\PELoader.h"
#include "PELoader\PEImage.h"
#include "PELoader\TlsResolver.h"
#include "BinaryFileReader\BinaryFileReader.h"
#include "TlsCallbackProxy\TlsCallbackProxy.h"

PELoader::PELoader* _peLoader = nullptr;
PELoader::TlsResolver* _tlsResolver = nullptr;
PELoader::PEImage* _peImage = nullptr;
BOOL _entryPointCalled = FALSE;

void NTAPI TlsCallbackProxy(PVOID hModule, DWORD dwReason, PVOID pContext)
{
  if (_entryPointCalled == FALSE) return;

  if (dwReason == DLL_THREAD_DETACH)
  {
    _tlsResolver->ExecuteCallbacks(_peImage, dwReason, pContext);
    _tlsResolver->ClearTlsData();
  }
  else if (dwReason == DLL_THREAD_ATTACH)
  {
    _tlsResolver->InitializeTlsData(_peImage);
    _tlsResolver->ExecuteCallbacks(_peImage, dwReason, pContext);
  }
  else if (dwReason == DLL_PROCESS_ATTACH)
  {
    _tlsResolver->ExecuteCallbacks(_peImage, dwReason, pContext);
  }
  else if (dwReason == DLL_PROCESS_DETACH)
  {
    _tlsResolver->ExecuteCallbacks(_peImage, dwReason, pContext);
  }
}

//int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow) // Usage: Change Linker->System->Subsystem to Windows
int main(int argc, char* argv[]) // Usage: Change Linker->System->Subsystem to Console
{
  // Load PE from file
  std::string file = "Example.exe";

  BinaryFileReader* fileReader = new BinaryFileReader(file);

  _peLoader = new PELoader::PELoader();
  _tlsResolver = new PELoader::TlsResolver();

  const BYTE* data = fileReader->GetBuffer();
  LPVOID imageBase = _peLoader->LoadPE(_tlsResolver, (LPVOID)data);
  _peImage = new PELoader::PEImage(imageBase);

  // Clean up
  delete _peLoader;
  _peLoader = nullptr;

  delete fileReader;
  fileReader = nullptr;

  // Call entry point
  LPVOID entryPoint = _peImage->GetEntryPoint();
  _entryPointCalled = TRUE;  
  ((void(*)())(entryPoint))();

  return 0;
}