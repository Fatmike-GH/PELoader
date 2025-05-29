#include <Windows.h>
#include <string>
#include <iostream>

void TlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext);
DWORD WINAPI ThreadFunction(LPVOID lpParam);

#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func") 

#pragma const_seg(".CRT$XLB")

extern __declspec(thread) UINT64 _tlsVariable = 10;
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_func = (PIMAGE_TLS_CALLBACK)TlsCallback;

#pragma const_seg()

//#define DLL_PROCESS_ATTACH   1    
//#define DLL_THREAD_ATTACH    2    
//#define DLL_THREAD_DETACH    3    
//#define DLL_PROCESS_DETACH   0

void TlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext)
{
  if (dwReason == DLL_PROCESS_ATTACH)
  {
    std::cout << std::endl;
    std::cout << "TlsCallback: DLL_PROCESS_ATTACH : Value of _tlsVariable is: " << std::to_string(_tlsVariable) << " (expected value: 10)" << std::endl;
    std::cout << "Setting _tlsVariable to 111" << std::endl;
    _tlsVariable = 111;
    std::cout << std::endl;
  }
  else if (dwReason == DLL_PROCESS_DETACH)
  {
    return;
  }
  else if (dwReason == DLL_THREAD_ATTACH)
  {
    std::cout << std::endl;
    std::cout << "TlsCallback: DLL_THREAD_ATTACH : Value of _tlsVariable is: " << std::to_string(_tlsVariable) << " (expected value: 10)" << std::endl;
    std::cout << "Setting _tlsVariable to 333" << std::endl;
    _tlsVariable = 333;
    std::cout << std::endl;
  }
  else if (dwReason == DLL_THREAD_DETACH)
  {
    std::cout << std::endl;
    std::cout << "TlsCallback: DLL_THREAD_DETACH : Value of _tlsVariable is : " << std::to_string(_tlsVariable) << " (expected value : 444)" << std::endl;
    std::cout << std::endl;
  }
}

DWORD WINAPI ThreadFunction(LPVOID lpParam)
{
  std::cout << "New thread: Value of _tlsVariable is: " << std::to_string(_tlsVariable) << " (expected value: 333)" << std::endl;

  std::cout << "New thread: Setting _tlsVariable to 444" << std::endl;
  _tlsVariable = 444;

  std::cout << "New thread: Value of _tlsVariable is: " << std::to_string(_tlsVariable) << " (expected value: 444)" << std::endl;

  return 0;
}

int main()
{
  std::cout << "Main thread: Value of _tlsVariable is: " << std::to_string(_tlsVariable) << " (expected value: 111)" << std::endl;

  std::cout << "Main thread: Setting _tlsVariable to 222" << std::endl;
  _tlsVariable = 222;

  std::cout << "Main thread: Value of _tlsVariable is: " << std::to_string(_tlsVariable) << " (expected value: 222)" << std::endl;

  std::cout << "Main thread: Starting thread..." << std::endl;

  DWORD threadId = 0;
  HANDLE threadHandle = CreateThread(NULL, 0, ThreadFunction, nullptr, 0, &threadId);
  if (threadHandle == NULL)
  {
    std::cout << "Thread creation failed." << std::endl;
    return 0;
  }

  WaitForSingleObject(threadHandle, INFINITE);
  CloseHandle(threadHandle);

  std::cout << "Main thread: Thread has finished execution." << std::endl;
  std::cout << "Main thread: Value of _tlsVariable is: " << std::to_string(_tlsVariable) << " (expected value: 222)" << std::endl;

  std::cout << std::endl;
  std::cout << "Press a key to exit...";
  std::cin.get();

  return 0;
}
