# Fatmike's PE Loader

A PE loader with full Thread Local Storage (TLS) support.  
Keywords: pe loader, pe loading, manual mapping, manual mapper, tls, thread local storage

## Introduction

### Motivation

My previous PE loader was unable to load both single-threaded and multi-threaded Rust executables. This limitation is due to Rust's use of Thread Local Storage (TLS) callbacks to initialize its runtime environment. A common but insufficient approach used in many PE loaders is to support TLS by simply iterating over the TLS callbacks and invoking them with the *DLL_PROCESS_ATTACH* parameter. While this may work for some executables, it is not adequate for Rust binaries or other applications with more complex TLS initialization requirements.

### Static TLS: A Brief Overview

The PE loader must handle two key aspects of Thread-Local Storage (TLS): TLS data and TLS callbacks.

#### TLS data

Each loaded module (including the main module) that uses static TLS is assigned a unique TLS index (a slot number) dynamically by the Windows loader at runtime. This index is then stored in the AddressOfIndex field of the module’s *IMAGE_TLS_DIRECTORY* structure and is used to reference the module's TLS data. It's important to note that *AddressOfIndex* does not contain the actual TLS index in the PE file; the value is assigned dynamically by the Windows loader. The TLS index is consistent across all threads, but the data it references is unique to each thread. Consequently, for every new thread, memory must be allocated for TLS data specific to that thread. The default TLS data must then be copied and stored in the thread’s *ThreadLocalStoragePointer* at the corresponding TLS index for each module. The default TLS data is stored in the *PIMAGE_TLS_DIRECTORY* of the PE file itself.

#### TLS callbacks

TLS callbacks are stored in the *AddressOfCallBacks* field of the *PIMAGE_TLS_DIRECTORY* structure. Each callback has the following the signature:

*void TlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext)*

The *dwReason* parameter indicates the reason for the callback invocation and can be one of the following:

- *DLL_PROCESS_ATTACH*  
- *DLL_PROCESS_DETACH*  
- *DLL_THREAD_ATTACH*  
- *DLL_THREAD_DETACH*

These callbacks are executed in response to the corresponding events.

## TLS Initialization: What the Windows loader handles and what must be done manually

### Windows

The PE loader uses *LoadLibrary* to resolve imports. This approach allows TLS to be automatically handled for these modules by the Windows loader.

### PE loader

- The TLS index must be retrieved and stored in the *A*ddressOfIndex* field of the *PIMAGE_TLS_DIRECTORY* for the main module  
- For each new thread (signaled by *DLL_THREAD_ATTACH*), including the main thread, TLS data memory must be allocated, the default TLS data copied, and the pointer set in the thread environment block (*TEB*) at the appropriate TLS index (*TEB->ThreadLocalStoragePointer*)
- Upon thread termination (*DLL_THREAD_DETACH*), the TLS pointer in the *TEB* at the corresponding TLS index must be cleared (set to zero)
- TLS callbacks for the main thread must be invoked with the *DLL_PROCESS_ATTACH* reason prior to transferring execution to the entry point (EP) of the target module. This represents the final initialization step before starting the main execution
- TLS callbacks must also be called for new and terminating threads and processes, using the *DLL_THREAD_ATTACH* and *DLL_THREAD_DETACH* reasons, respectively, as well as *DLL_PROCESS_ATTACH* and *DLL_PROCESS_DETACH*

### How to handle *DLL_THREAD_ATTACH*, *DLL_THREAD_DETACH* and *DLL_PROCESS_DETACH*

Handling the initial *DLL_PROCESS_ATTACH* is the simplest part, as we can execute all TLS callbacks of the target by iterating over the *AddressOfCallbacks* in the *PIMAGE_TLS_DIRECTORY* prior to invoking the target’s entry point. The challenge lies in tracking the creation/termination of new threads/processes thereafter. Initially, I considered hooking thread creation functions, but this approach has not been tested. Instead, I implemented a TLS callback proxy (``TlsCallbackProxy``) within the PE loader (main module), anticipating it to be the first TLS callback invoked. This allows the proxy to set up TLS data required for the actual TLS callbacks of the target, which are then called manually. For all other modules, TLS handling is automatically done by the Windows loader.

## Visual Studio Solution overview

The Visual Studio Solution consists of two projects:
- PE Loader
- Example

### PE Loader Project

The key aspect of the PE loader is its handling of TLS. It implements a ``TlsCallbackProxy`` to forward TLS callbacks to the target executable. Additionally, the ``PELoader::LoadPE`` method performs some additional steps for TLS initialization. I recommend to have a closer look on the following methods within the PE loader:

- ``InitializeTlsIndex``  
- ``InitializeTlsData``  
- ``ExecuteTlsCallbacks``
  
The ``InitializeTlsIndex`` method retrieves the TLS index from the PE loader itself, as this index has been assigned and initialized dynamically by the Windows loader. Since the PE loader does not directly utilize TLS data and only needs a single TLS callback (``TlsCallbackProxy``), this TLS index is reused for the target module. While I cannot guarantee that this approach is universally reliable, it has proven successful in loading a variety of target executables. Previously, I experimented with using *TlsAlloc* and *TlsFree*, but this approach was not successful.  

As you can see in the ``UpdatePEB`` method, i do not set the field *TlsIndex* of the *PLDR_DATA_TABLE_ENTRY* structure to the actual TLS index. Although I initially implemented this, it caused unexpected behavior and was subsequently removed.

### Example Project

``Example.exe`` is a test executable that utilizes both TLS data and a TLS callback. It reads and modifies the TLS data across multiple threads and also updates it within the TLS callback itself.  
If you wish, you can remove the ``TlsCallbackProxy`` by excluding the ``TlsCallbackProxy.h``header and attempt to load the executable with the PE loader. Additionally, you may experiment by removing one or more of the TLS-related methods (``InitializeTlsIndex``, ``InitializeTlsData``, ``ExecuteTlsCallbacks``) to observe how the behavior of ``Example.exe`` is affected.

## Limitations

- Although the method I use to retrieve the TLS index for the main module is experimental and may not be universally reliable, it has still proven to work across a range of tested target executables, including MSVC Console and Windows applications, Rust Console and Windows builds, and Delphi binaries.

- The target executable requires a relocation table to ensure reliable loading, as the image base of the loader may conflict with that of the target. In a practical scenario, such as when the target is loaded from a memory section rather than from disk, this issue can be resolved by rebasing the PE loader to an unused image base and removing its relocation table.

- Some executables have an embedded manifest that specifies required module versions. If such a manifest is necessary, it can be added to ``manifest.h`` within the PE loader. In a real-world scenario, when the PE loader loads the target executable from a memory section, the manifest should be extracted from the target executable and added to the PE loader as a resource.

- Error handling is not fully implemented.

