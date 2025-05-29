#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

class BinaryFileReader
{
public:
  BinaryFileReader(std::string& fileName);
  ~BinaryFileReader();

  const BYTE* GetBuffer() { return _buffer; }
  DWORD GetBufferSize() { return _bufferSize; }

private:
  BYTE* _buffer;
  DWORD _bufferSize;
};

