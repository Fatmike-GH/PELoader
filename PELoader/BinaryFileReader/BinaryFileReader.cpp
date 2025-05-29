#include <fstream>
#include "BinaryFileReader.h"

BinaryFileReader::BinaryFileReader(std::string& fileName)
{
  std::ifstream file;
  file.open(fileName, std::ios::binary | std::ios::in);

  file.seekg(0, file.end);
  _bufferSize = (int)file.tellg();
  file.seekg(0, file.beg);
  _buffer = new BYTE[_bufferSize];
  file.read((char*)_buffer, _bufferSize);
}

BinaryFileReader::~BinaryFileReader()
{
  delete[] _buffer;
  _buffer = nullptr;
}

