#include "PEFile.h"

namespace PELoader
{
	PEFile::PEFile(LPVOID fileBuffer)
	{
		_buffer = (BYTE*)fileBuffer;
		_PIMAGE_DOS_HEADER = (PIMAGE_DOS_HEADER)_buffer;
		_PIMAGE_NT_HEADERS = (PIMAGE_NT_HEADERS)(_buffer + _PIMAGE_DOS_HEADER->e_lfanew);
		_PIMAGE_SECTION_HEADER = IMAGE_FIRST_SECTION(_PIMAGE_NT_HEADERS);
	}

	PEFile::~PEFile()
	{
	}
}