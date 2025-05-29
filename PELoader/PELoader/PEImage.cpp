#include "PEImage.h"

namespace PELoader
{
	PEImage::PEImage(LPVOID imageBase)
	{
		_imageBase = imageBase;
		_PIMAGE_DOS_HEADER = (PIMAGE_DOS_HEADER)_imageBase;
		_PIMAGE_NT_HEADERS = (PIMAGE_NT_HEADERS)((BYTE*)_imageBase + _PIMAGE_DOS_HEADER->e_lfanew);
		_PIMAGE_SECTION_HEADER = IMAGE_FIRST_SECTION(_PIMAGE_NT_HEADERS);
		_entryPoint = (BYTE*)_imageBase + _PIMAGE_NT_HEADERS->OptionalHeader.AddressOfEntryPoint;
	}

	PEImage::~PEImage()
	{
	}
}