#pragma once
#include <Windows.h>
#include <string>
#include <vector>
BOOL ReadRegistryString(
	HKEY root, 
	const std::wstring& subkey,
	const std::wstring& valueName,
	std::wstring& out);

BOOL QueryRegistryLastWriteTime(
	HKEY root, 
	const std::wstring& subkey, 
	FILETIME& ft);

std::wstring FileTimeToString(const FILETIME& ft);