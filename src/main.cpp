#include <iostream>
#include "Nt/Def.h"
#include <vector>
#include <Psapi.h>

//https://www.unknowncheats.me/forum/general-programming-and-reversing/502738-ida-style-pattern-scanner.html
DWORD64 PatternScan(const wchar_t* module, const char* signature)
{
	static auto pattern_to_byte = [](const char* pattern)
		{
			auto bytes = std::vector<char>{};
			auto start = const_cast<char*>(pattern);
			auto end = const_cast<char*>(pattern) + strlen(pattern);

			for (auto current = start; current < end; ++current)
			{
				if (*current == '?')
				{
					++current;
					if (*current == '?')
						++current;
					bytes.push_back('\?');
				}
				else
				{
					bytes.push_back(strtoul(current, &current, 16));
				}
			}
			return bytes;
		};

	MODULEINFO mInfo;
	K32GetModuleInformation(GetCurrentProcess(), GetModuleHandleW(module), &mInfo, sizeof(mInfo));
	DWORD64 base = (DWORD64)mInfo.lpBaseOfDll;
	DWORD64 sizeOfImage = (DWORD64)mInfo.SizeOfImage;
	auto patternBytes = pattern_to_byte(signature);

	DWORD64 patternLength = patternBytes.size();
	auto data = patternBytes.data();

	for (DWORD64 i = 0; i < sizeOfImage - patternLength; i++)
	{
		bool found = true;
		for (DWORD64 j = 0; j < patternLength; j++)
		{
			char a = '\?';
			char b = *(char*)(base + i + j);
			found &= data[j] == a || data[j] == b;
		}
		if (found)
		{
			return base + i;
		}
	}
	return NULL;
}

bool myLoadLibrary(const wchar_t* name)
{
	if (!name)
		return false;

	HMODULE lib = LoadLibraryW(name);

	if (!lib)
		return false;

	FreeLibrary(lib);
	return true;
}

bool myLdrLoadDll(const wchar_t* name)
{
	if (!name)
		return false;

	//Get the func LdrLoadDll which is exported in ntdll.dll
	//We need to reinterpret_cast this, as GetProcAddress returns a FARPROC
	auto Proc = reinterpret_cast<tLdrLoadDll*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrLoadDll"));
	if (!Proc)
		return false;

	//Our handle buffer, which will contain the HMODULE
	HANDLE lib = nullptr;

	//Get RtlInitUnicodeString, which is also exported by ntdll.dll
	//We also need to reinterpret_cast, as this also returns a FARPROC
	auto Rtl = reinterpret_cast<tRtlInitUnicodeString*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString"));
	if (!Rtl)
		return false;

	//Our UNICODE_STRING buffer
	UNICODE_STRING str;

	//We call the RtlInitUnicodeString function, to fill out our "str" buffer
	Rtl(&str, name);

	//We call the "Proc" which is our "LdrLoadDll" function
	NTSTATUS stat = Proc(nullptr, 0, &str, &lib);
	if (NT_SUCCESS(stat))
	{
		//Free the library again, if it was successfully loaded
		FreeLibrary(static_cast<HMODULE>(lib));
		return true;
	}

	return false;
}

//https://www.unknowncheats.me/forum/general-programming-and-reversing/633220-sos-ldrploaddll-user-mode.html
bool myLdrpLoadDll(const wchar_t* name)
{
	if (!name)
		return false;

	//Get the func LdprLoadDll via Patternscanning
	//We need to reinterpret_cast this, as PatternScan returns a DWORD64
	auto Proc = reinterpret_cast<tLdrpLoadDll*>(PatternScan(L"ntdll.dll", "40 55 53 56 57 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 48 8B FA"));
	if (!Proc)
		return false;

	//Our handle buffer, which will contain the HMODULE
	HANDLE lib = nullptr;

	//Get RtlInitUnicodeString, which is also exported by ntdll.dll
	//We also need to reinterpret_cast, as this also returns a FARPROC
	auto Rtl = reinterpret_cast<tRtlInitUnicodeString*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString"));
	if (!Rtl)
		return false;

	//Our UNICODE_STRING buffer
	UNICODE_STRING str;

	//We call the RtlInitUnicodeString function, to fill out our "str" buffer
	Rtl(&str, name);

	//A unknown struct buffer
	LDR_UNKSTRUCT unk_struct{};

	//A pointer to a LDR_DATA_TABLE_ENTRY, which contains our loaded Dll later
	LDR_DATA_TABLE_ENTRY* entry= nullptr;

	//Call LdrpLoadDll
	NTSTATUS stat = Proc(&str, &unk_struct, 0, &entry);
	if (NT_SUCCESS(stat))
	{
		//Free dll if it was loaded successfully
		lib = entry->DllBase;
		FreeLibrary(HMODULE(EntryOut->DllBase));
		return true;
	}

	return false;
}

bool myLdrpLoadDllInternal(const wchar_t* name)
{
	if (!name)
		return false;

	//Get the func LdrpLoadDllInternal via Patternscanning
	//We need to reinterpret_cast this, as PatternScan returns a DWORD64
	auto Proc = reinterpret_cast<tLdrpLoadDllInternal*>(PatternScan(L"ntdll.dll", "4C 8B DC 45 89 43 ? 49 89 53 ? 49 89 4B ? 53 56 57 41 54 41 55 41 56 41 57 48 83 EC ? 45 8B E1 41 8B F0"));
	if (!Proc)
		return false;

	//Our handle buffer, which will contain the HMODULE
	HANDLE lib = nullptr;

	//Get RtlInitUnicodeString, which is also exported by ntdll.dll
	//We also need to reinterpret_cast, as this also returns a FARPROC
	auto Rtl = reinterpret_cast<tRtlInitUnicodeString*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString"));
	if (!Rtl)
		return false;

	//Our UNICODE_STRING buffer
	UNICODE_STRING str;

	//We call the RtlInitUnicodeString function, to fill out our "str" buffer
	//This is somehow a bit wird, in this case we are not allowed to give the FullPath
	//I did not reverse this further as it was already really exhausting, if you find out more, please let me know! :)
	Rtl(&str, L"dfscli.dll");

	//A unknown struct buffer
	LDR_UNKSTRUCT unk_struct = {};

	//Again our pointer to LDR_DATA_TABLE_ENTRY for our loaded Dll
	LDR_DATA_TABLE_ENTRY* EntryOut = nullptr;

	//Get two LdrEntrys
	//This is really important, we actually need to get two entrys
	//We firstly get the Teb (Thread Environment Block), which has a pointer to the PEB (Process Environment Block)
	//The peb has a pointer to the Ldr
	//The Ldr has a pointer to the InMemoryOrderModuleList Linked List
	//We use the CONTAINING_RECORD macro to get the entry
	
	LDR_DATA_TABLE_ENTRY pFirst = *CONTAINING_RECORD(NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Blink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	LDR_DATA_TABLE_ENTRY pSecond = *CONTAINING_RECORD(NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

	//pStat is a buffer for the parameter
	// stat will not have a real "NTSTATUS"
	// you need to checkout pStat!
	NTSTATUS pStat = {};

	//We call our LdrpLoadDllInternal
	NTSTATUS stat = Proc(&str, &unk_struct, 0, 0, &pFirst, &pSecond, &EntryOut, &pStat, 0);

	//IO check both status values
	if (NT_SUCCESS(stat) && NT_SUCCESS(pStat))
	{
		lib = EntryOut->DllBase;
		FreeLibrary(HMODULE());
		return true;
	}
	return false;
}

int wmain()
{
	const wchar_t* Dll = LR"(C:\Windows\system32\dfscli.dll)";

	if (myLoadLibrary(Dll))
	{
		std::cout << "Successfully loaded dll! [myLoadLibrary]" << std::endl;
	}

	else
		std::cout << "Failed to load dll! [myLdrpLoadDllInternal]" << std::endl;

	if (myLdrLoadDll(Dll))
	{
		std::cout << "Successfully loaded dll! [myLdrLoadDll]" << std::endl;
	}

	else
		std::cout << "Failed to load dll! [myLdrpLoadDllInternal]" << std::endl;

	if (myLdrpLoadDll(Dll))
	{
		std::cout << "Successfully loaded dll! [myLdrpLoadDll]" << std::endl;
	}

	else
		std::cout << "Failed to load dll! [myLdrpLoadDllInternal]" << std::endl;

	if (myLdrpLoadDllInternal(Dll))
	{
		std::cout << "Successfully loaded dll! [myLdrpLoadDllInternal]" << std::endl;
	}

	else
		std::cout << "Failed to load dll! [myLdrpLoadDllInternal]" << std::endl;

	return 0;
}
