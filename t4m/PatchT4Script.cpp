// ==========================================================
// alterIWnet project
// 
// Component: aiw_client
// Sub-component: steam_api
// Purpose: Functionality to interact with the GameScript 
//          runtime.
//
// Initial author: NTAuthority
// Adapted: 2015-07-21
// Started: 2011-12-19
// ==========================================================

#include "StdInc.h"
#include "Script.h"


static int Scr_GetInt(int slot)
{
	int result = 0;

	DWORD _Scr_GetInt = 0x699C50;
	__asm
	{
		mov ecx, slot
		mov eax, 0
		call _Scr_GetInt
		mov result, eax
	}

	return result;
}

static char* Scr_GetString(int slot)
{
	unsigned int result = 0;
	char* ret = 0;

	DWORD _Scr_GetString = 0x699F30;
	__asm
	{
		push slot
		mov eax, 0
		call _Scr_GetString
		add esp, 4
		mov result, eax
	}

	if (result)
	{
		unsigned int heapScrPtr = *(unsigned int *)0x3702390;

		ret = (char*)(heapScrPtr + 12 * result + 4);
	}

	return ret;
}

static void Scr_AddBool(int send)
{
	DWORD _Scr_AddBool = 0x69A8D0;

	__asm
	{
		mov esi, send
		mov eax, 0
		call _Scr_AddBool
	}
}

static void Scr_AddString(char* stri)
{
	DWORD _Scr_AddString = 0x69A7E0;

	__asm
	{
		push stri
		mov eax, 0
		call _Scr_AddString
		add esp, 4
	}
}

static void FS_FreeFile(char* buffer)
{
	*(DWORD*)0x2123C18 -= 1;
	DWORD Hunk_FreeTempMemory = 0x5E4580;
	__asm
	{
		mov esi, buffer
		call Hunk_FreeTempMemory
	}
}

static int FS_ReadFile(char* path, char** buffer)
{
	char* buff = nullptr;

	DWORD _FS_ReadFile = 0x5DBFB0;
	int result;
	void* a = &buff;
	__asm
	{
		push a
		mov eax, path
		call _FS_ReadFile
		mov result, eax
		add esp, 4
	}

	*buffer = buff;
	return result;
}

static int FS_FOpenFileWrite(char *path)
{
	DWORD _FS_FOpenFileWrite = 0x5DB1F0;
	int result;

	__asm
	{
		push 0
		push path
		call _FS_FOpenFileWrite
		add     esp, 8
		mov result, eax
	}

	return result;
}

static int FS_FOpenFileAppend(char *path)
{
	DWORD _FS_FOpenFileAppend = 0x5DB2E0;
	int result;

	__asm
	{
		push 0
		push path
		call _FS_FOpenFileAppend
		add     esp, 8
		mov result, eax
	}

	return result;
}

static int FS_Write(char *buff, size_t buffSize, int fd)
{
	int result;
	DWORD _FS_Write = 0x5DBED0;

	__asm
	{
		push fd
		push buffSize
		mov ecx, buff
		call _FS_Write
		add esp, 8
		mov result, eax
	}

	return result;
}

static void FS_FCloseFile(int fd)
{
	DWORD _FS_FCloseFile = 0x5DB060;

	__asm
	{
		mov eax, fd
		call _FS_FCloseFile
	}
}


static void testMethod(unsigned int gNum)
{
	Scr_AddBool(Scr_GetInt(0));
}

static void debugBox()
{
	char* str = Scr_GetString(0);

	if (!str)
		return;

	MessageBoxA(nullptr, str, "DEBUG", 0);
}

static void fileRead()
{
	char* file = Scr_GetString(0);

	if (!file)
		return;

	char* buf;
	int size = FS_ReadFile(file, &buf);

	if (size < 0)
		return;

	Scr_AddString(buf);

	FS_FreeFile(buf);
}

static void fileWrite()
{
	char* file = Scr_GetString(0);
	if (!file)
		return;

	char* data = Scr_GetString(1);
	if (!data)
		return;

	size_t dataSize = strlen(data);
	int mode = 0; // write
	char *modeStr = Scr_GetString(2);

	if (modeStr && !strcmp(modeStr, "append"))
		mode = 1; // append

	int fd;

	if (!mode)
		fd = FS_FOpenFileWrite(file);
	else
		fd = FS_FOpenFileAppend(file);

	if (fd < 1)
		return;

	FS_Write(data, dataSize, fd);

	FS_FCloseFile(fd);

	Scr_AddBool(true);
}


static void* __cdecl GetMethods(const char** name)
{
	if (!name || !*name)
		return nullptr;

	if (!strcmp(*name, "testmethod"))
		return testMethod;

	return nullptr;
}

static DWORD sub_5305B0 = 0x5305B0;
static __declspec(naked) void GetMethodsStub()
{
	__asm
	{
		// original code
		push    edi
		push    esi
		call    sub_5305B0
		add     esp, 8

		// test if the method is still null
		test    eax, eax
		jnz     short returnSafe

		// try our custom gsc methods
		push    esi
		call    GetMethods
		add     esp, 4

		// return back
	returnSafe:
		push 53068Eh
		retn
	}
}

static void* __cdecl GetFunctions(const char* name)
{
	if (!name)
		return nullptr;

	if (!strcmp(name, "fileread"))
		return fileRead;

	if (!strcmp(name, "filewrite"))
		return fileWrite;

	if (!strcmp(name, "debugbox"))
		return debugBox;

	return nullptr;
}

static __declspec(naked) void GetFunctionStub()
{
	__asm
	{
		// original code we patched over
		push    esi
		push    edi
		xor edi, edi
		xor esi, esi
		nop

		// call our custom gsc
		push ebx
		call GetFunctions
		add     esp, 4

		// test if we need to hook our custom call
		test    eax, eax
		jz returnSafe

		// return from the function with the answer
		pop     edi
		pop     esi
		pop     ebp
		pop     ebx
		retn


	returnSafe:
		// return to normal execution
		push 52F0C0h
		retn
	}
}


void PatchT4Script()
{
	// Patch the Scr_GetMethod so we can use custom GSC calls
	Detours::X86::DetourFunction((PBYTE)0x530684, (PBYTE)&GetMethodsStub, Detours::X86Option::USE_JUMP);
	Detours::X86::DetourFunction((PBYTE)0x52F0B9, (PBYTE)&GetFunctionStub, Detours::X86Option::USE_JUMP);
}
