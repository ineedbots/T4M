// ==========================================================
// T4M project
// 
// Component: clientdll
// Purpose: World at War patches
//
// Initial author: UNKNOWN
// Started: 2015-07-08
// ==========================================================

#include "StdInc.h"

void loadGameOverlay();
void PatchT4();
void PatchT4_MemoryLimits();
void PatchT4_Branding();
void PatchT4_Console();
void PatchT4_Dvars();
void PatchT4_NoBorder();
void PatchT4_PreLoad();
void PatchT4_SteamDRM();
void PatchT4_FileDebug();

#define KEY_MASK_FIRE           1
#define KEY_MASK_SPRINT         2
#define KEY_MASK_MELEE          4
#define KEY_MASK_RELOAD         16
#define KEY_MASK_LEANLEFT       64
#define KEY_MASK_LEANRIGHT      128
#define KEY_MASK_PRONE          256
#define KEY_MASK_CROUCH         512
#define KEY_MASK_JUMP           1024
#define KEY_MASK_ADS_MODE       2048
#define KEY_MASK_TEMP_ACTION    4096
#define KEY_MASK_HOLDBREATH     8192
#define KEY_MASK_FRAG           16384
#define KEY_MASK_SMOKE          32768
#define KEY_MASK_NIGHTVISION    262144
#define KEY_MASK_ADS            524288
#define KEY_MASK_USE            0x28

#define MAX_G_BOTAI_ENTRIES     64

void Sys_RunInit()
{
	PatchT4();
}

StompHook SV_MoveBotHook;
StompHook SV_UpdateBots;

typedef struct client_s {
	int state; // 0 - 4
	char pad[4]; // 4 - 8
	int deltaMessage; // 8 - 12
	char pad2[4]; // 12 - 16
	int outgoingSequence; // 16 - 20
	char pad3[12]; // 20 - 32
	int isNotBot; // 32 - 36
	char pad4[762004]; // 36 - 762040
} client_t;

typedef struct usercmd_s {
	int time;
	int buttons;
	float angles[3];
	uint16_t weapon;
	char forward;
	char right;
	char pad[24];
} usercmd_t;

typedef struct BotMovementInfo_t
{
	/* Actions */
	int buttons;
	/* Movement */
	uint8_t forward;
	uint8_t right;
	/* Weapon */
	uint16_t weapon;
} BotMovementInfo_t;

static BotMovementInfo_t g_botai[MAX_G_BOTAI_ENTRIES];

struct BotAction_t
{
	const char* action;
	int key;
};

static const BotAction_t BotActions[] =
{
	{ "gostand", KEY_MASK_JUMP },
	{ "gocrouch", KEY_MASK_CROUCH },
	{ "goprone", KEY_MASK_PRONE },
	{ "fire", KEY_MASK_FIRE },
	{ "melee", KEY_MASK_MELEE },
	{ "frag", KEY_MASK_FRAG },
	{ "smoke", KEY_MASK_SMOKE },
	{ "reload", KEY_MASK_RELOAD },
	{ "sprint", KEY_MASK_SPRINT },
	{ "leanleft", KEY_MASK_LEANLEFT },
	{ "leanright", KEY_MASK_LEANRIGHT },
	{ "ads", KEY_MASK_ADS_MODE },
	{ "holdbreath", KEY_MASK_HOLDBREATH },
	{ "use", KEY_MASK_USE },
	{ "0", 8 },
	{ "1", 32 },
	{ "2", 65536 },
	{ "3", 131072 },
	{ "4", 1048576 },
	{ "5", 2097152 },
	{ "6", 4194304 },
	{ "7", 8388608 },
	{ "8", 16777216 },
	{ "9", 33554432 },
};

void SV_UpdateBotsStub()
{
	client_t *sv_clients = (client_t *)0x28C7B10;
	int sv_maxclients = *(int *)(*(int *)0x23C3AA8 + 16);
	DWORD SV_ClientThink = 0x578D80;
	unsigned int sv_servertime = *(int *)0x28C7B04;

	for (int i = 0; i < sv_maxclients; i++)
	{
		client_t *cl = &sv_clients[i];

		if (cl->state < 3)
			continue;

		if (cl->isNotBot)
			continue;

		usercmd_t usercmd = { 0 };
		usercmd.time = sv_servertime;

		usercmd.forward = g_botai[i].forward;
		usercmd.right = g_botai[i].right;
		usercmd.weapon = g_botai[i].weapon;
		usercmd.buttons = g_botai[i].buttons;
		
		cl->deltaMessage = cl->outgoingSequence - 1;

		// call SV_ClientThink
		void *a = (void *)cl;
		void *b = (void *)&usercmd;
		__asm
		{
			mov ecx, b
			mov eax, a
			call SV_ClientThink
		}
	}
}

void NOOP()
{
}

void keklol(unsigned int gNum)
{
	MessageBoxA(nullptr, va("%u", gNum), "DEBUG", 0);
}

void *GetFunction(void* caller, const char** name, int* isDev)
{
	if (!strcmp(*name, "keklol"))
	{
		*isDev = 0;
		return keklol;
	}

	return 0;
}

__declspec(naked) void GetFunctionStub2()
{
	__asm
	{
			test eax, eax
			jnz returnSafe

			sub esp, 8h
			push[esp + 10h]
			call GetFunction
			add esp, 0Ch

		// 5233AE
		returnSafe:
			retn
	}
}

__declspec(naked) void GetFunctionStub()
{
	__asm
	{
			test eax, eax
			jnz returnSafe

			sub esp, 8h
			push[esp + 10h]
			call GetFunction
			add esp, 0Ch

		// 52329F 46B46F 46C97F
		returnSafe:
			pop     edi
			pop     esi
			pop     ebp
			xor     eax, eax
			pop     ebx
			retn
	}
}

void PatchT4()
{
	//PatchT4_SteamDRM();
	//PatchT4_MemoryLimits();
	//PatchT4_Branding();
	//PatchT4_Console();
	//PatchT4_Dvars();
	//PatchT4_NoBorder();
	//PatchT4_PreLoad();
	//PatchT4_FileDebug();

	// Check if game got started using steam
	//if (!GetModuleHandle("gameoverlayrenderer.dll"))
	//	loadGameOverlay(); // nullsub 

	for (int i = 0; i < MAX_G_BOTAI_ENTRIES; i++)
	{
		g_botai[i] = { 0 };
		g_botai[i].weapon = 1;
	}

	SV_UpdateBots.initialize(0x57F6C4, SV_UpdateBotsStub, 5, false);
	SV_UpdateBots.installHook();

	SV_MoveBotHook.initialize(0x57F46B, NOOP, 5, false);
	SV_MoveBotHook.installHook();

	Detours::X86::DetourFunction((PBYTE)0x52329F, (PBYTE)&GetFunctionStub, Detours::X86Option::USE_JUMP);
	Detours::X86::DetourFunction((PBYTE)0x46B46F, (PBYTE)&GetFunctionStub, Detours::X86Option::USE_JUMP);
	Detours::X86::DetourFunction((PBYTE)0x46C97F, (PBYTE)&GetFunctionStub, Detours::X86Option::USE_JUMP);
	Detours::X86::DetourFunction((PBYTE)0x5233AE, (PBYTE)&GetFunctionStub2, Detours::X86Option::USE_JUMP);
}

void PatchT4_PreLoad()
{
	nop(0x5FE685, 5); // remove optimal settings popup
	*(BYTE*)0x5FF386 = (BYTE)0xEB; // skip safe mode check
}

void PatchT4_SteamDRM()
{
	// Replace encrypted .text segment
	DWORD size = 0x3EA000;
	std::string data = GetBinaryResource(IDB_TEXT);
	uncompress((unsigned char*)0x401000, &size, (unsigned char*)data.data(), data.size());

	// Apply new entry point
	HMODULE hModule = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER header = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD)hModule + header->e_lfanew);
	ntHeader->OptionalHeader.AddressOfEntryPoint = 0x3AF316;
}

//code from https://github.com/momo5502/cod-mod/
void loadGameOverlay()
{
	try
	{
		std::string m_steamDir;
		HKEY hRegKey;

		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Valve\\Steam", 0, KEY_QUERY_VALUE, &hRegKey) == ERROR_SUCCESS)
		{
			char pchSteamDir[MAX_PATH];
			DWORD dwLength = sizeof(pchSteamDir);
			RegQueryValueExA(hRegKey, "InstallPath", NULL, NULL, (BYTE*)pchSteamDir, &dwLength);
			RegCloseKey(hRegKey);

			m_steamDir = pchSteamDir;
		}

		//Com_Printf(0, "Loading %s\\gameoverlayrenderer.dll...\n", m_steamDir.c_str());
		HMODULE overlay = LoadLibrary(va("%s\\gameoverlayrenderer.dll", m_steamDir.c_str()));

		if (overlay)
		{
			FARPROC _SetNotificationPosition = GetProcAddress(overlay, "SetNotificationPosition");

			if (_SetNotificationPosition)
			{
				((void(*)(uint32_t))_SetNotificationPosition)(1);
			}
		}
	}
	catch (int e)
	{
		//Com_Printf(0, "Failed to inject Steam's gameoverlay: %d", e);
	}
}