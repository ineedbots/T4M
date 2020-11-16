#include "StdInc.h"

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


char* Scr_GetString(int slot)
{
	unsigned int result = 0;
	char* ret = 0;

	DWORD _Scr_GetString = 0x656350;
	__asm
	{
		push slot
		mov eax, slot
		call _Scr_GetString
		add esp, 4
		mov result, eax
	}

	if (result)
	{
		unsigned int heapScrPtr = *(unsigned int *)0xF66B3B8;

		ret = (char*)(heapScrPtr + 12 * result + 4);
	}

	return ret;
}

int BG_GetWeaponIndexForName(const char *weaponName)
{
	int weapIndex = 0;

	DWORD _BG_GetWeaponIndexForName = 0x41FFB0;
	__asm
	{
		push weaponName
		call _BG_GetWeaponIndexForName
		add esp, 4
		mov weapIndex, eax
	}

	return weapIndex;
}

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
	client_t* sv_clients = (client_t*)0x28C7B10;
	int sv_maxclients = *(int*)(*(int*)0x23C3AA8 + 16);
	DWORD SV_ClientThink = 0x578D80;
	unsigned int sv_servertime = *(int*)0x28C7B04;

	for (int i = 0; i < sv_maxclients; i++)
	{
		client_t* cl = &sv_clients[i];

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
		void* a = (void*)cl;
		void* b = (void*)&usercmd;
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

bool IsEntPlayer(unsigned int gNum)
{
	unsigned int* ents = (unsigned int*)0x1F8E300;
	unsigned int* ent = (unsigned int *)ents + 204 * gNum * 4;

	return ent[97];
}

void botAction(unsigned int gNum)
{
	if (gNum > MAX_G_BOTAI_ENTRIES || !IsEntPlayer(gNum))
		return;

	char* action = Scr_GetString(0);

	if (action[0] == '+')
		g_botai[gNum].buttons = 0x1;
	else
		g_botai[gNum].buttons = 0x0;
}

void* GetFunction(void* caller, const char** name, int* isDev)
{
	if (!strcmp(*name, "botaction"))
	{
		*isDev = 0;
		return botAction;
	}

	return nullptr;
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

	returnSafe:
		pop     edi
		pop     esi
		pop     ebp
		xor eax, eax
		pop     ebx
		retn
	}
}

void PatchT4MP()
{
	// init the bot commands
	for (int i = 0; i < MAX_G_BOTAI_ENTRIES; i++)
	{
		g_botai[i] = { 0 };
		g_botai[i].weapon = 1;
	}

	// Prevent the default behaviour of the bots
	Detours::X86::DetourFunction((PBYTE)0x57F46B, (PBYTE)&NOOP, Detours::X86Option::USE_CALL);

	// Have the bots perform actions according to their g_botai entry
	Detours::X86::DetourFunction((PBYTE)0x57F6C4, (PBYTE)&SV_UpdateBotsStub, Detours::X86Option::USE_CALL);

	// Patch the Scr_GetMethod so we can use custom GSC calls
	Detours::X86::DetourFunction((PBYTE)0x52329F, (PBYTE)&GetFunctionStub, Detours::X86Option::USE_JUMP);
	Detours::X86::DetourFunction((PBYTE)0x46B46F, (PBYTE)&GetFunctionStub, Detours::X86Option::USE_JUMP);
	Detours::X86::DetourFunction((PBYTE)0x46C97F, (PBYTE)&GetFunctionStub, Detours::X86Option::USE_JUMP);
	Detours::X86::DetourFunction((PBYTE)0x5233AE, (PBYTE)&GetFunctionStub2, Detours::X86Option::USE_JUMP);
}
