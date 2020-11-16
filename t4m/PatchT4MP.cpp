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

int Scr_GetInt(int slot)
{
	int result = 0;

	DWORD _Scr_GetInt = 0x656130;
	__asm
	{
		push slot
		mov eax, slot
		call _Scr_GetInt
		add esp, 4
		mov result, eax
	}

	return result;
}

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

typedef struct {
	bool    allowoverflow;    // if false, do a Com_Error
	bool    overflowed;        // set to true if the buffer size failed (with allowoverflow set)
	bool    oob;            // set to true if the buffer size failed (with allowoverflow set)
	int        readcount;
	char* data;
	int        bit;
	int        maxsize;
	int        cursize;                // for bitwise reads and writes
	int ok;
} msg_t;

typedef enum {
	NA_BOT,
	NA_BAD,                    // an address lookup failed
	NA_LOOPBACK,
	NA_BROADCAST,
	NA_IP,
	NA_IPX,
	NA_BROADCAST_IPX
} netadrtype_t;

typedef struct {
	netadrtype_t    type;

	char    ip[4];
	char    ipx[12];

	unsigned short    port;
} netadr_t;

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


void Scr_AddBool(int send)
{
	DWORD _Scr_AddBool = 0x656A10;

	__asm
	{
		push send
		mov eax, send
		call _Scr_AddBool
		add esp, 4
	}
}

void SV_ConnectionlessPacket(msg_t* msg, netadr_t where)
{
	DWORD _SV_ConnectionlessPacket = 0x57E320;
	int a = ((int*)(&where))[0];
	int b = ((int*)(&where))[1];
	int c = ((int*)(&where))[2];
	int d = ((int*)(&where))[3];
	int e = ((int*)(&where))[4];
	int f = ((int*)(&where))[5];
	__asm
	{
		push f
		push e
		push d
		push c
		push b
		push a
		push msg
		call _SV_ConnectionlessPacket
		add esp, 28
	}
}

void SV_ConnectionlessPacketStub(msg_t* msg, netadr_t where)
{
	SV_ConnectionlessPacket(msg, where);
}

int SV_DropClient(client_t* cl, char* reason)
{
	int result = 0;

	DWORD _SV_DropClient = 0x576FD0;
	void* a = cl;
	__asm
	{
		push reason
		mov eax, a
		call _SV_DropClient
		add esp, 4
		mov result, eax
	}

	return result;
}

void SV_UpdateBotsStub()
{
	client_t* sv_clients = (client_t*)0x28C7B10;
	int sv_maxclients = *(int*)(*(int*)0x23C3AA8 + 16);
	DWORD SV_ClientThink = 0x578D80;
	unsigned int sv_servertime = *(int*)0x28C7B04;

	for (int i = 0; i < sv_maxclients; i++)
	{
		client_t* cl = &sv_clients[i];

		if (!cl->isNotBot && cl->state == 2)
		{
			SV_DropClient(cl, "EXE_DISCONNECTED"); // remove the dead bots
			continue;
		}

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

void isBot(unsigned int gNum)
{
	int sv_maxclients = *(int*)(*(int*)0x23C3AA8 + 16);

	if (gNum >= sv_maxclients)
		return;

	client_t* sv_clients = (client_t*)0x28C7B10;

	Scr_AddBool(!(&sv_clients[gNum])->isNotBot);
}

void botMoveForward(unsigned int gNum)
{
	if (gNum >= MAX_G_BOTAI_ENTRIES)
		return;

	g_botai[gNum].forward = Scr_GetInt(0);
}

void botMoveRight(unsigned int gNum)
{
	if (gNum >= MAX_G_BOTAI_ENTRIES)
		return;

	g_botai[gNum].right = Scr_GetInt(0);
}

void botWeapon(unsigned int gNum)
{
	if (gNum >= MAX_G_BOTAI_ENTRIES)
		return;

	char* weapon = Scr_GetString(0);

	g_botai[gNum].weapon = BG_GetWeaponIndexForName(weapon);
}

void botStop(unsigned int gNum)
{
	if (gNum >= MAX_G_BOTAI_ENTRIES)
		return;

	g_botai[gNum] = { 0 };
	g_botai[gNum].weapon = 1;
}

void botAction(unsigned int gNum)
{
	if (gNum >= MAX_G_BOTAI_ENTRIES)
		return;

	char* action = Scr_GetString(0);

	for (size_t i = 0; i < sizeof(BotActions) / sizeof(BotAction_t); ++i)
	{
		if (strcmp(&action[1], BotActions[i].action))
			continue;

		if (action[0] == '+')
			g_botai[gNum].buttons |= BotActions[i].key;
		else
			g_botai[gNum].buttons &= ~(BotActions[i].key);

		return;
	}
}

void* GetFunction(void* caller, const char** name, int* isDev)
{
	if (!strcmp(*name, "botaction"))
	{
		*isDev = 0;
		return botAction;
	}

	if (!strcmp(*name, "botstop"))
	{
		*isDev = 0;
		return botStop;
	}

	if (!strcmp(*name, "botweapon"))
	{
		*isDev = 0;
		return botWeapon;
	}

	if (!strcmp(*name, "botmoveforward"))
	{
		*isDev = 0;
		return botMoveForward;
	}

	if (!strcmp(*name, "botmoveright"))
	{
		*isDev = 0;
		return botMoveRight;
	}

	if (!strcmp(*name, "isbot"))
	{
		*isDev = 0;
		return isBot;
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

	// Patch incoming connectionless messages
	Detours::X86::DetourFunction((PBYTE)0x57EB55, (PBYTE)&SV_ConnectionlessPacketStub, Detours::X86Option::USE_CALL);

	// Allow Remote desktop
	Detours::X86::DetourFunction((PBYTE)0x5D06F2, (PBYTE)0x5D0721, Detours::X86Option::USE_JUMP);
}
