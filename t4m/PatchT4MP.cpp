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

typedef struct client_s {
	int state; // 0 - 4
	char pad[4]; // 4 - 8
	int deltaMessage; // 8 - 12
	char pad2[4]; // 12 - 16
	int outgoingSequence; // 16 - 20
	char pad3[12]; // 20 - 32
	int isNotBot; // 32 - 36
	char pad4[610056]; // 36 - 610092
	int ping; // 610092 - 610094
	char pad5[151942]; // 610094 - 762040
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

	int ping;
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

int Scr_GetInt(int slot)
{
	int result = 0;

	DWORD _Scr_GetInt = 0x656130;
	__asm
	{
		mov ecx, slot
		mov eax, 0
		call _Scr_GetInt
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
		mov eax, 0
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
		push 0x4FB490
		push weaponName
		call _BG_GetWeaponIndexForName
		add esp, 8
		mov weapIndex, eax
	}

	return weapIndex;
}

void FS_FreeFile(char* buffer)
{
	*(DWORD*)0xF366844 -= 1;
	DWORD Hunk_FreeTempMemory = 0x5BB0D0;
	__asm
	{
		mov esi, buffer
		call Hunk_FreeTempMemory
	}
}

int FS_ReadFile(char* path, char** buffer)
{
	char* buff = nullptr;

	DWORD _FS_ReadFile = 0x5B2940;
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

void Scr_AddBool(int send)
{
	DWORD _Scr_AddBool = 0x656A10;

	__asm
	{
		push send
		mov eax, 0
		call _Scr_AddBool
		add esp, 4
	}
}

void Scr_AddString(char* str)
{
	DWORD _Scr_AddString = 0x656BD0;

	__asm
	{
		push str
		mov eax, 0
		call _Scr_AddString
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

void SV_ClientThink(client_t* cl, usercmd_t* usercmd)
{
	DWORD _SV_ClientThink = 0x578D80;

	void* a = (void*)cl;
	void* b = (void*)usercmd;
	__asm
	{
		mov ecx, b
		mov eax, a
		call _SV_ClientThink
	}
}

void SV_UpdateBotsStub()
{
	client_t* sv_clients = (client_t*)0x28C7B10;
	int sv_maxclients = *(int*)(*(int*)0x23C3AA8 + 16);
	unsigned int sv_servertime = *(int*)0x28C7B04;

	for (int i = 0; i < sv_maxclients; i++)
	{
		client_t* cl = &sv_clients[i];

		if (!cl->isNotBot && cl->state == 2)
		{
			SV_DropClient(cl, "EXE_DISCONNECTED"); // remove the dead bots
			cl->state = 0;
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
		cl->ping = g_botai[i].ping;

		SV_ClientThink(cl, &usercmd);
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

void RemoveTestclient(unsigned int gNum)
{
	int sv_maxclients = *(int*)(*(int*)0x23C3AA8 + 16);

	if (gNum >= sv_maxclients)
		return;

	client_t* sv_clients = (client_t*)0x28C7B10;

	SV_DropClient(&sv_clients[gNum], "EXE_DISCONNECTED");
	(&sv_clients[gNum])->state = 0;
}

void botMovement(unsigned int gNum)
{
	if (gNum >= MAX_G_BOTAI_ENTRIES)
		return;

	g_botai[gNum].forward = Scr_GetInt(0);
	g_botai[gNum].right = Scr_GetInt(1);
}

void setPing(unsigned int gNum)
{
	if (gNum >= MAX_G_BOTAI_ENTRIES)
		return;

	g_botai[gNum].ping = Scr_GetInt(0);
}

void botWeapon(unsigned int gNum)
{
	if (gNum >= MAX_G_BOTAI_ENTRIES)
		return;

	char* weapon = Scr_GetString(0);

	if (!weapon)
		return;

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

	if (!action)
		return;

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

void fileRead(unsigned int gNum)
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

void* __cdecl GetMethods(const char** name)
{
	if (!name)
		return nullptr;

	if (!strcmp(*name, "botaction"))
		return botAction;

	if (!strcmp(*name, "botstop"))
		return botStop;

	if (!strcmp(*name, "botweapon"))
		return botWeapon;

	if (!strcmp(*name, "botmovement"))
		return botMovement;

	if (!strcmp(*name, "isbot"))
		return isBot;

	if (!strcmp(*name, "removetestclient"))
		return RemoveTestclient;

	if (!strcmp(*name, "setping"))
		return setPing;

	return nullptr;
}

static DWORD sub_5232D0 = 0x5232D0;
__declspec(naked) void GetMethodsStub()
{
	__asm
	{
		// original code
		push    edi
		push    esi
		call    sub_5232D0
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
		push 5233AEh
		retn
	}
}

void* __cdecl GetFunctions(const char* name)
{
	if (!strcmp(name, "fileread"))
		return fileRead;

	return nullptr;
}

__declspec(naked) void GetFunctionStub()
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
		push 523260h
		retn
	}
}

static std::vector<std::string> botNames;

// https://stackoverflow.com/a/44495206
std::vector<std::string> split(char *phrase, std::string delimiter)
{
    std::vector<std::string> list;
    std::string s = std::string(phrase);
    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delimiter)) != std::string::npos)
	{
        token = s.substr(0, pos);
        list.push_back(token);
        s.erase(0, pos + delimiter.length());
    }
    list.push_back(s);
    return list;
}

// iw4x-client
void Replace(std::string &string, const std::string& find, const std::string& replace)
{
	size_t nPos = 0;

	while ((nPos = string.find(find, nPos)) != std::string::npos)
	{
		string = string.replace(nPos, find.length(), replace);
		nPos += replace.length();
	}
}

int BuildBotConnectStr(char* Buffer, const char *connectStr, int num, int protcol, int port)
{
	if (botNames.empty())
	{
		char* names;
		int size = FS_ReadFile("bots.txt", &names);

		if (size > 0)
		{
			std::vector<std::string> namesv = split(names, "\n");

			for (auto name : namesv)
			{
				Replace(name, "\r", "");

				if (!name.empty())
				{
					botNames.push_back(name);
				}
			}

			FS_FreeFile(names);
		}
	}

	char name[128];

	if (botNames.empty())
		sprintf(name, "bot%d", num - 1);
	else
		sprintf(name, "%s", botNames.at((num - 1) % botNames.size()).c_str());

	return sprintf(Buffer, connectStr, name, protcol, port);
}

static char* botConnectStr = "connect \"\\cg_predictItems\\1\\cl_punkbuster\\0\\cl_anonymous\\0\\color\\4\\head\\default\\model\\multi\\snaps\\20\\"
    "rate\\5000\\name\\%s\\protocol\\%d\\qport\\%d\"";

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
	Detours::X86::DetourFunction((PBYTE)0x5233A4, (PBYTE)&GetMethodsStub, Detours::X86Option::USE_JUMP);
	Detours::X86::DetourFunction((PBYTE)0x523259, (PBYTE)&GetFunctionStub, Detours::X86Option::USE_JUMP);

	// Patch incoming connectionless messages
	Detours::X86::DetourFunction((PBYTE)0x57EB55, (PBYTE)&SV_ConnectionlessPacketStub, Detours::X86Option::USE_CALL);

	// Allow Remote desktop
	Detours::X86::DetourFunction((PBYTE)0x5D06F2, (PBYTE)0x5D0721, Detours::X86Option::USE_JUMP);

	// Use our connect string
	*(char **)0x579458 = botConnectStr;

	// intersept connect string sprintf
	Detours::X86::DetourFunction((PBYTE)0x57945D, (PBYTE)&BuildBotConnectStr, Detours::X86Option::USE_CALL);
}
