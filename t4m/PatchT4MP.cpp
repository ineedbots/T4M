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

int FS_FOpenFileWrite(char *path)
{
	DWORD _FS_FOpenFileWrite = 0x5B1B60;
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

int FS_FOpenFileAppend(char *path)
{
	DWORD _FS_FOpenFileAppend = 0x5B1C50;
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

int FS_Write(char *buff, size_t buffSize, int fd)
{
	int result;
	DWORD _FS_Write = 0x5B2860;

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

void FS_FCloseFile(int fd)
{
	DWORD _FS_FCloseFile = 0x5B19D0;

	__asm
	{
		mov eax, fd
		call _FS_FCloseFile
	}
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

void Scr_AddString(char* stri)
{
	DWORD _Scr_AddString = 0x656BD0;

	__asm
	{
		push stri
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
	unsigned int sv_maxclients = *(int*)(*(int*)0x23C3AA8 + 16);

	if (gNum >= sv_maxclients)
		return;

	client_t* sv_clients = (client_t*)0x28C7B10;

	Scr_AddBool(!(&sv_clients[gNum])->isNotBot);
}

void RemoveTestclient(unsigned int gNum)
{
	unsigned int sv_maxclients = *(int*)(*(int*)0x23C3AA8 + 16);

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

static size_t _CURLWrite(void* buffer, size_t size, size_t nmemb, void* param)
{
	std::string& text = *static_cast<std::string*>(param);
	size_t totalsize = size * nmemb;
	text.append(static_cast<char*>(buffer), totalsize);
	return totalsize;
}

bool HTTPGet(const char* url, std::string &result)
{
	bool ret = false;
	CURL* curl;
	CURLcode res;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();

	if (curl)
	{
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _CURLWrite);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // follow redirects
		curl_easy_setopt(curl, CURLOPT_TIMEOUT , 5L); // timeout in 5 seconds
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT , 5L);

		res = curl_easy_perform(curl);
		if (res == CURLE_OK)
		{
			long response_code;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

			ret = (response_code >= 200 && response_code < 300);
		}

		curl_easy_cleanup(curl);
	}

	curl_global_cleanup();
	return ret;
}

void fileRead()
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

void fileWrite()
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

void scriptHTTPGet()
{
	char* url = Scr_GetString(0);

	if (!url)
		return;

	std::string res;

	if (!HTTPGet(url, res))
		return;

	Scr_AddString((char *)res.c_str());
}

void debugBox()
{
	char* str = Scr_GetString(0);

	if (!str)
		return;

	MessageBoxA(nullptr, str, "DEBUG", 0);
}

void Com_PrintMessageMP(int channel, char* pntstr, int err)
{
	DWORD _Com_PrintMessage = 0x5622B0;

	__asm
	{
		push err
		push pntstr
		push channel
		call _Com_PrintMessage
		add esp, 0Ch
	}
}

void printConsole()
{
	char* str = Scr_GetString(0);

	if (!str)
		return;

	Com_PrintMessageMP(0, str, 0);
}

void* __cdecl GetMethods(const char** name)
{
	if (!name || !*name)
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
	if (!name)
		return nullptr;

	if (!strcmp(name, "fileread"))
		return fileRead;

	if (!strcmp(name, "filewrite"))
		return fileWrite;

	if (!strcmp(name, "httpget"))
		return scriptHTTPGet;

	if (!strcmp(name, "debugbox"))
		return debugBox;

	if (!strcmp(name, "printconsole"))
		return printConsole;

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

	if (num < 0)
		num = 0;

	char name[128];

	if (botNames.empty())
		sprintf(name, "bot%d", num);
	else
		sprintf(name, "%s", botNames.at(num % botNames.size()).c_str());

	return sprintf(Buffer, connectStr, name, protcol, port);
}

static char* botConnectStr = "connect \"\\cg_predictItems\\1\\cl_punkbuster\\0\\cl_anonymous\\0\\color\\4\\head\\default\\model\\multi\\snaps\\20\\"
    "rate\\5000\\name\\%s\\protocol\\%d\\qport\\%d\"";

void PatchT4MP_SteamDRM()
{
	if (*(DWORD*)0x401000 != 0x7FE5ED21)
		return;

	// Replace encrypted .text segment
	DWORD size = 0x3E5000;
	std::string data = GetBinaryResource(IDB_TEXT);
	uncompress((unsigned char*)0x401000, &size, (unsigned char*)data.data(), data.size());

	// Apply new entry point
	HMODULE hModule = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER header = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD)hModule + header->e_lfanew);
	ntHeader->OptionalHeader.AddressOfEntryPoint = 0x3A8256;
}

const char* SetConsoleVersion();
const char* SetShortVersion();
void loadGameOverlay();

void PatchT4MP()
{
	PatchT4MP_SteamDRM();

	if (!GetModuleHandle("gameoverlayrenderer.dll"))
		loadGameOverlay();

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


	// allow changing g_antilag
	*(BYTE*)0x4FDA31 = 0;


	nop(0x5CF675, 5); // remove optimal settings popup
	*(BYTE*)0x5D03E6 = (BYTE)0xEB; // skip safe mode check

	PatchMemory(0x856380, (PBYTE)CONSOLEVERSION_STR, 14);	// change the console input version

	Detours::X86::DetourFunction((PBYTE)0x592B11, (PBYTE)&SetShortVersion, Detours::X86Option::USE_CALL); // change version number bottom right of main
	Detours::X86::DetourFunction((PBYTE)0x48C532, (PBYTE)&SetConsoleVersion, Detours::X86Option::USE_CALL); // change the version info of console window
	Detours::X86::DetourFunction((PBYTE)0x5658ED, (PBYTE)&SetConsoleVersion, Detours::X86Option::USE_CALL); // change the version info of version 
}
