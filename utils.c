#include <windows.h>
#include <winternl.h>
#include <psapi.h>

typedef struct _LDR_MODULE
{
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _RTL_USER_PROCESS_PARAMETERS *PRTL_USER_PROCESS_PARAMETERS;
typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifdef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#endif

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];
typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];

#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    ULONG_PTR HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME *Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

// 将C++的wstring处理函数转换为C语言的相应函数
size_t wlindexof(const wchar_t *str, size_t len, wchar_t c)
{
    for (size_t i = len - 1; i != (size_t)(-1); --i)
    {
        if (str[i] == c)
            return i;
    }
    return -1;
}

// 将C++的类型转换为C语言的类型
HMODULE GetModuleHandlePeb(LPCWSTR name)
{
#ifdef _AMD64_
    PPEB peb = (PPEB)(*(PDWORD64)(0x60));
#else
    PPEB peb = (PPEB)(*(PDWORD)(0x30));
#endif

    PPEB_LDR_DATA LdrData = (PPEB_LDR_DATA)(peb->Ldr);
    PLDR_MODULE ListEntry = (PLDR_MODULE)(LdrData->InMemoryOrderModuleList.Flink);
    while (ListEntry && ListEntry->BaseAddress)
    {
        size_t lastDot = wlindexof(ListEntry->BaseDllName.Buffer, ListEntry->BaseDllName.Length, L'.');
        size_t cmpResult = lastDot != -1
                               ? wcsncmp(ListEntry->BaseDllName.Buffer, name, lastDot)
                               : wcscmp(ListEntry->BaseDllName.Buffer, name);

        if (!cmpResult)
            return (HMODULE)(ListEntry->BaseAddress);

        ListEntry = (PLDR_MODULE)(ListEntry->InLoadOrderModuleList.Flink);
    }

    return NULL;
}

// 将C++的函数指针转换为C语言的函数指针
PVOID GetProcAddressPeb(HMODULE hModule, LPCSTR name)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(hModule);
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)(hModule) + dosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

    IMAGE_DATA_DIRECTORY exportDir = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exportDir.Size)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)(hModule) + exportDir.VirtualAddress);
    PDWORD functions = (PDWORD)((DWORD_PTR)(hModule) + exports->AddressOfFunctions);
    PDWORD names = (PDWORD)((DWORD_PTR)(hModule) + exports->AddressOfNames);

    for (size_t i = 0; i < exports->NumberOfFunctions; i++)
    {
        DWORD rva = *(functions + i);
        LPCSTR szName = (LPCSTR)((DWORD_PTR)(hModule) + *(names + i));
        if (!strcmp(name, szName))
            return (PBYTE)((DWORD_PTR)(hModule) + rva);
    }

    return NULL;
}

BYTE HookCode[12] = {0x48, 0xB8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xFF, 0xE0};

void UnHookFuncAddress64(UINT64 FuncAddress, BYTE OldCode[12])
{
    DWORD OldProtect = 0;
    if (VirtualProtect((LPVOID)FuncAddress, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
    {
        memcpy((LPVOID)FuncAddress, OldCode, 12);
    }
    VirtualProtect((LPVOID)FuncAddress, 12, OldProtect, &OldProtect);
}

void HookFunction64(char *lpModule, LPCSTR lpFuncName, LPVOID lpFunction, BYTE OldCode[12])
{
    DWORD_PTR FuncAddress = (UINT64)GetProcAddressPeb(GetModuleHandle(lpModule), lpFuncName);
    DWORD OldProtect = 0;

    if (VirtualProtect((LPVOID)FuncAddress, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
    {
        memcpy(OldCode, (LPVOID)FuncAddress, 12);     // 拷贝原始机器码指令
        *(PINT64)(HookCode + 2) = (UINT64)lpFunction; // 填充90为指定跳转地址
    }
    memcpy((LPVOID)FuncAddress, &HookCode, sizeof(HookCode)); // 拷贝Hook机器指令
    VirtualProtect((LPVOID)FuncAddress, 12, OldProtect, &OldProtect);
}
void UnHookFunction64(char *lpModule, LPCSTR lpFuncName, BYTE OldCode[12])
{
    DWORD OldProtect = 0;
    UINT64 FuncAddress = (UINT64)GetProcAddressPeb(GetModuleHandleA(lpModule), lpFuncName);
    if (VirtualProtect((LPVOID)FuncAddress, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
    {
        memcpy((LPVOID)FuncAddress, OldCode, 12);
    }
    VirtualProtect((LPVOID)FuncAddress, 12, OldProtect, &OldProtect);
}

void HookFuncAddress64(DWORD_PTR FuncAddress, LPVOID lpFunction, BYTE OldCode[12])
{
    DWORD OldProtect = 0;

    if (VirtualProtect((LPVOID)FuncAddress, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
    {
        memcpy(OldCode, (LPVOID)FuncAddress, 12);     // 拷贝原始机器码指令
        *(PINT64)(HookCode + 2) = (UINT64)lpFunction; // 填充90为指定跳转地址
    }
    memcpy((LPVOID)FuncAddress, &HookCode, sizeof(HookCode)); // 拷贝Hook机器指令
    VirtualProtect((LPVOID)FuncAddress, 12, OldProtect, &OldProtect);
}