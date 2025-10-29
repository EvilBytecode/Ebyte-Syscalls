#include <iostream>
#include <Windows.h>
#include "EbyteSyscall.h"

using namespace ebytesyscalls;

definitions::PVEH_HOOK_ENTRY vehhook::g_hooklist = nullptr;

void WINAPI hooked_sleep(DWORD ms)
{
    printf("[+] Hooked Sleep called! Parameter: %lu ms\n", ms);
}

void WINAPI hooked_int3_function()
{
    printf("[+] INT3 exception handler redirected here!\n");
    printf("[+] Control flow was obfuscated via breakpoint exception\n");
}

__declspec(noinline) void test_function()
{
    printf("[+] This should never print directly - should hit INT3 instead\n");
}

int main()
{
#ifdef _WIN64
    printf("[+] Testing EbyteSyscalls [x64]...\n\n");
#else
    printf("[+] Testing EbyteSyscalls [x86]...\n\n");
#endif

    uintptr_t ntdllbase = internals::getntdllbase();
    printf("[+] NTDLL Base: 0x%p\n", (void*)ntdllbase);

    DWORD ntdllsize = internals::getmodulesize(ntdllbase);
    printf("[+] NTDLL Size: 0x%lx (%lu bytes)\n", ntdllsize, ntdllsize);

    uintptr_t kernel32base = internals::getmodulebase(L"kernel32.dll");
    printf("[+] KERNEL32 Base: 0x%p\n", (void*)kernel32base);

    uintptr_t ntqueryaddr = internals::getprocaddr(L"ntdll.dll", "NtQueryInformationProcess");
    printf("[+] NtQueryInformationProcess: 0x%p\n", (void*)ntqueryaddr);

    if (ntqueryaddr) {
        uint8_t* bytes = (uint8_t*)ntqueryaddr;
        printf("[+] First 8 bytes: %02X %02X %02X %02X %02X %02X %02X %02X\n",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]);

        uint32_t ssn = internals::EbyteExtractSSN(ntqueryaddr);
        printf("[+] Syscall Number: 0x%lx\n", ssn);
    }

    DWORD rva = internals::vatorva(ntdllbase, ntqueryaddr);
    printf("[+] NtQueryInformationProcess RVA: 0x%lx\n", rva);

    uintptr_t vacheck = internals::rvatova(ntdllbase, rva);
    printf("[+] RVA to VA: 0x%p\n", (void*)vacheck);

    bool inmodule = internals::isaddrinmodule(ntqueryaddr, ntdllbase);
    printf("[+] Address in module: %s\n\n", inmodule ? "true" : "false");

#ifdef _WIN64
    uintptr_t pattern = internals::findpattern(ntdllbase, "4C 8B D1 B8");
    printf("[+] Pattern [4C 8B D1 B8] found at: 0x%p\n", (void*)pattern);

    uint8_t bytepat[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
    uintptr_t bmsearch = internals::boyermooresearch(ntdllbase, bytepat, 4);
    printf("[+] Boyer-Moore found at: 0x%p\n\n", (void*)bmsearch);
#else
    uintptr_t pattern = internals::findpattern(ntdllbase, "B8 ?? ?? ?? ?? BA");
    printf("[+] Pattern [B8 ?? ?? ?? ?? BA] found at: 0x%p\n", (void*)pattern);

    uint8_t bytepat[] = { 0xB8 };
    uintptr_t bmsearch = internals::boyermooresearch(ntdllbase, bytepat, 1);
    printf("[+] Boyer-Moore [B8] found at: 0x%p\n\n", (void*)bmsearch);
#endif

    printf("[+] Testing Trampoline Hook...\n");
    uintptr_t ntdelayaddr = internals::getprocaddr(L"ntdll.dll", "NtDelayExecution");
    if (ntdelayaddr) {
        uint8_t original[6];
        printf("[+] NtDelayExecution: 0x%p\n", (void*)ntdelayaddr);
        printf("[+] Original bytes: ");
        for (int i = 0; i < 6; i++)
            printf("%02X ", ((uint8_t*)ntdelayaddr)[i]);
        printf("\n");

        if (tramphook::hookfunction(ntdelayaddr, ntqueryaddr, original)) {
            printf("[+] Hook installed!\n");
            printf("[+] Hooked bytes: ");
            for (int i = 0; i < 6; i++)
                printf("%02X ", ((uint8_t*)ntdelayaddr)[i]);
            printf("\n");

            if (tramphook::unhookfunction(ntdelayaddr, original)) {
                printf("[+] Hook removed!\n");
                printf("[+] Restored bytes: ");
                for (int i = 0; i < 6; i++)
                    printf("%02X ", ((uint8_t*)ntdelayaddr)[i]);
                printf("\n\n");
            }
        }
        else {
            printf("[-] Hook failed!\n\n");
        }
    }
    else {
        printf("[-] NtDelayExecution not found!\n\n");
    }
    uintptr_t jmp_rbx_gadget = ebytesyscalls::internals::findropgadget(ntdllbase, "jmp [rbx]");
    uintptr_t custom_gadget = ebytesyscalls::internals::findgadget(ntdllbase, "48 89 5C 24 08");

    if (jmp_rbx_gadget) {
        printf("[+] ROP gadget 'jmp [rbx]' found at: 0x%p\n", (void*)jmp_rbx_gadget);
    }
    else {
        printf("[-] ROP gadget 'jmp [rbx]' NOT found\n");
    }

    if (custom_gadget) {
        printf("[+] Custom gadget '48 89 5C 24 08' found at: 0x%p\n", (void*)custom_gadget);
    }
    else {
        printf("[-] Custom gadget '48 89 5C 24 08' NOT found\n");
    }



    structs::PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnlen = 0;

    NTSTATUS status = syscaller::EbyteSyscall<NTSTATUS>("NtQueryInformationProcess", CURRENT_PROCESS, 0, &pbi, sizeof(pbi), &returnlen);

    if (NT_SUCCESS(status)) {
        printf("[+] Syscall Success!\n");
        printf("[+] Current PID: %lu\n", GetCurrentProcessId());
        printf("[+] Process ID from PBI: %lu\n", (ULONG)pbi.processid);
        printf("[+] PEB Address: 0x%p\n", pbi.pebaddress);
    }
    else {
        printf("[-] Syscall Failed: 0x%lx\n", status);
    }

    printf("\n[+] Testing VEH Hook...\n");
    
    if (!vehhook::initialize())
    {
        printf("[-] Failed to initialize VEH handler\n");
    }
    else
    {
        printf("[+] VEH handler initialized\n");
    }

    typedef VOID(WINAPI* psleep)(DWORD);
    psleep pSleep = (psleep)internals::getprocaddr(L"kernel32.dll", "Sleep");
    
    if (pSleep)
    {
        printf("[+] Sleep function address: 0x%p\n", (void*)pSleep);
        
        static definitions::VEH_HOOK_ENTRY sleephook = { 0 };
        
        sleephook.OriginalFunction = (LPVOID)pSleep;
        sleephook.RedirectFunction = (LPVOID)hooked_sleep;
        sleephook.Next = nullptr;
        
        if (vehhook::addhook(&sleephook))
        {
            printf("[+] VEH hook added to Sleep\n");
            
            printf("[+] Calling Sleep(100) #1...\n");
            Sleep(100);
            
            printf("[+] Calling Sleep(100) #2...\n");
            Sleep(100);
            
            printf("[+] Calling Sleep(100) #3...\n");
            Sleep(100);
            
            vehhook::removehook(&sleephook);
            printf("[+] VEH hook removed from Sleep\n");
            
            printf("[+] Calling Sleep(100) after removal (should work normally)...\n");
            Sleep(100);
        }
        else
        {
            printf("[-] Failed to add VEH hook\n");
        }
    }

    printf("\n[+] Testing Intentional INT3 Exception Obfuscation...\n");
    
    printf("[+] test_function address: 0x%p\n", (void*)test_function);
    printf("[+] First byte before INT3: 0x%02X\n", ((uint8_t*)test_function)[0]);
    
    static definitions::VEH_HOOK_ENTRY int3hook = { 0 };
    if (vehhook::triggerint3hook((LPVOID)test_function, (LPVOID)hooked_int3_function, &int3hook))
    {
        printf("[+] INT3 hook installed at test_function\n");
        printf("[+] First byte after INT3: 0x%02X (should be 0xCC)\n", ((uint8_t*)test_function)[0]);
        printf("[+] Calling test_function() - should trigger INT3 exception...\n");
        
        // This call will hit INT3, trigger exception, and redirect -> hooked_int3_function
        test_function();
        
        printf("[+] INT3 exception obfuscation test completed\n");
    }
    else
    {
        printf("[-] Failed to install INT3 hook\n");
    }

    printf("\n[+] All tests completed.\n");
    getchar();
    return 0;
}