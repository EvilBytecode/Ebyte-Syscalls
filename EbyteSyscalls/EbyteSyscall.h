#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define STRICT
#define WIN32_NO_STATUS
#ifndef __EBYTESYSCALLS_FUNC
#define __EBYTESYSCALLS_FUNC __forceinline
#endif

#include <Windows.h>
#include <cstdint>

#define NTSTATUS long
#define NT_SUCCESS(status) ((NTSTATUS)(status) >= 0)
#define CURRENT_PROCESS ((HANDLE)-1)
#define CURRENT_THREAD ((HANDLE)-2)

namespace ebytesyscalls
{
    namespace definitions
    {
        /// <summary>
        /// Copies memory from source to destination without using standard library functions.
        /// </summary>
        /// <param name="dest">Destination buffer to copy to.</param>
        /// <param name="src">Source buffer to copy from.</param>
        /// <param name="len">Number of bytes to copy.</param>
        /// <returns>Returns pointer to destination buffer.</returns>
        __EBYTESYSCALLS_FUNC PVOID vxmovememory(PVOID dest, const PVOID src, SIZE_T len) {
            char* d = (char*)dest;
            const char* s = (const char*)src;
            while (len--)
                *d++ = *s++;
            return dest;
        }

        typedef struct _UNICODE_STRING {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR  Buffer;
        } UNICODE_STRING, * PUNICODE_STRING;

        typedef struct _PEB_LDR_DATA {
            ULONG Length;
            BOOLEAN Initialized;
            HANDLE SsHandle;
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
            PVOID EntryInProgress;
            BOOLEAN ShutdownInProgress;
            HANDLE ShutdownThreadId;
        } PEB_LDR_DATA, * PPEB_LDR_DATA;

        typedef struct _PEB {
            BOOLEAN InheritedAddressSpace;
            BOOLEAN ReadImageFileExecOptions;
            BOOLEAN BeingDebugged;
            union {
                BOOLEAN BitField;
                struct {
                    BOOLEAN ImageUsesLargePages : 1;
                    BOOLEAN IsProtectedProcess : 1;
                    BOOLEAN IsImageDynamicallyRelocated : 1;
                    BOOLEAN SkipPatchingUser32Forwarders : 1;
                    BOOLEAN IsPackagedProcess : 1;
                    BOOLEAN IsAppContainer : 1;
                    BOOLEAN IsProtectedProcessLight : 1;
                    BOOLEAN IsLongPathAwareProcess : 1;
                };
            };
            HANDLE Mutant;
            PVOID ImageBaseAddress;
            PPEB_LDR_DATA Ldr;
        } PEB, * PPEB;

        typedef struct _LDR_DATA_TABLE_ENTRY {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            LIST_ENTRY InInitializationOrderLinks;
            PVOID DllBase;
            PVOID EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
        } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

        typedef struct _VEH_HOOK_ENTRY {
            LPVOID OriginalFunction;
            LPVOID RedirectFunction;
            struct _VEH_HOOK_ENTRY* Next;
        } VEH_HOOK_ENTRY, * PVEH_HOOK_ENTRY;
    }

    namespace structs
    {
        typedef struct _PROCESS_BASIC_INFORMATION {
            PVOID reserved1;
            PVOID pebaddress;
            PVOID reserved2[2];
            ULONG_PTR processid;
            PVOID reserved3;
        } PROCESS_BASIC_INFORMATION;

        typedef struct _SYSTEM_PROCESS_INFORMATION {
            ULONG nextentryoffset;
            ULONG threadcount;
            BYTE reserved1[48];
            definitions::UNICODE_STRING imagename;
            LONG basepriority;
            HANDLE processid;
            HANDLE parentprocessid;
        } SYSTEM_PROCESS_INFORMATION;
    }

    namespace internals
    {
        /// <summary>
        /// Gets the Process Environment Block (PEB) address by reading from thread-local storage.
        /// </summary>
        /// <returns>Returns pointer to PEB structure, or nullptr on failure.</returns>
        __EBYTESYSCALLS_FUNC definitions::PEB* getpeb() noexcept
        {
#ifdef _WIN64
            return reinterpret_cast<definitions::PEB*>(__readgsqword(0x60));
#else
            return reinterpret_cast<definitions::PEB*>(__readfsdword(0x30));
#endif
        }

        /// <summary>
        /// Extracts the System Call Number (SSN) from a syscall function's bytecode.
        /// </summary>
        /// <param name="funcaddr">Address of the syscall function.</param>
        /// <returns>Returns the system call number, or 0 if not found.</returns>
        __EBYTESYSCALLS_FUNC uint32_t EbyteExtractSSN(uintptr_t funcaddr)
        {
            uint8_t* bytes = reinterpret_cast<uint8_t*>(funcaddr);

            for (int i = 0; i < 32; i++)
            {
                if (bytes[i] == 0xB8 && i + 4 < 32)
                {
                    uint32_t result = 0;
                    definitions::vxmovememory(&result, &bytes[i + 1], sizeof(uint32_t));
                    return result;
                }
            }
            return 0;
        }

        /// <summary>
        /// Converts a Relative Virtual Address (RVA) to a Virtual Address (VA) by adding the module base address.
        /// </summary>
        /// <param name="modulebase">Base address of the module.</param>
        /// <param name="rva">Relative Virtual Address to convert.</param>
        /// <returns>Returns the calculated Virtual Address.</returns>
        __EBYTESYSCALLS_FUNC uintptr_t rvatova(uintptr_t modulebase, DWORD rva)
        {
            return modulebase + rva;
        }

        /// <summary>
        /// Converts a Virtual Address (VA) to a Relative Virtual Address (RVA) by subtracting the module base address.
        /// </summary>
        /// <param name="modulebase">Base address of the module.</param>
        /// <param name="va">Virtual Address to convert.</param>
        /// <returns>Returns the calculated Relative Virtual Address.</returns>
        __EBYTESYSCALLS_FUNC DWORD vatorva(uintptr_t modulebase, uintptr_t va)
        {
            return (DWORD)(va - modulebase);
        }

        /// <summary>
        /// Gets the base address of a loaded module by traversing the PEB module list.
        /// </summary>
        /// <param name="modulename">Name of the module to find (e.g., L"ntdll.dll").</param>
        /// <returns>Returns the base address of the module, or 0 if not found.</returns>
        __EBYTESYSCALLS_FUNC uintptr_t getmodulebase(const wchar_t* modulename)
        {
            definitions::PEB* peb = getpeb();
            definitions::PPEB_LDR_DATA pebldr = peb->Ldr;
            LIST_ENTRY* head = &pebldr->InLoadOrderModuleList;
            LIST_ENTRY* current = head->Flink;

            while (current && current != head)
            {
                auto entry = CONTAINING_RECORD(current, definitions::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                if (entry->BaseDllName.Buffer && _wcsicmp(entry->BaseDllName.Buffer, modulename) == 0)
                {
                    return reinterpret_cast<uintptr_t>(entry->DllBase);
                }

                current = current->Flink;
            }

            return 0;
        }

        /// <summary>
        /// Gets the size of a loaded module by parsing the PE header.
        /// </summary>
        /// <param name="modulebase">Base address of the module.</param>
        /// <returns>Returns the size of the module in bytes, or 0 on failure.</returns>
        __EBYTESYSCALLS_FUNC DWORD getmodulesize(uintptr_t modulebase)
        {
            if (!modulebase) return 0;

            IMAGE_DOS_HEADER* dosheader = reinterpret_cast<IMAGE_DOS_HEADER*>(modulebase);
            if (dosheader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

#ifdef _WIN64
            IMAGE_NT_HEADERS64* ntheader = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<uint8_t*>(modulebase) + dosheader->e_lfanew);
            if (ntheader->Signature != IMAGE_NT_SIGNATURE) return 0;
            return ntheader->OptionalHeader.SizeOfImage;
#else
            IMAGE_NT_HEADERS32* ntheader = reinterpret_cast<IMAGE_NT_HEADERS32*>(reinterpret_cast<uint8_t*>(modulebase) + dosheader->e_lfanew);
            if (ntheader->Signature != IMAGE_NT_SIGNATURE) return 0;
            return ntheader->OptionalHeader.SizeOfImage;
#endif
        }

        /// <summary>
        /// Gets the address of the export directory table from a PE module.
        /// </summary>
        /// <param name="modulebase">Base address of the module.</param>
        /// <returns>Returns the address of the export directory, or 0 on failure.</returns>
        __EBYTESYSCALLS_FUNC uintptr_t getexportdir(uintptr_t modulebase)
        {
            if (!modulebase) return 0;

            IMAGE_DOS_HEADER* dosheader = reinterpret_cast<IMAGE_DOS_HEADER*>(modulebase);
            if (dosheader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

#ifdef _WIN64
            IMAGE_NT_HEADERS64* ntheader = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<uint8_t*>(modulebase) + dosheader->e_lfanew);
#else
            IMAGE_NT_HEADERS32* ntheader = reinterpret_cast<IMAGE_NT_HEADERS32*>(reinterpret_cast<uint8_t*>(modulebase) + dosheader->e_lfanew);
#endif
            if (ntheader->Signature != IMAGE_NT_SIGNATURE) return 0;

            auto exportrva = ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (!exportrva) return 0;

            return rvatova(modulebase, exportrva);
        }

        /// <summary>
        /// Gets the base address of a module safely without using Win32 API functions.
        /// </summary>
        /// <param name="modulename">Name of the module to find.</param>
        /// <returns>Returns the base address of the module, or 0 if not found.</returns>
        __EBYTESYSCALLS_FUNC uintptr_t getmodulehandlewsafe(const wchar_t* modulename)
        {
            return getmodulebase(modulename);
        }

        /// <summary>
        /// Gets the address of an exported function by parsing the PE export directory.
        /// </summary>
        /// <param name="modulebase">Base address of the module.</param>
        /// <param name="functionname">Name of the function to find.</param>
        /// <returns>Returns the address of the function, or 0 if not found.</returns>
        __EBYTESYSCALLS_FUNC uintptr_t getprocaddrbybase(uintptr_t modulebase, const char* functionname)
        {
            if (!modulebase) return 0;

            IMAGE_DOS_HEADER* dosheader = reinterpret_cast<IMAGE_DOS_HEADER*>(modulebase);
            if (dosheader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

#ifdef _WIN64
            IMAGE_NT_HEADERS64* ntheader = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<uint8_t*>(modulebase) + dosheader->e_lfanew);
#else
            IMAGE_NT_HEADERS32* ntheader = reinterpret_cast<IMAGE_NT_HEADERS32*>(reinterpret_cast<uint8_t*>(modulebase) + dosheader->e_lfanew);
#endif
            if (ntheader->Signature != IMAGE_NT_SIGNATURE) return 0;

            auto imgexportva = ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (!imgexportva) return 0;

            IMAGE_EXPORT_DIRECTORY* imgexportdir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(reinterpret_cast<uint8_t*>(modulebase) + imgexportva);

            auto addroffunctions = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(modulebase) + imgexportdir->AddressOfFunctions);
            auto addrofnames = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(modulebase) + imgexportdir->AddressOfNames);
            auto addrofnameords = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(modulebase) + imgexportdir->AddressOfNameOrdinals);

            for (auto i = 0u; i < imgexportdir->NumberOfNames; i++)
            {
                auto stringmatches = false;
                char* currentname = reinterpret_cast<char*>(modulebase) + addrofnames[i];

                for (auto j = 0;; j++)
                {
                    if (currentname[j] == '\0' || functionname[j] == '\0')
                    {
                        break;
                    }
                    else
                    {
                        if (currentname[j] == functionname[j])
                        {
                            stringmatches = true;
                            continue;
                        }
                        else
                        {
                            stringmatches = false;
                            break;
                        }
                    }
                }

                if (stringmatches)
                {
                    return reinterpret_cast<uintptr_t>(reinterpret_cast<uint8_t*>(modulebase) + addroffunctions[addrofnameords[i]]);
                }
            }

            return 0;
        }

        /// <summary>
        /// Gets the base address of ntdll.dll by traversing the PEB module list.
        /// </summary>
        /// <returns>Returns the base address of ntdll.dll, or 0 if not found.</returns>
        __EBYTESYSCALLS_FUNC uintptr_t getntdllbase()
        {
            static uintptr_t ntdllbase = 0;
            if (ntdllbase)
                return ntdllbase;

#ifdef _M_X64
            definitions::PPEB peb = (definitions::PPEB)__readgsqword(0x60);
#else
            definitions::PPEB peb = (definitions::PPEB)__readfsdword(0x30);
#endif
            definitions::PPEB_LDR_DATA ldr = peb->Ldr;
            LIST_ENTRY* list = ldr->InMemoryOrderModuleList.Flink;

            for (LIST_ENTRY* entry = list; entry != &ldr->InMemoryOrderModuleList; entry = entry->Flink)
            {
                auto dtentry = CONTAINING_RECORD(entry, definitions::LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                if (wcsstr(dtentry->BaseDllName.Buffer, L"ntdll.dll"))
                {
                    ntdllbase = (uintptr_t)dtentry->DllBase;
                    return ntdllbase;
                }
            }

            return 0;
        }

        /// <summary>
        /// Gets the address of a syscall stub function used for dynamic syscall invocation.
        /// </summary>
        /// <returns>Returns the address of the syscall stub, or 0 on failure.</returns>
        __EBYTESYSCALLS_FUNC uintptr_t getsyscallstubaddr()
        {
            uintptr_t ntdllbase = getntdllbase();
            if (!ntdllbase) return 0;

            uintptr_t syscallstubaddr = getprocaddrbybase(ntdllbase, "NtAlpcSendWaitReceivePort");
            return syscallstubaddr;
        }

        /// <summary>
        /// Gets the address of an exported function from a module by name.
        /// </summary>
        /// <param name="modulename">Name of the module (e.g., L"ntdll.dll").</param>
        /// <param name="functionname">Name of the function to find.</param>
        /// <returns>Returns the address of the function, or 0 if not found.</returns>
        __EBYTESYSCALLS_FUNC uintptr_t getprocaddr(const wchar_t* modulename, const char* functionname)
        {
            uintptr_t modulebase = getmodulebase(modulename);
            if (!modulebase) return 0;

            return getprocaddrbybase(modulebase, functionname);
        }

        /// <summary>
        /// Checks if an address is within the bounds of a loaded module.
        /// </summary>
        /// <param name="addr">Address to check.</param>
        /// <param name="modulebase">Base address of the module.</param>
        /// <returns>Returns true if the address is within the module, otherwise false.</returns>
        __EBYTESYSCALLS_FUNC bool isaddrinmodule(uintptr_t addr, uintptr_t modulebase)
        {
            uintptr_t modulesize = getmodulesize(modulebase);
            return (addr >= modulebase && addr < (modulebase + modulesize));
        }

        /// <summary>
        /// Searches for a byte pattern with a mask in a module's memory.
        /// </summary>
        /// <param name="modulebase">Base address of the module to search.</param>
        /// <param name="pattern">Byte pattern to search for.</param>
        /// <param name="mask">Mask string where '?' matches any byte.</param>
        /// <returns>Returns the address where the pattern was found, or 0 if not found.</returns>
        __EBYTESYSCALLS_FUNC uintptr_t patternfind(uintptr_t modulebase, const char* pattern, const char* mask)
        {
            DWORD modulesize = getmodulesize(modulebase);
            if (!modulesize) return 0;

            size_t patternlen = 0;
            while (mask[patternlen]) patternlen++;

            uint8_t* scanaddr = reinterpret_cast<uint8_t*>(modulebase);

            for (size_t i = 0; i < modulesize - patternlen; i++)
            {
                bool found = true;
                for (size_t j = 0; j < patternlen; j++)
                {
                    if (mask[j] != '?' && scanaddr[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                    return reinterpret_cast<uintptr_t>(&scanaddr[i]);
            }

            return 0;
        }

        /// <summary>
        /// Searches for a byte pattern in module memory using the Boyer-Moore algorithm.
        /// </summary>
        /// <param name="modulebase">Base address of the module to search.</param>
        /// <param name="pattern">Byte array containing the pattern to search for.</param>
        /// <param name="patternlen">Length of the pattern in bytes.</param>
        /// <returns>Returns the address where the pattern was found, or 0 if not found.</returns>
        __EBYTESYSCALLS_FUNC uintptr_t boyermooresearch(uintptr_t modulebase, const uint8_t* pattern, size_t patternlen)
        {
            DWORD modulesize = getmodulesize(modulebase);
            if (!modulesize || !pattern || patternlen == 0) return 0;

            uint8_t* haystack = reinterpret_cast<uint8_t*>(modulebase);
            int chartable[256];

            for (int i = 0; i < 256; i++)
                chartable[i] = static_cast<int>(patternlen);

            for (size_t j = 0; j < patternlen - 1; j++)
                chartable[pattern[j]] = static_cast<int>(patternlen - 1 - j);

            for (size_t i = patternlen - 1; i < modulesize; )
            {
                size_t startpos = i;
                int j = static_cast<int>(patternlen) - 1;

                while (j >= 0 && pattern[j] == haystack[i])
                {
                    if (j == 0)
                        return reinterpret_cast<uintptr_t>(&haystack[startpos - patternlen + 1]);
                    i--;
                    j--;
                }

                i = startpos + chartable[haystack[startpos]];
            }

            return 0;
        }

        /// <summary>
        /// Searches for a byte signature pattern in module memory (format: "48 89 5C 24 08" with optional "??" wildcards).
        /// </summary>
        /// <param name="modulebase">Base address of the module to search.</param>
        /// <param name="signature">Hex signature string (e.g., "48 89 5C 24 08" or "B8 ?? ?? ?? ?? BA").</param>
        /// <returns>Returns the address where the signature was found, or 0 if not found.</returns>
        __EBYTESYSCALLS_FUNC uintptr_t findpattern(uintptr_t modulebase, const char* signature)
        {
            DWORD modulesize = getmodulesize(modulebase);
            if (!modulesize || !signature) return 0;

            uint8_t* scanaddr = reinterpret_cast<uint8_t*>(modulebase);

            uint8_t pattern[256];
            char mask[256];
            size_t patternindex = 0;
            size_t siglen = 0;

            while (signature[siglen]) siglen++;

            for (size_t i = 0; i < siglen; i++)
            {
                if (signature[i] == ' ') continue;

                if (signature[i] == '?')
                {
                    pattern[patternindex] = 0;
                    mask[patternindex] = '?';
                    patternindex++;
                    if (i + 1 < siglen && signature[i + 1] == '?') i++;
                }
                else if (i + 1 < siglen)
                {
                    char byte[3] = { signature[i], signature[i + 1], 0 };
                    char* endptr;
                    pattern[patternindex] = (uint8_t)strtoul(byte, &endptr, 16);
                    mask[patternindex] = 'x';
                    patternindex++;
                    i++;
                }
            }

            for (size_t i = 0; i <= modulesize - patternindex; i++)
            {
                bool found = true;
                for (size_t j = 0; j < patternindex; j++)
                {
                    if (mask[j] == 'x' && scanaddr[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                    return reinterpret_cast<uintptr_t>(&scanaddr[i]);
            }

            return 0;
        }

        /// <summary>
        /// Finds a code gadget (instruction sequence) in a module by signature.
        /// </summary>
        /// <param name="modulebase">Base address of the module to search.</param>
        /// <param name="signature">Hex signature of the gadget to find.</param>
        /// <returns>Returns the address of the gadget, or 0 if not found.</returns>
        __EBYTESYSCALLS_FUNC uintptr_t findgadget(uintptr_t modulebase, const char* signature)
        {
            return findpattern(modulebase, signature);
        }

        /// <summary>
        /// Finds common ROP (Return-Oriented Programming) gadgets in a module.
        /// </summary>
        /// <param name="modulebase">Base address of the module to search.</param>
        /// <param name="gadgettype">Type of gadget to find (e.g., "ret", "pop rcx", "jmp rbx").</param>
        /// <returns>Returns the address of the ROP gadget, or 0 if not found.</returns>
        __EBYTESYSCALLS_FUNC uintptr_t findropgadget(uintptr_t modulebase, const char* gadgettype)
        {
            if (strcmp(gadgettype, "ret") == 0)
                return findpattern(modulebase, "C3");

            if (strcmp(gadgettype, "pop rcx") == 0)
                return findpattern(modulebase, "59 C3");

            if (strcmp(gadgettype, "pop rdx") == 0)
                return findpattern(modulebase, "5A C3");

            if (strcmp(gadgettype, "pop r8") == 0)
                return findpattern(modulebase, "41 58 C3");

            if (strcmp(gadgettype, "pop r9") == 0)
                return findpattern(modulebase, "41 59 C3");

            if (strcmp(gadgettype, "jmp rbx") == 0)
                return findpattern(modulebase, "FF E3");

            if (strcmp(gadgettype, "jmp rcx") == 0)
                return findpattern(modulebase, "FF E1");

            if (strcmp(gadgettype, "jmp [rbx]") == 0)
                return findpattern(modulebase, "FF 23");

            if (strcmp(gadgettype, "jmp [rcx]") == 0)
                return findpattern(modulebase, "FF 21");

            if (strcmp(gadgettype, "add rsp 28") == 0)
                return findpattern(modulebase, "48 83 C4 28 C3");

            if (strcmp(gadgettype, "add rsp 38") == 0)
                return findpattern(modulebase, "48 83 C4 38 C3");

            return 0;
        }
    }

    namespace tramphook
    {
        /// <summary>
        /// Copies memory from source to destination, optionally changing memory protection.
        /// </summary>
        /// <param name="dst">Destination buffer to copy to.</param>
        /// <param name="src">Source buffer to copy from.</param>
        /// <param name="len">Number of bytes to copy.</param>
        /// <param name="changeprot">If true, changes memory protection to allow writing.</param>
        /// <returns>Returns true on success, otherwise false.</returns>
        __EBYTESYSCALLS_FUNC bool copymem(void* dst, void* src, size_t len, bool changeprot)
        {
            if (changeprot)
            {
                DWORD oldprot = 0;
                SIZE_T regionsize = len;
                PVOID baseaddr = dst;

                typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
                auto ntprotect = (pNtProtectVirtualMemory)internals::getprocaddr(L"ntdll.dll", "NtProtectVirtualMemory");

                if (!ntprotect) return false;

                NTSTATUS status = ntprotect(CURRENT_PROCESS, &baseaddr, &regionsize, PAGE_EXECUTE_READWRITE, &oldprot);
                if (status < 0) return false;

                definitions::vxmovememory(dst, src, len);

                ntprotect(CURRENT_PROCESS, &baseaddr, &regionsize, oldprot, &oldprot);
                return true;
            }
            else
            {
                definitions::vxmovememory(dst, src, len);
                return true;
            }
        }

        /// <summary>
        /// Installs a trampoline hook (JMP instruction) from source function to destination function.
        /// </summary>
        /// <param name="source">Address of the function to hook.</param>
        /// <param name="destination">Address of the hook function to redirect to.</param>
        /// <param name="originalbytes">Buffer to store the original bytes (must be at least 6 bytes).</param>
        /// <returns>Returns true if hook was installed successfully, otherwise false.</returns>
        __EBYTESYSCALLS_FUNC bool hookfunction(uintptr_t source, uintptr_t destination, uint8_t* originalbytes)
        {
            uint8_t hookcode[6];
            hookcode[0] = 0x90;
            hookcode[1] = 0xE9;

#ifdef _WIN64
            int64_t offset = destination - source - 6;
#else
            int32_t offset = destination - source - 6;
#endif

            definitions::vxmovememory(&hookcode[2], &offset, 4);

            if (originalbytes)
                definitions::vxmovememory(originalbytes, (void*)source, 6);

            return copymem((void*)source, hookcode, 6, true);
        }

        /// <summary>
        /// Removes a trampoline hook by restoring original bytes.
        /// </summary>
        /// <param name="address">Address of the hooked function.</param>
        /// <param name="originalbytes">Buffer containing the original bytes to restore.</param>
        /// <returns>Returns true if hook was removed successfully, otherwise false.</returns>
        __EBYTESYSCALLS_FUNC bool unhookfunction(uintptr_t address, uint8_t* originalbytes)
        {
            if (!originalbytes)
                return false;

            return copymem((void*)address, originalbytes, 6, true);
        }

        /// <summary>
        /// Installs custom hook code at a specified address.
        /// </summary>
        /// <param name="address">Address where to install the hook.</param>
        /// <param name="hookcode">Buffer containing the hook code to install.</param>
        /// <param name="len">Length of the hook code in bytes.</param>
        /// <returns>Returns true if hook was installed successfully, otherwise false.</returns>
        __EBYTESYSCALLS_FUNC bool installhook(uintptr_t address, uint8_t* hookcode, size_t len)
        {
            return copymem((void*)address, hookcode, len, true);
        }
    }

    /// <summary>
    /// Gets the System Call Number (SSN) from a syscall function's bytecode.
    /// </summary>
    /// <param name="modulebase">Base address of the module containing the syscall function.</param>
    /// <param name="functionname">Name of the syscall function (e.g., "NtQueryInformationProcess").</param>
    /// <returns>Returns the system call number, or 0 if not found.</returns>
    __EBYTESYSCALLS_FUNC uint32_t EbyteGetSSN(uintptr_t modulebase, const char* functionname)
    {
        auto funcaddr = internals::getprocaddrbybase(modulebase, functionname);
        if (!funcaddr) return 0;

#ifdef _WIN64
        uint32_t result = 0;
        definitions::vxmovememory(&result, (void*)(funcaddr + 4), sizeof(uint32_t));
        return result;
#else
        uint32_t result = 0;
        definitions::vxmovememory(&result, (void*)(funcaddr + 1), sizeof(uint32_t));
        return result;
#endif
    }

    /// <summary>
    /// Overwrites the system call number in a syscall stub to redirect execution.
    /// </summary>
    /// <param name="newsyscallidx">New system call number to write.</param>
    /// <param name="oldprotout">Optional pointer to receive the old memory protection value.</param>
    /// <param name="origsyscallidx">Pointer to receive the original system call number.</param>
    /// <param name="newprot">New memory protection flags (default: PAGE_EXECUTE_READWRITE).</param>
    /// <returns>Returns true on success, otherwise false.</returns>
    __EBYTESYSCALLS_FUNC bool EbyteOverwriteSSN(uint32_t newsyscallidx, PDWORD oldprotout, uint32_t* origsyscallidx, DWORD newprot = PAGE_EXECUTE_READWRITE)
    {
        uintptr_t ntdllbase = internals::getntdllbase();
        uintptr_t stubaddr = internals::getsyscallstubaddr();

        if (!ntdllbase || !stubaddr)
            return false;

#ifdef _WIN64
        const int offset = 4;
#else
        const int offset = 1;
#endif

        SIZE_T regionsize = 8;
        PVOID baseaddr = (PVOID)stubaddr;
        DWORD oldprot = 0;

        typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        auto ntprotect = (pNtProtectVirtualMemory)internals::getprocaddr(L"ntdll.dll", "NtProtectVirtualMemory");

        if (!ntprotect) return false;

        NTSTATUS status = ntprotect(CURRENT_PROCESS, &baseaddr, &regionsize, newprot, &oldprot);
        if (status < 0) return false;

        if (oldprotout)
            *oldprotout = oldprot;

        uint32_t oldsyscallidx = 0;
        definitions::vxmovememory(&oldsyscallidx, (void*)(stubaddr + offset), sizeof(uint32_t));
        definitions::vxmovememory((void*)(stubaddr + offset), &newsyscallidx, sizeof(uint32_t));
        *origsyscallidx = oldsyscallidx;

        baseaddr = (PVOID)stubaddr;
        regionsize = 8;
        ntprotect(CURRENT_PROCESS, &baseaddr, &regionsize, oldprot, &oldprot);

        return true;
    }

    namespace syscaller
    {
#ifdef _WIN64
        /// <summary>
        /// Calls a system call safely by dynamically overwriting the syscall stub (x64 version).
        /// </summary>
        /// <typeparam name="ReturnType">Return type of the syscall function.</typeparam>
        /// <typeparam name="Args">Variable template arguments matching the syscall parameters.</typeparam>
        /// <param name="syscallname">Name of the syscall function to call (e.g., "NtQueryInformationProcess").</param>
        /// <param name="args">Arguments to pass to the syscall function.</param>
        /// <returns>Returns the result of the syscall, or default-constructed ReturnType on failure.</returns>
        template<typename ReturnType, typename... Args>
        ReturnType EbyteSyscall(const char* syscallname, Args... args)
        {
            uintptr_t ntdllbase = internals::getntdllbase();
            if (!ntdllbase) return ReturnType();

            uintptr_t stubaddr = internals::getprocaddrbybase(ntdllbase, "NtAlpcSendWaitReceivePort");
            if (!stubaddr) return ReturnType();

            uint32_t syscallidx = EbyteGetSSN(ntdllbase, syscallname);
            if (!syscallidx) return ReturnType();

            DWORD oldprot = 0;
            uint32_t origsyscallidx = 0;

            if (!EbyteOverwriteSSN(syscallidx, &oldprot, &origsyscallidx))
                return ReturnType();

            using FnCaller = ReturnType(*)(Args...);
            auto syscallcaller = reinterpret_cast<FnCaller>(stubaddr);
            ReturnType result = syscallcaller(args...);

            SIZE_T regionsize = 8;
            PVOID baseaddr = (PVOID)stubaddr;

            typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
            auto ntprotect = (pNtProtectVirtualMemory)internals::getprocaddr(L"ntdll.dll", "NtProtectVirtualMemory");

            if (ntprotect)
            {
                DWORD tmpprot = 0;
                ntprotect(CURRENT_PROCESS, &baseaddr, &regionsize, PAGE_EXECUTE_READWRITE, &tmpprot);
                definitions::vxmovememory((void*)(stubaddr + 4), &origsyscallidx, sizeof(uint32_t));
                baseaddr = (PVOID)stubaddr;
                regionsize = 8;
                ntprotect(CURRENT_PROCESS, &baseaddr, &regionsize, oldprot, &oldprot);
            }

            return result;
        }
#else
        /// <summary>
        /// Assembly stub helper function for calling syscalls on x86 (naked function).
        /// </summary>
        /// <typeparam name="ReturnType">Return type of the syscall function.</typeparam>
        template<typename ReturnType>
        __declspec(naked) ReturnType __stdcall callsyscallstub()
        {
            __asm {
                mov eax, [esp + 4]
                call eax
                ret
            }
        }

        /// <summary>
        /// Calls a system call safely by dynamically overwriting the syscall stub (x86 version).
        /// </summary>
        /// <typeparam name="ReturnType">Return type of the syscall function.</typeparam>
        /// <typeparam name="Args">Variable template arguments matching the syscall parameters.</typeparam>
        /// <param name="syscallname">Name of the syscall function to call (e.g., "NtQueryInformationProcess").</param>
        /// <param name="args">Arguments to pass to the syscall function.</param>
        /// <returns>Returns the result of the syscall, or default-constructed ReturnType on failure.</returns>
        template<typename ReturnType, typename... Args>
        ReturnType EbyteSyscall(const char* syscallname, Args... args)
        {
            uintptr_t ntdllbase = internals::getntdllbase();
            if (!ntdllbase) return ReturnType();

            uintptr_t stubaddr = internals::getprocaddrbybase(ntdllbase, "NtAlpcSendWaitReceivePort");
            if (!stubaddr) return ReturnType();

            uint32_t syscallidx = EbyteGetSSN(ntdllbase, syscallname);
            if (!syscallidx) return ReturnType();

            DWORD oldprot = 0;
            uint32_t origsyscallidx = 0;

            if (!EbyteOverwriteSSN(syscallidx, &oldprot, &origsyscallidx))
                return ReturnType();

            using FnCaller = ReturnType(__stdcall*)(Args...);
            auto syscallcaller = reinterpret_cast<FnCaller>(stubaddr);
            ReturnType result = syscallcaller(args...);

            SIZE_T regionsize = 8;
            PVOID baseaddr = (PVOID)stubaddr;

            typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
            auto ntprotect = (pNtProtectVirtualMemory)internals::getprocaddr(L"ntdll.dll", "NtProtectVirtualMemory");

            if (ntprotect)
            {
                DWORD tmpprot = 0;
                ntprotect(CURRENT_PROCESS, &baseaddr, &regionsize, PAGE_EXECUTE_READWRITE, &tmpprot);
                definitions::vxmovememory((void*)(stubaddr + 1), &origsyscallidx, sizeof(uint32_t));
                baseaddr = (PVOID)stubaddr;
                regionsize = 8;
                ntprotect(CURRENT_PROCESS, &baseaddr, &regionsize, oldprot, &oldprot);
            }

            return result;
        }
#endif
    }

    namespace vehhook
    {
        extern definitions::PVEH_HOOK_ENTRY g_hooklist;

        /// <summary>
        /// Vectored Exception Handler that intercepts guard page violations and redirects execution to hook functions.
        /// Also handles intentional INT3 breakpoints for control flow obfuscation.
        /// </summary>
        /// <param name="pexcepinfo">Pointer to exception information structure containing exception code and CPU context.</param>
        /// <returns>Returns EXCEPTION_CONTINUE_EXECUTION if handled, EXCEPTION_CONTINUE_SEARCH otherwise.</returns>
        __EBYTESYSCALLS_FUNC LONG NTAPI vehexceptionhandler(PEXCEPTION_POINTERS pexcepinfo)
        {
            // Handle intentional INT3 breakpoint exceptions for control flow obfuscation
            if (pexcepinfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
            {
                uintptr_t rip = 0;
#ifdef _WIN64
                rip = pexcepinfo->ContextRecord->Rip;
#else
                rip = pexcepinfo->ContextRecord->Eip;
#endif

                definitions::PVEH_HOOK_ENTRY current = g_hooklist;
                while (current)
                {
                    // For INT3, Rip/eip points exactly to where INT3 was placed (the instruction pointer)
                    if (rip == (uintptr_t)current->OriginalFunction)
                    {
#ifdef _WIN64
                        pexcepinfo->ContextRecord->Rip = (uintptr_t)current->RedirectFunction;
#else
                        pexcepinfo->ContextRecord->Eip = (uintptr_t)current->RedirectFunction;
#endif
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                    current = current->Next;
                }
            }
            else if (pexcepinfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
            {
                uintptr_t rip = 0;
#ifdef _WIN64
                rip = pexcepinfo->ContextRecord->Rip;
#else
                rip = pexcepinfo->ContextRecord->Eip;
#endif

                definitions::PVEH_HOOK_ENTRY current = g_hooklist;
                while (current)
                {
                    if (rip == (uintptr_t)current->OriginalFunction)
                    {
#ifdef _WIN64
                        pexcepinfo->ContextRecord->Rip = (uintptr_t)current->RedirectFunction;
#else
                        pexcepinfo->ContextRecord->Eip = (uintptr_t)current->RedirectFunction;
#endif
                        pexcepinfo->ContextRecord->EFlags |= 0x100;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                    current = current->Next;
                }
            }
            else if (pexcepinfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
            {
                typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
                auto ntprotect = (pNtProtectVirtualMemory)internals::getprocaddr(L"ntdll.dll", "NtProtectVirtualMemory");
                
                if (ntprotect)
                {
                    definitions::PVEH_HOOK_ENTRY current = g_hooklist;
                    while (current)
                    {
                        PVOID baseaddr = current->OriginalFunction;
                        SIZE_T regionsize = 1;
                        ULONG old = 0;
                        ntprotect(CURRENT_PROCESS, &baseaddr, &regionsize, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
                        current = current->Next;
                    }
                }
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }

        /// <summary>
        /// Initializes the Vectored Exception Handler by registering it with Windows.
        /// </summary>
        /// <returns>Returns true if the handler was registered successfully, otherwise false.</returns>
        __EBYTESYSCALLS_FUNC bool initialize()
        {
            PVOID handler = AddVectoredExceptionHandler(1, vehexceptionhandler);
            return handler != nullptr;
        }

        /// <summary>
        /// Adds a VEH hook entry to the list and sets PAGE_GUARD protection on the target function.
        /// </summary>
        /// <param name="hookentry">Pointer to VEH_HOOK_ENTRY structure containing OriginalFunction and RedirectFunction addresses.</param>
        /// <returns>Returns true if the hook was added and protection was set successfully, otherwise false.</returns>
        __EBYTESYSCALLS_FUNC bool addhook(definitions::PVEH_HOOK_ENTRY hookentry)
        {
            if (!hookentry || !hookentry->OriginalFunction) return false;

            hookentry->Next = g_hooklist;
            g_hooklist = hookentry;

            typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
            auto ntprotect = (pNtProtectVirtualMemory)internals::getprocaddr(L"ntdll.dll", "NtProtectVirtualMemory");
            
            if (!ntprotect) return false;

            PVOID baseaddr = hookentry->OriginalFunction;
            SIZE_T regionsize = 1;
            ULONG oldprot = 0;
            NTSTATUS status = ntprotect(CURRENT_PROCESS, &baseaddr, &regionsize, PAGE_EXECUTE_READ | PAGE_GUARD, &oldprot);
            
            if (status < 0) return false;

            return true;
        }

        /// <summary>
        /// Removes a VEH hook entry from the list and restores normal memory protection.
        /// </summary>
        /// <param name="hookentry">Pointer to VEH_HOOK_ENTRY structure to remove from the hook list.</param>
        /// <returns>Returns true if the hook was removed and protection was restored successfully, otherwise false.</returns>
        __EBYTESYSCALLS_FUNC bool removehook(definitions::PVEH_HOOK_ENTRY hookentry)
        {
            if (!hookentry || !g_hooklist) return false;

            if (g_hooklist == hookentry)
            {
                g_hooklist = hookentry->Next;
                hookentry->Next = nullptr;
            }
            else
            {
                definitions::PVEH_HOOK_ENTRY current = g_hooklist;
                while (current->Next)
                {
                    if (current->Next == hookentry)
                    {
                        current->Next = hookentry->Next;
                        hookentry->Next = nullptr;
                        break;
                    }
                    current = current->Next;
                }
            }

            typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
            auto ntprotect = (pNtProtectVirtualMemory)internals::getprocaddr(L"ntdll.dll", "NtProtectVirtualMemory");
            
            if (ntprotect)
            {
                PVOID baseaddr = hookentry->OriginalFunction;
                SIZE_T regionsize = 1;
                ULONG oldprot = 0;
                ntprotect(CURRENT_PROCESS, &baseaddr, &regionsize, PAGE_EXECUTE_READ, &oldprot);
            }

            return true;
        }

        /// <summary>
        /// Finds a VEH hook entry by searching for the original function address.
        /// </summary>
        /// <param name="originalfunction">Address of the original function to search for.</param>
        /// <returns>Returns pointer to the VEH_HOOK_ENTRY if found, otherwise nullptr.</returns>
        __EBYTESYSCALLS_FUNC definitions::PVEH_HOOK_ENTRY findhook(LPVOID originalfunction)
        {
            definitions::PVEH_HOOK_ENTRY current = g_hooklist;
            while (current)
            {
                if (current->OriginalFunction == originalfunction)
                    return current;
                current = current->Next;
            }
            return nullptr;
        }

        /// <summary>
        /// Triggers an intentional exception at a specific address for control flow obfuscation.
        /// Uses INT3 (breakpoint instruction) to generate STATUS_BREAKPOINT exception.
        /// </summary>
        /// <param name="targetaddr">Address where to trigger the exception.</param>
        /// <param name="redirectaddr">Address to redirect execution to in the exception handler.</param>
        /// <param name="hookentry">Pre-allocated VEH_HOOK_ENTRY structure to use for the hook.</param>
        /// <returns>Returns true if the hook was set up successfully, otherwise false.</returns>
        __EBYTESYSCALLS_FUNC bool triggerint3hook(LPVOID targetaddr, LPVOID redirectaddr, definitions::PVEH_HOOK_ENTRY hookentry)
        {
            if (!targetaddr || !redirectaddr || !hookentry) return false;

            hookentry->OriginalFunction = targetaddr;
            hookentry->RedirectFunction = redirectaddr;
            hookentry->Next = nullptr;

            hookentry->Next = g_hooklist;
            g_hooklist = hookentry;

            typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
            auto ntprotect = (pNtProtectVirtualMemory)internals::getprocaddr(L"ntdll.dll", "NtProtectVirtualMemory");
            
            if (!ntprotect) return false;

            PVOID baseaddr = targetaddr;
            SIZE_T regionsize = 1;
            ULONG oldprot = 0;
            NTSTATUS status = ntprotect(CURRENT_PROCESS, &baseaddr, &regionsize, PAGE_EXECUTE_READWRITE, &oldprot);
            
            if (status < 0) return false;

            uint8_t int3 = 0xCC;
            definitions::vxmovememory(targetaddr, &int3, 1);

            ntprotect(CURRENT_PROCESS, &baseaddr, &regionsize, oldprot, &oldprot);

            typedef NTSTATUS(NTAPI* pNtFlushInstructionCache)(HANDLE, PVOID, SIZE_T);
            auto ntflush = (pNtFlushInstructionCache)internals::getprocaddr(L"ntdll.dll", "NtFlushInstructionCache");
            if (ntflush)
            {
                ntflush(CURRENT_PROCESS, targetaddr, 1);
            }

            return true;
        }
    }
}