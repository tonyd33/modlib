#include <Windows.h>
#include <TlHelp32.h>
#include <sstream>
#include <string>
#include "modlib.h"
#include <bddisasm/bddisasm.h>
#include <bddisasm/disasmtypes.h>

namespace Util
{
    int HexCharToInt(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::invalid_argument("Invalid hex character");
    }

    // Function to convert a string to an underlying hex string
    std::string ConvertToHexString(const std::string& input) {
        if (input.size() % 2 != 0) {
            throw std::invalid_argument("Input string length must be even");
        }

        std::string result;
        result.reserve(input.size() / 2); // Reserve space for the result

        for (size_t i = 0; i < input.size(); i += 2) {
            char highNibble = HexCharToInt(input[i]);
            char lowNibble = HexCharToInt(input[i + 1]);
            char byte = (highNibble << 4) | lowNibble;
            result += byte;
        }

        return result;
    }

    /* tries to get a suitable instruction-aligned size for a hook.
       if a ret is found within the min hook size, return 0 size.
       a ret can cause problems with hooking. callers of LLHook should
       supply their own size and whether to run before/after if they're
       confident of the hook behavior. */
    unsigned FindHookSize(uintptr_t target)
    {
        auto cond = [](INSTRUX& ix) { return ix.Category != ND_CAT_RET; };

        // no point in searching past this amount
        uintptr_t end = DisasmUntil(target, MIN_HOOK_SIZE_FAR + MAX_INSTR_LEN, cond);
        if (end == 0) return 0;

        // no loss of data to unsigned because end - target is bounded
        return end - target;
    }

    /* keeps disassembling instructions until a condition has been met or
       we hit the max. */
    uintptr_t DisasmUntil(uintptr_t start, unsigned max, bool (*cond)(INSTRUX&))
    {
        INSTRUX ix;
        NDSTATUS status;
        ND_UINT8* curr = (ND_UINT8*)start;

        unsigned acc = 0;

        do {
            status = NdDecode(&ix, (ND_UINT8*)curr, ND_NATIVE_DEC, ND_NATIVE_DATA);

            /* discard the entire operation if not success. this may mean we
               weren't properly byte-aligned to begin with or something else
               as catastrophically bad. */
            if (!ND_SUCCESS(status)) return 0;

            acc += ix.Length;
        } while (!cond(ix) && acc < max);

        return start + acc;
    }


    uintptr_t NextInstruction(uintptr_t currInstruction)
    {
        INSTRUX ix;
        NDSTATUS status = NdDecode(&ix, (ND_UINT8*)currInstruction, ND_NATIVE_DEC, ND_NATIVE_DATA);
        if (!ND_SUCCESS(status)) return 0;

        return currInstruction + ix.Length;
    }

    std::vector<std::string> SplitString(
        const std::string& str,
        char delimiter
    )
    {
        std::vector<std::string> result;
        std::stringstream ss(str);
        std::string item;

        while (std::getline(ss, item, delimiter)) {
            result.push_back(item);
        }

        return result;
    }

    void InsertChunk(
        const std::string& chunk,
        std::string& bytePattern,
        std::string& mask,
        std::endian endianness
    )
    {
        std::string hexString = ConvertToHexString(chunk);
        if (endianness == std::endian::little)
            std::reverse(hexString.begin(), hexString.end());

        bytePattern += (hexString);
        mask += std::string(hexString.size(), 'x');
    }

    void ParsePattern(
        const std::string& pattern,
        std::string& bytePattern,
        std::string& mask,
        std::endian endianness
    )
    {
        std::vector<std::string> chunks = SplitString(pattern, ' ');
        for (std::string chunk : chunks)
        {
            if (chunk.size() == 0) continue;
            if (chunk[0] == '?')
            {
                bytePattern += '\x00'; // whatever
                mask += MASK_IGNORE_CHAR;
            }
            else
            {
                InsertChunk(chunk, bytePattern, mask, endianness);
            }
        }
    }

    bool CompareMaskedBytes(
        const char* on,
        const char* bytePattern,
        const char* mask
    )
    {
        for (; *mask != NULL; ++mask, ++on, ++bytePattern)
        {
            if (*mask == MASK_IGNORE_CHAR) continue;
            if (*on != *bytePattern) return false;
        }

        return true;
    }

    uintptr_t SearchMaskedPattern(
        uintptr_t start,
        uintptr_t end,
        const char* bytePattern,
        const char* mask
    )
    {
        for (uintptr_t i = start; i < end; i++)
        {
            if (CompareMaskedBytes((char*)i, bytePattern, mask))
                return i;
        }
        return 0;
    }

    /* TODO: implement */
    uintptr_t SearchMaskedPatternEx(
        HANDLE hProc,
        uintptr_t start,
        uintptr_t end,
        const char* bytePattern,
        const char* mask
    )
    {
        return 0;
    }

    uintptr_t SearchPattern(
        uintptr_t start,
        uintptr_t end,
        std::string pattern,
        std::endian endianness
    )
    {
        std::string bytePattern, mask;
        ParsePattern(pattern, bytePattern, mask, endianness);

        return SearchMaskedPattern(
            start,
            end,
            bytePattern.c_str(),
            mask.c_str()
        );
    }

    /* TODO: implement */
    uintptr_t SearchPatternEx(
        HANDLE hProc,
        uintptr_t start,
        uintptr_t end,
        std::string pattern,
        std::endian endianness
    ) {
        return 0;
    }

    void Patch(void* dst, void* src, unsigned size)
    {
        DWORD tmp;
        VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &tmp);
        memcpy(dst, src, size);
        VirtualProtect(dst, size, tmp, &tmp);
    }

    void PatchEx(HANDLE hProcess, void* dst, void* src, unsigned size)
    {
        DWORD tmp;
        VirtualProtectEx(hProcess, dst, size, PAGE_EXECUTE_READWRITE, &tmp);
        WriteProcessMemory(hProcess, dst, src, size, nullptr);
        VirtualProtectEx(hProcess, dst, size, tmp, &tmp);
    }

    uintptr_t ResolveMLP(uintptr_t ptr, std::vector<unsigned> offsets)
    {
        uintptr_t addr = ptr;
        for (unsigned int i = 0; i < offsets.size(); ++i)
        {
            addr = *(uintptr_t*)addr;
            addr += offsets[i];
        }
        return addr;

    }

    uintptr_t ResolveMLPEx(HANDLE hProc, uintptr_t ptr, std::vector<unsigned> offsets)
    {
        uintptr_t addr = ptr;
        for (unsigned int i = 0; i < offsets.size(); ++i)
        {
            ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0);
            addr += offsets[i];
        }
        return addr;
    }

    uintptr_t GetModuleBaseAddr(DWORD procId, const wchar_t* modName)
    {
        //initialize to zero for error checking
        uintptr_t modBaseAddr = 0;

        //get a handle to a snapshot of all modules
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);

        //check if it's valid
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            //this struct holds the actual module information
            MODULEENTRY32 modEntry;

            //this is required for the function to work
            modEntry.dwSize = sizeof(modEntry);

            //If a module exists, get it's entry
            if (Module32First(hSnap, &modEntry))
            {
                //loop through the modules
                do
                {
                    //compare the module name against ours
                    if (!_wcsicmp(modEntry.szModule, modName))
                    {
                        //copy the base address and break out of the loop
                        modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                        break;
                    }

                    //each iteration we grab the next module entry
                } while (Module32Next(hSnap, &modEntry));
            }
        }

        //free the handle
        CloseHandle(hSnap);
        return modBaseAddr;
    }

    DWORD GetProcId(const wchar_t* procName)
    {
        DWORD procId = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32 procEntry;
            procEntry.dwSize = sizeof(procEntry);

            if (Process32First(hSnap, &procEntry))
            {
                do
                {
                    if (!_wcsicmp(procEntry.szExeFile, procName))
                    {
                        procId = procEntry.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hSnap, &procEntry));
            }
        }
        CloseHandle(hSnap);
        return procId;
    }

    bool InjectDLL_LoadLibrary(const char* dllPath, HANDLE hProc, DLL_INJECTION_METHOD method)
    {

        void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (loc == NULL) return false;

        WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, NULL);

        HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
        if (hThread == NULL) return false;

        CloseHandle(hThread);

        return true;
    }

    bool InjectDLL(const wchar_t* dllPath, HANDLE hProc, DLL_INJECTION_METHOD method)
    {

    }
}