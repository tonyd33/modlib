#include <Windows.h>
#include <TlHelp32.h>
#include <sstream>
#include <string>
#include <bddisasm/bddisasm.h>
#include <bddisasm/disasmtypes.h>
#include <vector>
#include <ranges>
#include "modlib.h"

namespace Util
{
    BytesAssembler& BytesAssembler::operator<<(uint8_t byte)
    {
        bytes.push_back(byte);
        return *this;
    }
    BytesAssembler& BytesAssembler::operator<<(const char* str)
    {
        size_t len = strlen(str);
        for (size_t i = 0; i < len; ++i) {
            bytes.push_back(static_cast<char>(str[i]));
        }
        return *this;
    }

    BytesAssembler& BytesAssembler::operator<<(const std::vector<char>& data)
    {
        bytes.insert(bytes.end(), data.begin(), data.end());
        return *this;
    }

    BytesAssembler& BytesAssembler::operator<<(uint32_t value)
    {
        std::vector<char> toPush =
        {
            static_cast<char>(value & 0xFF),
            static_cast<char>((value >> 8) & 0xFF),
            static_cast<char>((value >> 16) & 0xFF),
            static_cast<char>((value >> 24) & 0xFF),
        };
        if constexpr (std::endian::native != std::endian::little)
            std::reverse(toPush.begin(), toPush.end());
        bytes.insert(std::end(bytes), std::begin(toPush), std::end(toPush));
        return *this;
    }

    BytesAssembler& BytesAssembler::operator<<(uint64_t value)
    {

        std::vector<char> toPush =
        {
            static_cast<char>(value & 0xFF),
            static_cast<char>((value >> 8) & 0xFF),
            static_cast<char>((value >> 16) & 0xFF),
            static_cast<char>((value >> 24) & 0xFF),
            static_cast<char>((value >> 32) & 0xFF),
            static_cast<char>((value >> 40) & 0xFF),
            static_cast<char>((value >> 48) & 0xFF),
            static_cast<char>((value >> 56) & 0xFF),
        };
        if constexpr (std::endian::native != std::endian::little)
            std::reverse(toPush.begin(), toPush.end());
        bytes.insert(std::end(bytes), std::begin(toPush), std::end(toPush));
        return *this;
    }

    size_t BytesAssembler::size() const
    {
        return bytes.size();
    }

    const char* BytesAssembler::data() const
    {
        return bytes.data();
    }

    HookStatus HookManager::LLHookCreate(LLHook hook, bool immediate)
    {
        uintptr_t target = hook.target;
        if (llMap.contains(target)) return H_EXISTS;
        llMap[target] = hook;

        if (!immediate) return H_OK;

        HookStatus ret;

        ret = llMap[target].Prepare();
        if (ret != H_OK) return ret;

        ret = llMap[target].Enable();
        if (ret != H_OK) return ret;

        return H_OK;
    }

    HookStatus HookManager::LLHookCreate(
        uintptr_t target,
        LLHookFunc hook,
        bool runBefore,
        bool immediate
    )
    {
        return LLHookCreate(LLHook(target, hook, runBefore), immediate);
    }

    HookStatus HookManager::LLHookCreate(
        uintptr_t target,
        LLHookFunc hook,
        unsigned size,
        bool runBefore,
        bool immediate
    )
    {
        return LLHookCreate(LLHook(target, hook, size, runBefore), immediate);
    }

    HookStatus HookManager::LLHookPrepare(uintptr_t target)
    {
        if (!llMap.contains(target)) return H_NOTFOUND;
        return llMap[target].Prepare();
    }

    HookStatus HookManager::LLHookEnable(uintptr_t target)
    {
        if (!llMap.contains(target)) return H_NOTFOUND;
        return llMap[target].Enable();
    }

    HookStatus HookManager::LLHookDisable(uintptr_t target)
    {
        if (!llMap.contains(target)) return H_NOTFOUND;
        return llMap[target].Disable();
    }

    HookStatus HookManager::LLHookUnload(uintptr_t target)
    {
        if (!llMap.contains(target)) return H_NOTFOUND;
        return llMap[target].Unload();
    }

    HookStatus HookManager::LLHookDelete(uintptr_t target)
    {
        if (!llMap.contains(target)) return H_NOTFOUND;
        HookStatus ret;
        auto ll = llMap[target];

        ret = ll.Disable();
        if (ret != H_OK) return ret;

        ret = ll.Unload();
        if (ret != H_OK) return ret;

        llMap.erase(target);
        return H_OK;
    }

    void HookManager::LLHookPrepareAll()
    {
        for (auto& [key, val] : llMap) { val.Prepare(); }
    }
    void HookManager::LLHookEnableAll()
    {
        for (auto& [key, val] : llMap) { val.Enable(); }
    }
    void HookManager::LLHookDisableAll()
    {
        for (auto& [key, val] : llMap) { val.Disable(); }
    }
    void HookManager::LLHookUnloadAll()
    {
        for (auto& [key, val] : llMap) { val.Unload(); }
    }

    void HookManager::LLHookDeleteAll()
    {
        auto keys = std::views::keys(llMap);
        std::vector<uintptr_t> keysCopy{ keys.begin(), keys.end() };
        for (auto key : keysCopy) { LLHookDelete(key); }
    }

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

#define x64_PUSH_RSP "\x54"
#define x64_PUSH_RBP "\x55"
#define x64_PUSHF    "\x9c"
#define x64_PUSH_R15 "\x41\x57"
#define x64_PUSH_R14 "\x41\x56"
#define x64_PUSH_R13 "\x41\x55"
#define x64_PUSH_R12 "\x41\x54"
#define x64_PUSH_R11 "\x41\x53"
#define x64_PUSH_R10 "\x41\x52"
#define x64_PUSH_R9  "\x41\x51"
#define x64_PUSH_R8  "\x41\x50"
#define x64_PUSH_RAX "\x50"
#define x64_PUSH_RCX "\x51"
#define x64_PUSH_RDX "\x52"
#define x64_PUSH_RBX "\x53"
#define x64_PUSH_RSI "\x56"
#define x64_PUSH_RDI "\x57"

// these are actually two instructions: movq rax, xmmN; push rax
#define x64_VIRT_PUSH_XMM3 "\x66\x48\x0F\x7E\xD8\x50"
#define x64_VIRT_PUSH_XMM2 "\x66\x48\x0F\x7E\xD0\x50"
#define x64_VIRT_PUSH_XMM1 "\x66\x48\x0F\x7E\xC8\x50"
#define x64_VIRT_PUSH_XMM0 "\x66\x48\x0F\x7E\xC0\x50"

// these are actually two instructions: pop rax; movq xmmN, rax
#define x64_VIRT_POP_XMM0 "\x58\x66\x48\x0F\x6E\xc0"
#define x64_VIRT_POP_XMM1 "\x58\x66\x48\x0F\x6E\xC8"
#define x64_VIRT_POP_XMM2 "\x58\x66\x48\x0F\x6E\xD0"
#define x64_VIRT_POP_XMM3 "\x58\x66\x48\x0F\x6E\xD8"

#define x64_POP_RDI "\x5f"
#define x64_POP_RSI "\x5e"
#define x64_POP_RBX "\x5b"
#define x64_POP_RDX "\x5a"
#define x64_POP_RCX "\x59"
#define x64_POP_RAX "\x58"
#define x64_POP_R8  "\x41\x58"
#define x64_POP_R9  "\x41\x59"
#define x64_POP_R10 "\x41\x5a"
#define x64_POP_R11 "\x41\x5b"
#define x64_POP_R12 "\x41\x5c"
#define x64_POP_R13 "\x41\x5d"
#define x64_POP_R14 "\x41\x5e"
#define x64_POP_R15 "\x41\x5f"
#define x64_POPF    "\x9d"
#define x64_POP_RBP "\x5d"
#define x64_POP_RSP "\x5c"

    /* TODO: implement LLHook for x86 too
       have fun, future me. */
#ifdef _WIN64
    void WritePushCtx(BytesAssembler& strm)
    {
        strm
            << x64_PUSH_RSP
            << x64_PUSH_RBP
            << x64_PUSHF
            << x64_PUSH_R15
            << x64_PUSH_R14
            << x64_PUSH_R13
            << x64_PUSH_R12
            << x64_PUSH_R11
            << x64_PUSH_R10
            << x64_PUSH_R9
            << x64_PUSH_R8
            << x64_PUSH_RDI
            << x64_PUSH_RSI
            << x64_PUSH_RDX
            << x64_PUSH_RCX
            << x64_PUSH_RBX
            << x64_PUSH_RAX
            << x64_VIRT_PUSH_XMM3
            << x64_VIRT_PUSH_XMM2
            << x64_VIRT_PUSH_XMM1
            << x64_VIRT_PUSH_XMM0
            ;
    }

    void WritePopCtx(BytesAssembler& strm)
    {
        strm
            << x64_VIRT_POP_XMM0
            << x64_VIRT_POP_XMM1
            << x64_VIRT_POP_XMM2
            << x64_VIRT_POP_XMM3
            << x64_POP_RAX
            << x64_POP_RBX
            << x64_POP_RCX
            << x64_POP_RDX
            << x64_POP_RSI
            << x64_POP_RDI
            << x64_POP_R8
            << x64_POP_R9
            << x64_POP_R10
            << x64_POP_R11
            << x64_POP_R12
            << x64_POP_R13
            << x64_POP_R14
            << x64_POP_R15
            << x64_POPF
            << x64_POP_RBP
            << x64_POP_RSP
            ;
    }
#else
       /* TODO: x86 */
    void WritePushCtx(BytesAssembler& strm)
    {
    }

    void WritePopCtx(BytesAssembler& strm)
    {
    }
#endif

    /* tries to get a suitable instruction-aligned size for a hook.
       if a ret is found within the min hook size, return 0 size.
       a ret can cause problems with hooking. callers of LLHook should
       supply their own size and whether to run before/after if they're
       confident of the hook behavior. */
    unsigned FindHookSize(uintptr_t target)
    {
        auto cond = [](INSTRUX& ix) { return ix.Category != ND_CAT_RET; };

        uintptr_t end = DisasmUntil(target, MIN_HOOK_SIZE, cond);
        if (end == 0) return 0;

        // no loss of data to unsigned because end - target < MIN_HOOK_SIZE
        return end - target;
    }

    LLHook::LLHook() {}

    LLHook::LLHook(uintptr_t target, LLHookFunc hook)
    {
        this->target = target;
        this->hook = hook;
        this->size = FindHookSize(target);
    }

    LLHook::LLHook(uintptr_t target, LLHookFunc hook, unsigned size)
    {
        this->target = target;
        this->hook = hook;
        this->size = size;
    }

    LLHook::LLHook(
        uintptr_t target,
        LLHookFunc hook,
        bool runBefore
    )
    {
        this->target = target;
        this->hook = hook;
        this->size = size;
        this->size = FindHookSize(target);
        this->runBefore = runBefore;
    }

    LLHook::LLHook(
        uintptr_t target,
        LLHookFunc hook,
        unsigned size,
        bool runBefore
    )
    {
        this->target = target;
        this->hook = hook;
        this->size = size;
        this->runBefore = runBefore;
    }

#ifdef _WIN64
    HookStatus LLHook::Prepare()
    {
        if (size < MIN_HOOK_SIZE) return H_NOSPACE;
        if (prepared) return H_OK;
        DWORD tmpProt;
        size_t executableOrigOffset = 0;
        uintptr_t returnAddr = target + size;

        origInstrs.resize(size);


        VirtualProtect((LPVOID)target, size, PAGE_EXECUTE_READWRITE, &tmpProt);
        memcpy(origInstrs.data(), (void*)target, size);
        VirtualProtect((LPVOID)target, size, tmpProt, &tmpProt);

        BytesAssembler trampStrm;

        /* before jumping to the trampoline, we'll do:
           push rax
           mov rax, trampoline
           jmp rax

           so we gotta pop it here first */
        trampStrm << x64_POP_RAX;

        if (runBefore)
        {
            executableOrigOffset = trampStrm.size();
            // execute overwritten bytes
            trampStrm << origInstrs;
        }

        // push all registers
        WritePushCtx(trampStrm);

        trampStrm
            << "\x48\x89\xE1"                       // mov rcx, rsp
            << "\x48\x81\xEC" << (uint32_t)CTX_SIZE // sub rsp, CTX_SIZE
            << "\x48\xBA" << (uint64_t)hook         // mov rdx, hook
            << "\xFF\xD2"                           // call rdx
            << "\x48\x81\xC4" << (uint32_t)CTX_SIZE // add rsp, CTX_SIZE
            ;

        // pop all registers
        WritePopCtx(trampStrm);

        if (!runBefore)
        {
            executableOrigOffset = trampStrm.size();
            // execute overwritten bytes
            trampStrm << origInstrs;
        }

        /*
            we need to jump back with the following conditions:
            - registers are undisturbed
            - calling a literal can only take 4-byte values in x64
            - pushing a literal can only take 4-byte values in x64
            relevant information:
            - push can (and usually does) push 8-byte values in x64
            - ret pops an 8-byte address and jumps to it

            the solution is to push the lo 4-bytes as an 8-byte value onto the
            stack and manually modify the hi 4-bytes and then do a ret lmao
         */
        uint32_t lo = (uint32_t)(returnAddr & 0xFFFFFFFF);
        uint32_t hi = (uint32_t)(((returnAddr) >> 32) & 0xFFFFFFFF);
        if constexpr (std::endian::native == std::endian::big)
        {
            uint32_t tmp = lo;
            lo = hi;
            hi = tmp;
        }
        trampStrm
            << "\x68" << lo             // push lo
            << "\xC7\x44\x24\x04" << hi // mov [rsp+0x4], hi
            << "\xC3"                   // ret
            ;

        // set the actual trampoline
        trampSize = trampStrm.size();
        trampoline = (char*)malloc(trampSize);
        if (trampoline == NULL) return H_ERR;

        memcpy(trampoline, trampStrm.data(), trampSize);
        // set appropriate memory access
        VirtualProtect(trampoline, trampSize, PAGE_EXECUTE_READWRITE, &trampProtect);

        executableOrig = (uintptr_t)trampoline + executableOrigOffset;

        prepared = true;
        return H_OK;
    }
#else
    /* TODO: x86 */
    HookStatus LLHook::Prepare()
    {
        return H_ERR;
    }
#endif

#ifdef _WIN64
    HookStatus LLHook::Enable()
    {
        if (!prepared) return H_NOTPREPARED;

        DWORD tmp;
        BytesAssembler strm;

        VirtualProtect((LPVOID)target, size, PAGE_EXECUTE_READWRITE, &tmp);

        strm
            << "\x50"                             // push rax
            << "\x48\xB8" << (uint64_t)trampoline // mov rax, trampoline
            << "\xFF\xE0"                         // jmp rax
            ;

        // fill remaining bytes with nops
        for (size_t i = strm.size(); i < size; i++)
            strm << "\x90";

        memcpy((void*)target, strm.data(), size);

        // restore protects
        VirtualProtect((LPVOID)target, size, tmp, &tmp);

        enabled = true;
        return H_OK;
    }
#else
    /* TODO: x86 */
    HookStatus LLHook::Enable()
    {
        return H_ERR;
    }
#endif

    HookStatus LLHook::Disable()
    {
        if (!enabled) return H_OK;

        DWORD tmp;

        VirtualProtect((LPVOID)target, size, PAGE_EXECUTE_READWRITE, &tmp);
        memcpy((void*)target, origInstrs.data(), size);
        VirtualProtect((LPVOID)target, size, tmp, &tmp);

        enabled = false;
        return H_OK;
    }

    HookStatus LLHook::Unload()
    {
        if (enabled) return H_STILLENABLED;
        if (!prepared) return H_OK;

        VirtualProtect(trampoline, trampSize, trampProtect, &trampProtect);
        free(trampoline);

        prepared = false;
        return H_OK;
    }

    uintptr_t LLHook::GetExecutableOrig()
    {
        return executableOrig;
    }

}
