#include <Windows.h>
#include <TlHelp32.h>
#include <sstream>
#include <string>
#include <bit>
#include "modlib.h"
#include <bddisasm/bddisasm.h>
#include <bddisasm/disasmtypes.h>

#define x64_PUSH_RSP "\x54"s
#define x64_PUSH_RBP "\x55"s
#define x64_PUSHF    "\x9c"s
#define x64_PUSH_R15 "\x41\x57"s
#define x64_PUSH_R14 "\x41\x56"s
#define x64_PUSH_R13 "\x41\x55"s
#define x64_PUSH_R12 "\x41\x54"s
#define x64_PUSH_R11 "\x41\x53"s
#define x64_PUSH_R10 "\x41\x52"s
#define x64_PUSH_R9  "\x41\x51"s
#define x64_PUSH_R8  "\x41\x50"s
#define x64_PUSH_RAX "\x50"s
#define x64_PUSH_RCX "\x51"s
#define x64_PUSH_RDX "\x52"s
#define x64_PUSH_RBX "\x53"s
#define x64_PUSH_RSI "\x56"s
#define x64_PUSH_RDI "\x57"s

// these are actually two instructions: movq rax, xmmN; push rax
#define x64_VIRT_PUSH_XMM3 "\x66\x48\x0F\x7E\xD8\x50"s
#define x64_VIRT_PUSH_XMM2 "\x66\x48\x0F\x7E\xD0\x50"s
#define x64_VIRT_PUSH_XMM1 "\x66\x48\x0F\x7E\xC8\x50"s
#define x64_VIRT_PUSH_XMM0 "\x66\x48\x0F\x7E\xC0\x50"s

// these are actually two instructions: pop rax; movq xmmN, rax
#define x64_VIRT_POP_XMM0 "\x58\x66\x48\x0F\x6E\xc0"s
#define x64_VIRT_POP_XMM1 "\x58\x66\x48\x0F\x6E\xC8"s
#define x64_VIRT_POP_XMM2 "\x58\x66\x48\x0F\x6E\xD0"s
#define x64_VIRT_POP_XMM3 "\x58\x66\x48\x0F\x6E\xD8"s

#define x64_POP_RDI "\x5f"s
#define x64_POP_RSI "\x5e"s
#define x64_POP_RBX "\x5b"s
#define x64_POP_RDX "\x5a"s
#define x64_POP_RCX "\x59"s
#define x64_POP_RAX "\x58"s
#define x64_POP_R8  "\x41\x58"s
#define x64_POP_R9  "\x41\x59"s
#define x64_POP_R10 "\x41\x5a"s
#define x64_POP_R11 "\x41\x5b"s
#define x64_POP_R12 "\x41\x5c"s
#define x64_POP_R13 "\x41\x5d"s
#define x64_POP_R14 "\x41\x5e"s
#define x64_POP_R15 "\x41\x5f"s
#define x64_POPF    "\x9d"s
#define x64_POP_RBP "\x5d"s
#define x64_POP_RSP "\x5c"s

#define INTERN_ALLOC(hProc, size) malloc((size))
#define EXTERN_ALLOC(hProc, size) VirtualAllocEx((hProc), 0, (size), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
#define ALLOC(hProc, size) (uintptr_t)((hProc) == nullptr ? \
    INTERN_ALLOC((hProc), (size)) : \
    EXTERN_ALLOC((hProc), (size)))

#define INTERN_FREE(hProc, ptr) free((ptr))
#define EXTERN_FREE(hProc, ptr) VirtualFreeEx((hProc), (ptr), 0, MEM_RELEASE)
#define FREE(hProc, ptr) \
if ((hProc) == NULL) INTERN_FREE(hProc, ptr); \
else EXTERN_FREE(hProc, ptr); \

#define INTERN_READMEM(hProc, dst, src, size) memcpy(((void*)dst), ((void*)src), ((size_t)size))
#define EXTERN_READMEM(hProc, dst, src, size) ReadProcessMemory((hProc), ((LPCVOID)src), ((LPVOID)dst), ((SIZE_T)size), 0)
#define READMEM(hProc, dst, src, size) \
if ((hProc) == NULL) INTERN_READMEM(hProc, dst, src, size); \
else EXTERN_READMEM(hProc, dst, src, size); \

#define INTERN_WRITEMEM(hProc, dst, src, size) memcpy(((void*)dst), ((void*)src), ((size_t)size))
#define EXTERN_WRITEMEM(hProc, dst, src, size) WriteProcessMemory((hProc), ((LPVOID)dst), ((LPVOID)src), ((SIZE_T)size), 0)
#define WRITEMEM(hProc, dst, src, size) \
if ((hProc) == NULL) INTERN_WRITEMEM(hProc, dst, src, size); \
else EXTERN_WRITEMEM(hProc, dst, src, size); \

#define INTERN_VIRTUALPROTECT(hProc, addr, size, prot, old) VirtualProtect(((LPVOID)addr), (size), (prot), (old))
#define EXTERN_VIRTUALPROTECT(hProc, addr, size, prot, old) VirtualProtectEx((hProc), ((LPVOID)addr), (size), (prot), (old))
#define VIRTUALPROTECT(hProc, addr, size, prot, old) \
if ((hProc) == NULL) INTERN_VIRTUALPROTECT(hProc, addr, size, prot, old); \
else EXTERN_VIRTUALPROTECT(hProc, addr, size, prot, old)

namespace Util
{

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

    void WriteJumpBack(BytesAssembler& strm, uintptr_t returnAddr)
    {
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
        strm
            << "\x68" << lo             // push lo
            << "\xC7\x44\x24\x04" << hi // mov [rsp+0x4], hi
            << "\xC3"                   // ret
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

    HookStatus IHook::Prepare()
    {
        return H_ABSTRACT;
    }

    HookStatus IHook::Enable()
    {
        return H_ABSTRACT;
    }

    HookStatus IHook::Disable()
    {
        return H_ABSTRACT;
    }

    HookStatus IHook::Unload()
    {
        return H_ABSTRACT;
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

        if (runBefore && runOrig)
        {
            executableOrigOffset = trampStrm.size();
            // execute overwritten bytes
            trampStrm << origInstrs;
        }

        // push all registers
        WritePushCtx(trampStrm);

        trampStrm
            << "\x48\x89\xE1"s                       // mov rcx, rsp
            << "\x48\x81\xEC"s << (uint32_t)CTX_SIZE // sub rsp, CTX_SIZE
            << "\x48\xBA"s << (uint64_t)hook         // mov rdx, hook
            << "\xFF\xD2"s                           // call rdx
            << "\x48\x81\xC4"s << (uint32_t)CTX_SIZE // add rsp, CTX_SIZE
            ;

        // pop all registers
        WritePopCtx(trampStrm);

        if (!runBefore && runOrig)
        {
            executableOrigOffset = trampStrm.size();
            // execute overwritten bytes
            trampStrm << origInstrs;
        }

        WriteJumpBack(trampStrm, returnAddr);

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
    HookStatus LLHook::Enable()
    {
        if (!prepared) return H_NOTPREPARED;

        DWORD tmp;
        BytesAssembler strm;

        VirtualProtect((LPVOID)target, size, PAGE_EXECUTE_READWRITE, &tmp);

        strm
            << "\x50"s                             // push rax
            << "\x48\xB8"s << (uint64_t)trampoline // mov rax, trampoline
            << "\xFF\xE0"s                         // jmp rax
            ;

        // fill remaining bytes with nops
        for (size_t i = strm.size(); i < size; i++)
            strm << "\x90"s;

        memcpy((void*)target, strm.data(), size);

        // restore protects
        VirtualProtect((LPVOID)target, size, tmp, &tmp);

        enabled = true;
        return H_OK;
    }
#else
    /* TODO: x86 */
    HookStatus LLHook::Prepare()
    {
        return H_ERR;
    }
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


    AssemblyHook::AssemblyHook() {}

    /* TODO: find hook size on remote process */
    /*
    AssemblyHook::AssemblyHook(uintptr_t target, std::vector<char> hook)
    {
        this->target = target;
        this->assembly = hook;
        this->size = FindHookSize(target);
    }
    */

    AssemblyHook::AssemblyHook(HANDLE hProc, uintptr_t target, std::vector<unsigned char> hook, unsigned size)
    {
        this->hProc = hProc;
        this->target = target;
        this->assembly = hook;
        this->size = size;
    }

    /* TODO: find hook size on remote process */
    /*
    AssemblyHook::AssemblyHook(
        uintptr_t target,
        std::vector<char> hook,
        bool runBefore
    )
    {
        this->target = target;
        this->assembly = hook;
        this->size = size;
        this->size = FindHookSize(target);
        this->runBefore = runBefore;
    }
    */

    AssemblyHook::AssemblyHook(
        HANDLE hProc,
        uintptr_t target,
        std::vector<unsigned char> hook,
        unsigned size,
        bool runBefore
    )
    {
        this->hProc = hProc;
        this->target = target;
        this->assembly = hook;
        this->size = size;
        this->runBefore = runBefore;
    }

#ifdef _WIN64
    HookStatus AssemblyHook::Prepare()
    {
        if (size < MIN_HOOK_SIZE) return H_NOSPACE;
        if (prepared) return H_OK;
        DWORD tmpProt;

        size_t executableOrigOffset = 0;
        uintptr_t returnAddr = target + size;
        origInstrs.resize(size);

        VIRTUALPROTECT(hProc, target, size, PAGE_EXECUTE_READWRITE, &tmpProt);
        READMEM(hProc, origInstrs.data(), target, size);
        VIRTUALPROTECT(hProc, target, size, tmpProt, &tmpProt);

        BytesAssembler trampStrm;

        /* before jumping to the trampoline, we'll do:
           push rax
           mov rax, trampoline
           jmp rax

           so we gotta pop it here first */
        trampStrm << x64_POP_RAX;
        if (runBefore && runOrig)
        {
            executableOrigOffset = trampStrm.size();
            trampStrm << origInstrs;
        }

        trampStrm << assembly;

        if (!runBefore && runOrig)
        {
            executableOrigOffset = trampStrm.size();
            trampStrm << origInstrs;
        }

        WriteJumpBack(trampStrm, returnAddr);

        // set the actual trampoline
        trampSize = trampStrm.size();
        trampoline = (char*)ALLOC(hProc, trampSize);
        if (trampoline == NULL) return H_ERR;

        WRITEMEM(hProc, trampoline, trampStrm.data(), trampSize);
        // set appropriate memory access
        VIRTUALPROTECT(hProc, trampoline, trampSize, PAGE_EXECUTE_READWRITE, &trampProtect);

        executableOrig = (uintptr_t)trampoline + executableOrigOffset;

        prepared = true;
        return H_OK;
    }
    HookStatus AssemblyHook::Enable()
    {
        if (!prepared) return H_NOTPREPARED;

        DWORD tmp;
        BytesAssembler strm;

        VIRTUALPROTECT(hProc, target, size, PAGE_EXECUTE_READWRITE, &tmp);

        strm
            << "\x50"s                             // push rax
            << "\x48\xB8"s << (uint64_t)trampoline // mov rax, trampoline
            << "\xFF\xE0"s                         // jmp rax
            ;

        // fill remaining bytes with nops
        for (size_t i = strm.size(); i < size; i++)
            strm << "\x90"s;

        WRITEMEM(hProc, target, strm.data(), size);

        // restore protects
        VIRTUALPROTECT(hProc, target, size, tmp, &tmp);

        enabled = true;
        return H_OK;
    }
#else
    /* TODO: x86 */
    HookStatus AssemblyHook::Prepare()
    {
        return H_ERR;
    }
    /* TODO: x86 */
    HookStatus AssemblyHook::Enable()
    {
        return H_ERR;
    }
#endif

    HookStatus AssemblyHook::Disable()
    {
        if (!enabled) return H_OK;

        DWORD tmp;

        VIRTUALPROTECT(hProc, target, size, PAGE_EXECUTE_READWRITE, &tmp);
        WRITEMEM(hProc, target, origInstrs.data(), size);
        VIRTUALPROTECT(hProc, target, size, tmp, &tmp);

        enabled = false;
        return H_OK;
    }

    HookStatus AssemblyHook::Unload()
    {
        if (enabled) return H_STILLENABLED;
        if (!prepared) return H_OK;

        VIRTUALPROTECT(hProc, trampoline, trampSize, trampProtect, &trampProtect);
        FREE(hProc, trampoline);

        prepared = false;
        return H_OK;
    }

    uintptr_t AssemblyHook::GetExecutableOrig()
    {
        return executableOrig;
    }
}
