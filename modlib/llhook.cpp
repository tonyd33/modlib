#include <Windows.h>
#include <TlHelp32.h>
#include <sstream>
#include <string>
#include <bit>
#include "modlib.h"
#include "bddisasm/bddisasm.h"
#include "bddisasm/disasmtypes.h"

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
#else
       /* TODO: x86 */
#endif

    /* tries to get a suitable instruction-aligned size for a hook.
       if a ret is found within the min hook size, return 0 size.
       a ret can cause problems with hooking. callers of LLHook should
       supply their own size and whether to run before/after if they're
       confident of the hook behavior. */
    uintptr_t FindHookSize(uintptr_t target)
    {
        auto cond = [](INSTRUX& ix) { return ix.Category != ND_CAT_RET; };

        uintptr_t end = DisasmUntil(target, MIN_HOOK_SIZE, cond);
        if (end == 0) return end;

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
        unsigned executableOrigOffset = 0;
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
        for (int i = strm.size(); i < size; i++)
            strm << "\x90";

        memcpy((void*)target, strm.data(), size);

        // restore protects
        VirtualProtect((LPVOID)target, size, tmp, &tmp);

        enabled = true;
        return H_OK;
    }
#else
    /* TODO: x86 */
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
