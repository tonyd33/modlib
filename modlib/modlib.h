#pragma once
#include <Windows.h>
#include <map>
#include <stdint.h>
#include <vector>
#include <string>
#include <bit>

#define MASK_IGNORE_CHAR '0'

namespace Util
{
    union XMMReg
    {
        float flt;
        double dbl;
    };

#ifdef _WIN64
#define MIN_HOOK_SIZE 13
#define CTX_SIZE 0xA8
    /* registers at the time right before jumping to the hook function.
       note that there's no RIP register because no point. */
    struct x64Ctx
    {
        /* xmm0, xmm1, xmm2, xmm3 */
        XMMReg xmm[4];

        uint64_t rax;
        uint64_t rbx;
        uint64_t rcx;
        uint64_t rdx;
        uint64_t rsi;
        uint64_t rdi;

        uint64_t r8;
        uint64_t r9;
        uint64_t r10;
        uint64_t r11;
        uint64_t r12;
        uint64_t r13;
        uint64_t r14;
        uint64_t r15;

        uint64_t rflags;

        uint64_t rbp;
        uint64_t rsp;
    };
    static_assert(sizeof(x64Ctx) == CTX_SIZE);

    typedef void (*LLHookFunc)(x64Ctx*);
#else
// TODO: complete x86
#define MIN_HOOK_SIZE 5
#define CTX_SIZE 0xA8
    struct x86Ctx {};
    typedef void (*LLHookFunc)(x86tx*);
#endif


    enum HookStatus
    {
        H_OK,
        H_NOTPREPARED,
        H_NOTFOUND,
        H_ERR,
        H_NOSPACE,
        H_STILLENABLED,
        H_EXISTS,
    };

    /* low level hook.
       tries to place a jmp at the specified address to a trampoline.
       trampoline will set up x(86|64)Ctx and then transfer control to
       caller. */
    struct LLHook
    {
    private:
        // don't use vector here because don't wanna ever change the pointer
        // to underlying r/w/e data
        char* trampoline = NULL;
        unsigned trampSize;
        DWORD trampProtect;

        std::vector<char> origInstrs;
        uintptr_t executableOrig;
    public:
        uintptr_t target;
        LLHookFunc hook;
        unsigned size;
        bool enabled = false;
        bool prepared = false;

        LLHook();
        LLHook(uintptr_t t, LLHookFunc h);
        LLHook(uintptr_t t, LLHookFunc h, unsigned s);

        HookStatus Prepare();
        HookStatus Enable();
        HookStatus Disable();
        HookStatus Unload();
        uintptr_t GetExecutableOrig();
    };


    class HookManager
    {
    private:
        std::map<uintptr_t, LLHook> llMap;
    public:
        HookStatus LLHookCreate(
            uintptr_t target,
            LLHookFunc hook,
            unsigned size,
            /* do prepare and enable if true */
            bool andEnable = false
        );
        HookStatus LLHookPrepare(uintptr_t target);
        HookStatus LLHookEnable(uintptr_t target);
        HookStatus LLHookDisable(uintptr_t target);
        HookStatus LLHookUnload(uintptr_t target);
        HookStatus LLHookDelete(uintptr_t target);

        /* not great because no status return */
        void LLHookPrepareAll();
        void LLHookEnableAll();
        void LLHookDisableAll();
        void LLHookUnloadAll();

        /*
            TODO: implement:
            - hook in remote process (is this even reasonable?)
            - function hooks
        */
    };

    /* get address of next instruction. */
    uintptr_t NextInstruction(uintptr_t currInstruction);

    /*
        searches for a pattern in the range.
        if mask[i] == MASK_IGNORE_CHAR, then bytePattern[i] is ignored to allow
        for wildcard-like behavior. any other (non-NULL) value of mask[i]
        will trigger a comparison for bytePattern[i].
        
        if not found, returns 0.
        otherwise, will return address of the first match.

        PRECONDITIONS:
        - pattern should be a hex string (e.g. "\xF3\E9\xA2")
        - length of pattern equals length of mask
     */
    uintptr_t SearchMaskedPattern(
        uintptr_t start,
        uintptr_t end,
        const char* bytePattern,
        const char* mask
    );
    uintptr_t SearchMaskedPatternEx(
        HANDLE hProc,
        uintptr_t start,
        uintptr_t end,
        const char* bytePattern,
        const char* mask
    );

    /*
        similar to SearchMaskedPattern, but accepts a literal string of hex
        characters for higher-level functionality and readability.
        - patterns can contain spaces and each space-delimited substring is
          called a "word"
        - words can contain multiple bytes
        - byte order is determined by the endianness argument
        - patterns can contain a wilcard in the form of "?"
        - multibyte words must not contain a wildcard
    */
    uintptr_t SearchPattern(
        uintptr_t start,
        uintptr_t end,
        std::string pattern,
        std::endian endianness = std::endian::native
    );

    uintptr_t SearchPatternEx(
        HANDLE hProc,
        uintptr_t start,
        uintptr_t end,
        std::string pattern,
        std::endian endianness = std::endian::native
    );

    /* helper function to parse a high-level pattern into a byte pattern and
       mask, returning it in bytePattern and mask. defined here for testing. */
    void ParsePattern(
        const std::string& pattern,
        std::string& bytePattern,
        std::string& mask,
        std::endian endianness = std::endian::native
    );

    void Patch(void* dst, void* src, unsigned size);
    void PatchEx(HANDLE hProc, void* dst, void* src, unsigned size);

    uintptr_t ResolveMLP(uintptr_t ptr, std::vector<unsigned> offsets);
    uintptr_t ResolveMLPEx(
        HANDLE hProc,
        uintptr_t ptr,
        std::vector<unsigned> offsets
    );

    uintptr_t GetModuleBaseAddr(DWORD procId, const wchar_t* modName);
    DWORD GetProcId(const wchar_t* procName);
}
