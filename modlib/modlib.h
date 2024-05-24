#pragma once
#include <Windows.h>
#include <map>
#include <stdint.h>
#include <memory>
#include <vector>
#include <string>
#include <string_view>
#include <bit>
#include <bddisasm/bddisasm.h>
#include <bddisasm/disasmtypes.h>

/* REMEMBER TO USE THIS WHEN USING BytesAssembler OR OTHER ASSEMBLY STUFF!!!!! */
using namespace std::string_literals;

#define MASK_IGNORE_CHAR '0'

namespace Util
{
    /* helper class for adding assembly instructions easily. allows for a file-like
       interface for pushing bytes into the stream. accounts for endianness */
    class BytesAssembler
    {
    private:
        std::vector<char> bytes;
    public:
        BytesAssembler& operator<<(uint8_t byte);
        /* this is kind of bad honestly. it's way too easy to forget to
           initialize a string literal and write something like "\xe9\x00\x01",
           which will be recognized as "\xe9" when implicit casting */
        BytesAssembler& operator<<(const std::string& data);
        BytesAssembler& operator<<(const std::vector<unsigned char>& data);
        BytesAssembler& operator<<(uint32_t value);
        BytesAssembler& operator<<(uint64_t value);


        size_t size() const;
        const char* data() const;
        
    };

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
#define CTX_SIZE 1
    struct x86Ctx 
    {

    };
    static_assert(sizeof(x86Ctx) == CTX_SIZE);

    typedef void (*LLHookFunc)(x86Ctx*);
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
        H_ABSTRACT
    };

    struct IHook
    {
    public:
        uintptr_t target;
        unsigned size;
        bool enabled = false;
        bool prepared = false;
        bool runBefore;
        bool runOrig = true;

        virtual HookStatus Prepare() = 0;
        virtual HookStatus Enable() = 0;
        virtual HookStatus Disable() = 0;
        virtual HookStatus Unload() = 0;
    };

    /* low level hook.
       tries to place a jmp at the specified address to a trampoline.
       trampoline will set up x(86|64)Ctx and then transfer control to
       caller via a call. once returned to trampoline, does some cleanup
       before jumping back to original flow. */
    struct LLHook : public IHook
    {
    private:
        // don't use vector here because don't wanna ever change the pointer
        // to underlying r/w/e data
        char* trampoline = NULL;
        size_t trampSize;
        DWORD trampProtect;

        std::vector<unsigned char> origInstrs;
        uintptr_t executableOrig;

        /* TODO: support runOrig = false in LLHook */
    public:
        LLHookFunc hook;

        LLHook();
        LLHook(uintptr_t t, LLHookFunc h);
        LLHook(uintptr_t t, LLHookFunc h, unsigned s);
        LLHook(uintptr_t target, LLHookFunc hook, bool runBefore);
        LLHook(uintptr_t t, LLHookFunc h, unsigned s, bool runBefore = false);

        HookStatus Prepare() override;
        HookStatus Enable() override;
        HookStatus Disable() override;
        HookStatus Unload() override;
        uintptr_t GetExecutableOrig();
    };

    /* even lower-level than LLHook.
       we just place a jmp at the specified address to a tiny trampoline
       that's accepted as bytecode. then, we jump back. */
    struct AssemblyHook : public IHook
    {
    private:
        // don't use vector here because don't wanna ever change the pointer
        // to underlying r/w/e data
        char* trampoline = NULL;
        size_t trampSize;
        DWORD trampProtect;

        std::vector<unsigned char> origInstrs;
        uintptr_t executableOrig;
    public:
        AssemblyHook();
        /* TODO: find hook size on remote process */
        // AssemblyHook(uintptr_t t, std::vector<char> h);
        AssemblyHook(HANDLE hProc, uintptr_t t, std::vector<unsigned char> h, unsigned s);
        // AssemblyHook(uintptr_t target, std::vector<char> hook, bool runBefore);
        AssemblyHook(
            HANDLE hProc,
            uintptr_t t,
            std::vector<unsigned char> h,
            unsigned s,
            bool runBefore = false
        );

        HANDLE hProc = NULL;
        uintptr_t target;
        std::vector<unsigned char> assembly;

        HookStatus Prepare() override;
        HookStatus Enable() override;
        HookStatus Disable() override;
        HookStatus Unload() override;
        uintptr_t GetExecutableOrig();
    };

    class HookManager
    {
    private:
        std::map<uintptr_t, std::unique_ptr<IHook>> llMap;

        HookStatus LLHookCreate(LLHook hook, bool andEnable = false);
        HookStatus AssemblyHookCreate(AssemblyHook hook, bool andEnable = false);
    public:
        HookStatus LLHookCreate(
            uintptr_t target,
            LLHookFunc hook,
            bool runBefore = false,
            bool andEnable = false
        );
        HookStatus LLHookCreate(
            uintptr_t target,
            LLHookFunc hook,
            unsigned size,
            bool runBefore = false,
            bool andEnable = false
        );

        HookStatus AssemblyHookCreate(
            HANDLE hProc,
            uintptr_t target,
            std::vector<unsigned char> assembly,
            bool runBefore = false,
            bool andEnable = false
        );
        HookStatus AssemblyHookCreate(
            HANDLE hProc,
            uintptr_t target,
            std::vector<unsigned char> assembly,
            unsigned size,
            bool runBefore = false,
            bool andEnable = false
        );

        HookStatus HookPrepare(uintptr_t target);
        HookStatus HookEnable(uintptr_t target);
        HookStatus HookDisable(uintptr_t target);
        HookStatus HookUnload(uintptr_t target);
        HookStatus HookDelete(uintptr_t target);

        /* not great because no status return */
        void HookPrepareAll();
        void HookEnableAll();
        void HookDisableAll();
        void HookUnloadAll();
        void HookDeleteAll();

        /*
            TODO: implement:
            - hook in remote process (is this even reasonable? prob not)
            - function hooks
        */
    };

#ifdef _WIN64
#define ND_NATIVE_DEC  ND_CODE_64
#define ND_NATIVE_DATA ND_DATA_64
#else
#define ND_NATIVE_DEC  ND_CODE_32
#define ND_NATIVE_DATA ND_DATA_32
#endif

    unsigned FindHookSize(uintptr_t target);

    uintptr_t DisasmUntil(uintptr_t start, unsigned max, bool (*cond)(INSTRUX&));

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
