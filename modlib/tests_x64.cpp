#include <iostream>
#include <algorithm>
#include <memory>
#include "modlib.h"
#include <bddisasm/bddisasm.h>
#include <bddisasm/disasmtypes.h>

/* i know there are the assert macro, but i don't like it because it just
   crashes the program without giving helpful info. i rewrite it here to
   log extra info. */
#define expectOrRet(EXPR, RET) if (!(EXPR)) { \
fprintf(stderr, "[%s:%d] Failed %s\n", __FILE__, __LINE__, #EXPR); \
return (RET); \
}
#define expectStoreGoto(EXPR, STORE, LAB) if (!(EXPR)) { \
fprintf(stderr, "[%s:%d] Failed %s\n", __FILE__, __LINE__, #EXPR); \
ret = ret | false; \
goto LAB; \
}

#define expect(EXPR) expectOrRet(EXPR, false);
#define expectMain(EXPR) expectOrRet(EXPR, 1);

bool TestPatternParse()
{
    std::string pattern, bytePattern, mask;
    auto isntMask = [](char c) { return c != MASK_IGNORE_CHAR; };

    // start basic
    pattern = "F3 E9 A2";
    bytePattern.clear();
    mask.clear();
    Util::ParsePattern(pattern, bytePattern, mask, std::endian::little);
    expect(bytePattern.size() == mask.size());
    expect(bytePattern[0] == '\xF3');
    expect(bytePattern[1] == '\xE9');
    expect(bytePattern[2] == '\xA2');
    expect(mask[0] != MASK_IGNORE_CHAR);
    expect(mask[1] != MASK_IGNORE_CHAR);
    expect(mask[2] != MASK_IGNORE_CHAR);
    expect(std::all_of(mask.begin(), mask.end(), isntMask));
    // end basic

    // start middle single wildcard
    pattern = "A7 ? F6";
    bytePattern.clear();
    mask.clear();
    Util::ParsePattern(pattern, bytePattern, mask, std::endian::little);
    expect(bytePattern.size() == mask.size());
    expect(bytePattern[0] == '\xA7');
    expect(bytePattern[2] == '\xF6');
    expect(mask[0] != MASK_IGNORE_CHAR);
    expect(mask[1] == MASK_IGNORE_CHAR);
    expect(mask[2] != MASK_IGNORE_CHAR);
    // end middle single wildcard

    // start middle many wildcard
    pattern = "B3 ?? C0";
    bytePattern.clear();
    mask.clear();
    Util::ParsePattern(pattern, bytePattern, mask, std::endian::little);
    expect(bytePattern.size() == mask.size());
    expect(bytePattern[0] == '\xB3');
    expect(bytePattern[2] == '\xC0');
    expect(mask[0] != MASK_IGNORE_CHAR);
    expect(mask[1] == MASK_IGNORE_CHAR);
    expect(mask[2] != MASK_IGNORE_CHAR);
    // end middle many wildcard

    // start end wildcard
    pattern = "D8 C9 ?";
    bytePattern.clear();
    mask.clear();
    Util::ParsePattern(pattern, bytePattern, mask, std::endian::little);
    expect(bytePattern.size() == mask.size());
    expect(bytePattern[0] == '\xD8');
    expect(bytePattern[1] == '\xC9');
    expect(mask[0] != MASK_IGNORE_CHAR);
    expect(mask[1] != MASK_IGNORE_CHAR);
    expect(mask[2] == MASK_IGNORE_CHAR);
    // end end wildcard

    // start extra whitespace
    pattern = "D2   C4 ";
    bytePattern.clear();
    mask.clear();
    Util::ParsePattern(pattern, bytePattern, mask, std::endian::little);
    expect(bytePattern.size() == mask.size());
    expect(bytePattern.size() == 2);
    expect(bytePattern[0] == '\xD2');
    expect(bytePattern[1] == '\xC4');
    expect(std::all_of(mask.begin(), mask.end(), isntMask));
    // end extra whitespace

    // start multiple bytes, little endian
    pattern = "1234 EF";
    bytePattern.clear();
    mask.clear();
    Util::ParsePattern(pattern, bytePattern, mask, std::endian::little);
    expect(bytePattern.size() == mask.size());
    expect(bytePattern.size() == 3)
        expect(bytePattern[0] == '\x34');
    expect(bytePattern[1] == '\x12');
    expect(bytePattern[2] == '\xEF');
    expect(std::all_of(mask.begin(), mask.end(), isntMask));
    // end multiple bytes, little endian

    // start multiple bytes, big endian
    pattern = "1234 EF";
    bytePattern.clear();
    mask.clear();
    Util::ParsePattern(pattern, bytePattern, mask, std::endian::big);
    expect(bytePattern.size() == mask.size());
    expect(bytePattern.size() == 3)
        expect(bytePattern[0] == '\x12');
    expect(bytePattern[1] == '\x34');
    expect(bytePattern[2] == '\xEF');
    expect(std::all_of(mask.begin(), mask.end(), isntMask));
    // end multiple bytes, big endian

    // start endianness doesn't affect words
    pattern = "12 34 EF";
    bytePattern.clear();
    mask.clear();
    Util::ParsePattern(pattern, bytePattern, mask, std::endian::little);
    expect(bytePattern.size() == mask.size());
    expect(bytePattern.size() == 3)
        expect(bytePattern[0] == '\x12');
    expect(bytePattern[1] == '\x34');
    expect(bytePattern[2] == '\xEF');
    expect(std::all_of(mask.begin(), mask.end(), isntMask));

    bytePattern.clear();
    mask.clear();
    Util::ParsePattern(pattern, bytePattern, mask, std::endian::big);
    expect(bytePattern.size() == mask.size());
    expect(bytePattern.size() == 3)
        expect(bytePattern[0] == '\x12');
    expect(bytePattern[1] == '\x34');
    expect(bytePattern[2] == '\xEF');
    expect(std::all_of(mask.begin(), mask.end(), isntMask));
    // end endianness doesn't affect words

    return true;
}

bool TestSearchPattern()
{
    //                        0   1   2   3   4   5   6   7   8   9
    const char* byteArray = "\x01\x23\x45\x67\x89\xAB\xCD\xEF\x01\x23";
    uintptr_t patternAddr;

    auto SearchPattern = [byteArray](
        const char* pattern,
        std::endian endian = std::endian::little
        )
        {
            return Util::SearchPattern(
                (uintptr_t)byteArray,
                (uintptr_t)byteArray + 7,
                pattern,
                endian
            );
        };

    // gets first match
    patternAddr = SearchPattern("01 23");
    expect(patternAddr == (uintptr_t)byteArray);

    // wildcard
    patternAddr = SearchPattern("45 ? 89 AB");
    expect(patternAddr == (uintptr_t)byteArray + 2);

    // doesn't care for extra chars in wildcard
    patternAddr = SearchPattern("45 ?? 89 AB");
    expect(patternAddr == (uintptr_t)byteArray + 2);

    // double wildcard
    patternAddr = SearchPattern("45 ? 89 ?");
    expect(patternAddr == (uintptr_t)byteArray + 2);

    // little endian
    patternAddr = SearchPattern("45 ? AB89", std::endian::little);
    expect(patternAddr == (uintptr_t)byteArray + 2);

    // big endian
    patternAddr = SearchPattern("45 ? 89AB", std::endian::big);
    expect(patternAddr == (uintptr_t)byteArray + 2);

    // no match
    patternAddr = SearchPattern("45 89");
    expect(patternAddr == 0);

    return true;
}

#define A_PAD 22
#define B_PAD 18
#define C_PAD 28
struct A;
struct B;
struct C;
#pragma pack(push, 1)
struct A
{
    char pad[A_PAD];
    B* b;
};
struct B
{
    char pad[B_PAD];
    C* c;
};

struct C
{
    char pad[C_PAD];
    int value;
};
#pragma pack(pop)

bool TestResolveMLP()
{
    A* a = (A*)malloc(sizeof(A));
    B* b = (B*)malloc(sizeof(B));
    C* c = (C*)malloc(sizeof(C));

    a->b = b;
    b->c = c;
    c->value = 123;

    expect(((uintptr_t)&a->b - (uintptr_t)a) == A_PAD);
    expect(((uintptr_t)&b->c - (uintptr_t)b) == B_PAD);
    expect(((uintptr_t)&c->value - (uintptr_t)c) == C_PAD);

    // showcasing some ways to use this
    uintptr_t resolve1 = Util::ResolveMLP((uintptr_t)a + A_PAD, { B_PAD, C_PAD });
    uintptr_t resolve2 = Util::ResolveMLP((uintptr_t)&a, { A_PAD, B_PAD, C_PAD });
    expect(resolve1 == resolve2);
    expect(resolve1 == (uintptr_t)&c->value);
    expect(*(int*)resolve1 == c->value);

    free(a);
    free(b);
    free(c);

    return true;
}


extern "C"
{
    int evil = false;
    extern void DummyFunc();
    extern uint8_t DummyFuncStartLabel;
    extern uint8_t DummyFuncMidLabel;
}

bool runBefore = false;
bool ctxVerified = false;

bool DummyHookBeforeVerifier(Util::x64Ctx* ctx)
{
    expect(ctx->rax == 1122);
    expect(ctx->rbx == 2233);
    expect(ctx->rcx == 3344);
    return true;
}

bool DummyHookAfterVerifier(Util::x64Ctx* ctx)
{
    expect(ctx->rax == 4455);
    expect(ctx->rbx == 6677);
    expect(ctx->rcx == 8899);
    return true;
}

void DummyHook(Util::x64Ctx* ctx)
{
    evil = true;
    if (runBefore)
        ctxVerified = DummyHookBeforeVerifier(ctx);
    else
        ctxVerified = DummyHookAfterVerifier(ctx);
}

bool TestLLHook()
{
    Util::HookManager hm;
    runBefore = false;
    evil = false;
    ctxVerified = false;

    /* idk why, but doing &DummyFuncLabel gives me an address to a jump
       table entry to DummyFunc. addressof seems to give the real address */
    uintptr_t startLabelAddr = (uintptr_t)std::addressof(DummyFuncStartLabel);
    uintptr_t midLabelAddr = (uintptr_t)std::addressof(DummyFuncMidLabel);

    // sanity checks
    INSTRUX ix;
    NDSTATUS status;
    status = NdDecodeEx(&ix, (ND_UINT8*)startLabelAddr, 21, ND_CODE_64, ND_DATA_64);
    expect(ND_SUCCESS(status));
    expect(ix.Length == 7); // mov rax, x
    // end sanity checks

    // start hook and run orig code before
    Util::LLHook hook1(midLabelAddr, DummyHook);
    hook1.size = 21;
    runBefore = false;
    hook1.runBefore = runBefore;
    expect(hook1.Prepare() == Util::H_OK);
    expect(hook1.Enable() == Util::H_OK);
    DummyFunc();
    expect(evil);
    expect(ctxVerified);
    evil = false;
    ctxVerified = false;
    hook1.Disable();
    hook1.Unload();
    // end hook and run orig code before


    // start hook and run orig code before
    Util::LLHook hook2(midLabelAddr, DummyHook);
    hook2.size = 21;
    runBefore = true;
    hook2.runBefore = runBefore;
    expect(hook2.Prepare() == Util::H_OK);
    expect(hook2.Enable() == Util::H_OK);
    DummyFunc();
    expect(evil);
    expect(ctxVerified);
    evil = false;
    ctxVerified = false;
    hook2.Disable();
    hook2.Unload();
    // end hook and run orig code before

    // start hook auto size
    Util::LLHook hook3(midLabelAddr, DummyHook);
    hook3.size = 0;
    expect(hook3.Prepare() == Util::H_OK);
    expect(hook3.size <= MIN_HOOK_SIZE_FAR);
    hook3.Unload();
    // end hook autosize

    return true;
}

/* TODO: spawn the process and pattern search for the desired instruction */
bool TestAssemblyHookEx()
{
    Util::HookManager hm;
    runBefore = true;

    uintptr_t modBaseAddr = 0;
    uintptr_t offset = 0x122e2;
    uintptr_t target = 0;

    // too lazy to debug creating the process from here. just run the program before running these tests for now
    DWORD procId = Util::GetProcId(L"dummyprogram.exe");
    expect(procId != 0);
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procId);
    expect(hProc != NULL);

    modBaseAddr = Util::GetModuleBaseAddr(procId, L"dummyprogram.exe");
    expect(modBaseAddr != 0);
    target = modBaseAddr + offset;

    unsigned char buf[4];
    expect(ReadProcessMemory(hProc, (LPCVOID)target, buf, 4, NULL) != 0);
    expect(buf[0] == 0xc6);
    expect(buf[1] == 0x45);
    expect(buf[2] == 0x04);
    expect(buf[3] == 0x00);

    std::string assembly = "\xC6\x45\x04\x01"s;
    Util::AssemblyHook hook(hProc, target, std::vector<unsigned char>(assembly.begin(), assembly.end()));
    hook.size = 15;
    hook.runBefore = true;
    hook.Prepare();
    hook.Enable();
    // the other process might be sleeping. give it some time to reach our hook and kill itself
    Sleep(1500);
    hook.Disable();
    hook.Unload();


    // expect it to FAIL because the process should be terminated already
    expect(TerminateProcess(hProc, 0) == 0);
    CloseHandle(hProc);
    return true;
}

int main()
{
    expectMain(TestPatternParse());
    expectMain(TestSearchPattern());
    expectMain(TestResolveMLP());
    expectMain(TestLLHook());
    // expectMain(TestAssemblyHookEx());

    printf("All tests passed!\n");
    return 0;
}