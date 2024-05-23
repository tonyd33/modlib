#include <iostream>
#include <algorithm>
#include "modlib.h"

/* i know there is the assert macro, but i don't like it because it just
   crashes the program without giving helpful info. i rewrite it here to
   log extra info. */
#define expectOrRet(EXPR, RET) if (!(EXPR)) { \
fprintf(stderr, "[%s:%d] Failed %s\n", __FILE__, __LINE__, #EXPR); \
return (RET); \
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
    expect(bytePattern.size() == 2)
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
        std::endian endian = std::endian::native
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


static bool evil = false;
void DummyFunc()
{
    printf("Henlo world :D\n");
}

void DummyHook(Util::x64Ctx* ctx)
{
    printf("Being evil >:D\n");
    evil = true;
}

bool TestLLHook()
{
    Util::HookManager hm;
    // this sucks really bad, we want to make this test as compiler independent
    // as possible, but... we'll fix that later

    // DummyFunction is actually a near jmp instruction
    uintptr_t dummyFuncRealAddr = (uintptr_t)DummyFunc;
    // so we add the operand as an offset
    dummyFuncRealAddr += *(uint32_t*)((uintptr_t)DummyFunc + 1);
    // plus the number of bytes the jmp instruction is
    dummyFuncRealAddr += 5;
    hm.LLHookCreate(
        dummyFuncRealAddr,
        (Util::LLHookFunc)DummyHook,
        0xf, // not good, try to make compiler independent
        true
    );
    expect(!evil);
    DummyFunc();
    expect(evil);

    hm.LLHookDelete(dummyFuncRealAddr);

    return true;
}

int main()
{
    expectMain(TestPatternParse());
    expectMain(TestSearchPattern());
    expectMain(TestResolveMLP());
    expectMain(TestLLHook());

    printf("All tests passed!\n");
    return 0;
}