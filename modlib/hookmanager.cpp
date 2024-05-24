#include <ranges>
#include "modlib.h"

namespace Util
{
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
}