#include <ranges>
#include "modlib.h"

namespace Util
{
    HookStatus HookManager::LLHookCreate(LLHook hook, bool immediate)
    {
        uintptr_t target = hook.target;
        if (llMap.contains(target)) return H_EXISTS;
        llMap[target] = std::make_unique<LLHook>(hook);

        if (!immediate) return H_OK;

        HookStatus ret;

        ret = llMap[target]->Prepare();
        if (ret != H_OK) return ret;

        ret = llMap[target]->Enable();
        if (ret != H_OK) return ret;

        return H_OK;
    }

    HookStatus HookManager::AssemblyHookCreate(AssemblyHook hook, bool immediate)
    {
        uintptr_t target = hook.target;
        if (llMap.contains(target)) return H_EXISTS;
        llMap[target] = std::make_unique<AssemblyHook>(hook);

        if (!immediate) return H_OK;

        HookStatus ret;

        ret = llMap[target]->Prepare();
        if (ret != H_OK) return ret;

        ret = llMap[target]->Enable();
        if (ret != H_OK) return ret;

        return H_OK;
    }


    HookStatus HookManager::HookPrepare(uintptr_t target)
    {
        if (!llMap.contains(target)) return H_NOTFOUND;
        return llMap[target]->Prepare();
    }

    HookStatus HookManager::HookEnable(uintptr_t target)
    {
        if (!llMap.contains(target)) return H_NOTFOUND;
        return llMap[target]->Enable();
    }

    HookStatus HookManager::HookDisable(uintptr_t target)
    {
        if (!llMap.contains(target)) return H_NOTFOUND;
        return llMap[target]->Disable();
    }

    HookStatus HookManager::HookUnload(uintptr_t target)
    {
        if (!llMap.contains(target)) return H_NOTFOUND;
        return llMap[target]->Unload();
    }

    HookStatus HookManager::HookDelete(uintptr_t target)
    {
        if (!llMap.contains(target)) return H_NOTFOUND;
        HookStatus ret;
        auto& ll = llMap[target];

        ret = ll->Disable();
        if (ret != H_OK) return ret;

        ret = ll->Unload();
        if (ret != H_OK) return ret;

        llMap.erase(target);
        return H_OK;
    }

    void HookManager::HookPrepareAll()
    {
        for (auto& [key, val] : llMap) { val->Prepare(); }
    }
    void HookManager::HookEnableAll()
    {
        for (auto& [key, val] : llMap) { val->Enable(); }
    }
    void HookManager::HookDisableAll()
    {
        for (auto& [key, val] : llMap) { val->Disable(); }
    }
    void HookManager::HookUnloadAll()
    {
        for (auto& [key, val] : llMap) { val->Unload(); }
    }

    void HookManager::HookDeleteAll()
    {
        auto keys = std::views::keys(llMap);
        std::vector<uintptr_t> keysCopy{ keys.begin(), keys.end() };
        for (auto key : keysCopy) { HookDelete(key); }
    }
}