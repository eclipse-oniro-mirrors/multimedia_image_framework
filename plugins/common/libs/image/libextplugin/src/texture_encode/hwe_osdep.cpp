/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hwe_osdep.h"

#if defined(_WIN32)
#include "securec.h"
#endif

#define ID_AA64PFR0_ADVSIMD_BIT 20
#define MVFR1_ADVSIMD_BIT 8

namespace OHOS {
namespace ImagePlugin {
// detect cpu simd capibility
HWE_KernelType HWE_DetectSimdCapibility(void)
{
    HWE_KernelType ret = KERNEL_TYPE_C;
#if HWE_ARM_AARCH64
    uint64_t regval = 0;
    uint64_t advSimd;

    asm volatile("mrs %0, ID_AA64PFR0_EL1" : "=r"(regval));
    advSimd = (regval >> ID_AA64PFR0_ADVSIMD_BIT) & 0xf; // 0xf: bitmask
    if (advSimd == 0x0 || advSimd == 0x1) {              // 0x0: support neon without fp16; 0x1: support neno with fp16
        ret = KERNEL_TYPE_NEON;
    } else {
        ret = KERNEL_TYPE_C;
    }
#elif HWE_ARM_AARCH32
#if !HWE_IANDROID_ARM
    uint32_t regval = 0;
    uint32_t advSimd;

    asm volatile("mrs %0, MVFR1" : "=r"(regval));
    advSimd = (regval >> MVFR1_ADVSIMD_BIT) & 0xfff; // 0xff: bitmask
    if (advSimd == 0x111) {                          // 0x111: support neon
        ret = KERNEL_TYPE_NEON;
    } else {
        ret = KERNEL_TYPE_C;
    }
#else
    ret = KERNEL_TYPE_NEON;
#endif
#elif HWE_X86_64
    ret = KERNEL_TYPE_AVX2;
#elif HWE_X86_32
    ret = KERNEL_TYPE_C;
#endif
    return ret;
}

#ifdef _WIN32
static HWE_Win32ThreadControl g_threadPool;

int32_t HWE_PthreadMutexInit(HWE_PthreadMutex *mutex)
{
    return !InitializeCriticalSectionAndSpinCount(mutex, HWE_SPIN_COUNT);
}

int32_t HWE_PthreadMutexLock(HWE_PthreadMutex *mutex)
{
    static HWE_PthreadMutex init = HWE_PTHREAD_MUTEX_INITIALIZER;
    if (!memcmp(mutex, &init, sizeof(HWE_PthreadMutex))) {
        *mutex = g_threadPool.staticMutex;
    }
    EnterCriticalSection(mutex);
    return 0;
}

int32_t HWE_PthreadMutexUnLock(HWE_PthreadMutex *mutex)
{
    LeaveCriticalSection(mutex);
    return 0;
}

int32_t HWE_PthreadMutexDestroy(HWE_PthreadMutex *mutex)
{
    LeaveCriticalSection(mutex);
    return 0;
}

int32_t HWE_PthreadCondInit(HWE_PthreadCond *cond)
{
    HWE_Win32Cond *win32Cond = nullptr;
    if (g_threadPool.condInit) {
        g_threadPool.condInit(cond);
        return 0;
    }
    win32Cond = (HWE_Win32Cond *)calloc(1, sizeof(HWE_Win32Cond));
    if (!win32Cond) {
        return -1;
    }
    cond->ptr = win32Cond;
    win32Cond->semaphore = CreateSemaphore(nullptr, 0, 0x7fffffff, nullptr);
    if (!win32Cond->semaphore) {
        return -1;
    }
    if (HWE_PthreadMutexInit(&win32Cond->mtxWaiterCount)) {
        return -1;
    }
    if (HWE_PthreadMutexInit(&win32Cond->mtxBroadcast)) {
        return -1;
    }
    win32Cond->waitersDone = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!win32Cond->waitersDone) {
        return -1;
    }
    return 0;
}

int32_t HWE_PthreadCondDestroy(HWE_PthreadCond *cond)
{
    HWE_Win32Cond *win32Cond = nullptr;
    if (g_threadPool.condInit) {
        return 0;
    }
    win32Cond = (HWE_Win32Cond *)cond->ptr;
    CloseHandle(win32Cond->semaphore);
    CloseHandle(win32Cond->waitersDone);
    HWE_PthreadMutexDestroy(&win32Cond->mtxBroadcast);
    HWE_PthreadMutexDestroy(&win32Cond->mtxWaiterCount);
    free(win32Cond);
    return 0;
}

int32_t HWE_PthreadCondWait(HWE_PthreadCond *cond, HWE_PthreadMutex *mutex)
{
    HWE_Win32Cond *win32Cond = nullptr;
    int32_t iLastWaiter;
    if (g_threadPool.condWait) {
        return !g_threadPool.condWait(cond, mutex, INFINITE);
    }
    win32Cond = (HWE_Win32Cond *)cond->ptr;
    (VOID)HWE_PthreadMutexLock(&win32Cond->mtxBroadcast);
    (VOID)HWE_PthreadMutexLock(&win32Cond->mtxWaiterCount);
    win32Cond->waiterCount++;
    (VOID)HWE_PthreadMutexUnLock(&win32Cond->mtxWaiterCount);
    (VOID)HWE_PthreadMutexUnLock(&win32Cond->mtxBroadcast);
    (VOID)HWE_PthreadMutexUnLock(mutex);
    WaitForSingleObject(win32Cond->semaphore, INFINITE);
    (VOID)HWE_PthreadMutexLock(&win32Cond->mtxWaiterCount);
    win32Cond->waiterCount--;
    iLastWaiter = !win32Cond->waiterCount || !win32Cond->isBroadcast;
    (VOID)HWE_PthreadMutexUnLock(&win32Cond->mtxWaiterCount);
    if (iLastWaiter) {
        SetEvent(win32Cond->waitersDone);
    }
    return HWE_PthreadMutexLock(mutex);
}

int32_t HWE_PthreadCondSignal(HWE_PthreadCond *cond)
{
    HWE_Win32Cond *win32Cond = nullptr;
    int32_t haveWaiter;
    if (g_threadPool.condSignal) {
        g_threadPool.condSignal(cond);
        return 0;
    }
    win32Cond = (HWE_Win32Cond *)cond->ptr;
    (VOID)HWE_PthreadMutexLock(&win32Cond->mtxBroadcast);
    (VOID)HWE_PthreadMutexLock(&win32Cond->mtxWaiterCount);
    haveWaiter = win32Cond->waiterCount;
    (VOID)HWE_PthreadMutexUnLock(&win32Cond->mtxWaiterCount);
    if (haveWaiter) {
        ReleaseSemaphore(win32Cond->semaphore, 1, nullptr);
        WaitForSingleObject(win32Cond->waitersDone, INFINITE);
    }
    return HWE_PthreadMutexUnLock(&win32Cond->mtxBroadcast);
}

int32_t HWE_PthreadCondBroadcast(HWE_PthreadCond *cond)
{
    HWE_Win32Cond *win32Cond = nullptr;
    int32_t haveWaiter = 0;
    if (g_threadPool.condBroadcast) {
        g_threadPool.condBroadcast(cond);
        return 0;
    }
    win32Cond = (HWE_Win32Cond *)cond->ptr;
    (VOID)HWE_PthreadMutexLock(&win32Cond->mtxBroadcast);
    (VOID)HWE_PthreadMutexLock(&win32Cond->mtxWaiterCount);
    if (win32Cond->waiterCount) {
        win32Cond->isBroadcast = 1;
        haveWaiter = 1;
    }
    if (haveWaiter) {
        ReleaseSemaphore(win32Cond->semaphore, win32Cond->waiterCount, nullptr);
        (VOID)HWE_PthreadMutexUnLock(&win32Cond->mtxWaiterCount);
        WaitForSingleObject(win32Cond->waitersDone, INFINITE);
        win32Cond->isBroadcast = 0;
    } else {
        (VOID)HWE_PthreadMutexUnLock(&win32Cond->mtxWaiterCount);
    }
    return HWE_PthreadMutexUnLock(&win32Cond->mtxBroadcast);
}

static unsigned __stdcall HWE_Win32ThreadWorker(void *arg)
{
    HWE_Pthread *enc = (HWE_Pthread *)arg;
    enc->ret = enc->func(enc->arg);
    return 0;
}

int32_t HWE_PthreadJoin(HWE_Pthread thread)
{
    if (thread.isInit == 1) {
        DWORD pRet = WaitForSingleObject(thread.handle, INFINITE);
        if (pRet != WAIT_OBJECT_0) {
            return -1;
        }
        CloseHandle(thread.handle);
    }
    return 0;
}
#endif

#if !HWE_IANDROID_ARM
int32_t HWE_SetThreadAffinityMask(const HWE_Pthread *thread, uint32_t cpuNum, const uint32_t *cpuIdxArray)
{
    if (cpuNum == 0) {
        return 0;
    }
    if (thread->isInit) {
#if defined(_WIN32)
        DWORD_PTR threadAffinityMask;
        if (memset_s((void *)&threadAffinityMask, sizeof(DWORD_PTR), 0, sizeof(DWORD_PTR)) != 0) {
            return -1;
        }
        for (uint32_t idx = 0; idx < cpuNum; idx++) {
            threadAffinityMask |= (1 << cpuIdxArray[idx]);
        }
        int32_t ret = SetThreadAffinityMask(thread->handle, threadAffinityMask);
        return (ret == 0);
#elif defined(__GNUC__)
        cpu_set_t threadAffinityMask;
        CPU_ZERO(&threadAffinityMask);
        for (uint32_t idx = 0; idx < cpuNum; idx++) {
            CPU_SET(cpuIdxArray[idx], &threadAffinityMask);
        }
#ifdef ANDROID_PLATFORM
        return sched_setaffinity(thread->thread, sizeof(threadAffinityMask), &threadAffinityMask);
#else
        return pthread_setaffinity_np(thread->thread, sizeof(threadAffinityMask), &threadAffinityMask);
#endif
#else
        return 0;
#endif
    } else {
        return -1;
    }
}

int32_t HWE_SetThreadPriority(const HWE_Pthread *thread, int32_t schedPriority)
{
    if (thread->isInit) {
#if defined(_WIN32)
        return (SetThreadPriority(thread->handle, schedPriority) == 0);
#elif defined(__GNUC__)
        struct sched_param threadParam;
        threadParam.sched_priority = schedPriority;
        if (threadParam.sched_priority <= 0) {
            return pthread_setschedparam(thread->thread, SCHED_OTHER, &threadParam);
        } else {
            return pthread_setschedparam(thread->thread, SCHED_RR, &threadParam);
        }
#else
        return 0;
#endif
    } else {
        return -1;
    }
}
#endif
} // namespace ImagePlugin
} // namespace OHOS