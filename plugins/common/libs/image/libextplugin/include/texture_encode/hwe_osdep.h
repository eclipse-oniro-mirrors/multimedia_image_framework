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

#ifndef HWE_OSDEP_H
#define HWE_OSDEP_H

#include <stdlib.h>
#include <limits.h>
#include "hwe_type.h"
#if defined(_WIN32)
#include <process.h>
#include <windows.h>
#include <time.h>
#else
#include <sched.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/prctl.h>
#endif
#include "hwe_source_record.h"

#define HWE_FILE __FILE__
#define HWE_LINE __LINE__

// kernel type enumeration
#if HWE_ARM_AARCH64
typedef enum HWE_Kernel {
    KERNEL_TYPE_C = 0,
    KERNEL_TYPE_NEON,
    KERNEL_TYPE_TOTAL // total type number of kernel
} HWE_KernelType;
#elif HWE_ARM_AARCH32
typedef enum HWE_Kernel {
    KERNEL_TYPE_C = 0,
    KERNEL_TYPE_NEON,
    KERNEL_TYPE_TOTAL // total type number of kernel
} HWE_KernelType;
#elif HWE_X86_64
typedef enum HWE_Kernel {
    KERNEL_TYPE_C = 0,
    KERNEL_TYPE_ASM,
    KERNEL_TYPE_TOTAL,
    KERNEL_TYPE_SSE2,
    KERNEL_TYPE_SSE4,
    KERNEL_TYPE_AVX,
    KERNEL_TYPE_AVX2
} HWE_KernelType;
#elif HWE_X86_32
typedef enum HWE_Kernel {
    KERNEL_TYPE_C = 0,
    KERNEL_TYPE_INTRINSICS,
    KERNEL_TYPE_TOTAL  // total type number of kernel
} HWE_KernelType;
#else
typedef enum HWE_Kernel {
    KERNEL_TYPE_C = 0,
    KERNEL_TYPE_ASM,
    KERNEL_TYPE_TOTAL  // total type number of kernel
} HWE_KernelType;
#endif

HWE_KernelType HWE_DetectSimdCapibility(void);

#ifdef __ICL
#define inline __inline
#endif

#if defined(__GNUC__) && (__GNUC__ > 3 || __GNUC__ == 3 && __GNUC_MINOR__ > 0)
#define HWE_INLINE __attribute__((always_inline)) inline
#else
#ifdef __ICL
#define HWE_INLINE __forceinline
#else
#define HWE_INLINE __inline
#endif
#endif


#if defined(_WIN32)
#define HWE_SPIN_COUNT 0
#define HWE_PTHREAD_MUTEX_INITIALIZER \
    {                                 \
        0                             \
    }

typedef CRITICAL_SECTION HWE_PthreadMutex;
typedef struct HWE_PthreadCond {
    void *ptr;
} HWE_PthreadCond;
typedef struct HWE_Pthread {
    void *handle;
    void *(*func)(void *arg);
    void *arg;
    void *ret;
    signed char isInit;
} HWE_Pthread;
typedef struct HWE_Win32ThreadControl {
    HWE_PthreadMutex staticMutex;
    void(WINAPI *condBroadcast)(HWE_PthreadCond *cond);
    void(WINAPI *condInit)(HWE_PthreadCond *cond);
    void(WINAPI *condSignal)(HWE_PthreadCond *cond);
    BOOL(WINAPI *condWait)(HWE_PthreadCond *cond, HWE_PthreadMutex *mutex, DWORD milliseconds);
} HWE_Win32ThreadControl;
typedef struct HWE_Win32Cond {
    HWE_PthreadMutex mtxBroadcast;
    HWE_PthreadMutex mtxWaiterCount;
    volatile int32_t waiterCount;
    HANDLE semaphore;
    HANDLE waitersDone;
    volatile int32_t isBroadcast;
} HWE_Win32Cond;

int32_t HWE_PthreadMutexInit(HWE_PthreadMutex *mutex);
int32_t HWE_PthreadMutexLock(HWE_PthreadMutex *mutex);
int32_t HWE_PthreadMutexUnLock(HWE_PthreadMutex *mutex);
int32_t HWE_PthreadMutexDestroy(HWE_PthreadMutex *mutex);
int32_t HWE_PthreadCondInit(HWE_PthreadCond *cond);
int32_t HWE_PthreadCondDestroy(HWE_PthreadCond *cond);
int32_t HWE_PthreadCondWait(HWE_PthreadCond *cond, HWE_PthreadMutex *mutex);
int32_t HWE_PthreadCondSignal(HWE_PthreadCond *cond);
int32_t HWE_PthreadCondBroadcast(HWE_PthreadCond *cond);
int32_t HWE_PthreadJoin(HWE_Pthread thread);
#else
typedef struct HWE_PthreadMutexType {
    signed char isInit;
    pthread_mutex_t mutex;
} HWE_PthreadMutex;

typedef struct HWE_PthreadCondType {
    signed char isInit;
    pthread_cond_t cond;
} HWE_PthreadCond;

typedef struct HWE_PthreadType {
    signed char isInit;
    pthread_t thread;
} HWE_Pthread;

// detect cpu simd capibility

static HWE_INLINE int32_t HWE_PthreadMutexInit(HWE_PthreadMutex *mutex)
{
    int32_t ret = pthread_mutex_init(&mutex->mutex, nullptr);
    mutex->isInit = (ret == 0) ? TRUE : FALSE;
    if (mutex->isInit) {
        RecordInitMutexCount();
    }
    return ret;
}

static HWE_INLINE int32_t HWE_PthreadMutexLock(HWE_PthreadMutex *mutex)
{
    return mutex->isInit ? pthread_mutex_lock(&mutex->mutex) : -1;
}

static HWE_INLINE int32_t HWE_PthreadMutexUnLock(HWE_PthreadMutex *mutex)
{
    return mutex->isInit ? pthread_mutex_unlock(&mutex->mutex) : -1;
}

static HWE_INLINE int32_t HWE_PthreadMutexDestroy(HWE_PthreadMutex *mutex)
{
    if (mutex->isInit) {
        mutex->isInit = 0;
        RecordDestoryMutexCount();
        return pthread_mutex_destroy(&mutex->mutex);
    } else {
        return -1;
    }
}

static HWE_INLINE int32_t HWE_PthreadCondInit(HWE_PthreadCond *cond)
{
    int32_t ret = pthread_cond_init(&cond->cond, nullptr);
    cond->isInit = (ret == 0) ? TRUE : FALSE;
    if (cond->isInit) {
        RecordInitCondCount();
    }
    return ret;
}

static HWE_INLINE int32_t HWE_PthreadCondDestroy(HWE_PthreadCond *cond)
{
    if (cond->isInit) {
        cond->isInit = 0;
        RecordDestoryCondCount();
        return pthread_cond_destroy(&cond->cond);
    } else {
        return -1;
    }
}

static HWE_INLINE int32_t HWE_PthreadCondWait(HWE_PthreadCond *cond, HWE_PthreadMutex *mutex)
{
    return (cond->isInit && mutex->isInit) ? pthread_cond_wait(&cond->cond, &mutex->mutex) : -1;
}

static HWE_INLINE int32_t HWE_PthreadCondSignal(HWE_PthreadCond *cond)
{
    return cond->isInit ? pthread_cond_signal(&cond->cond) : -1;
}

static HWE_INLINE int32_t HWE_PthreadCondBroadcast(HWE_PthreadCond *cond)
{
    return cond->isInit ? pthread_cond_broadcast(&cond->cond) : -1;
}

static HWE_INLINE int32_t HWE_PthreadJoin(HWE_Pthread thread)
{
    if (thread.isInit) {
        thread.isInit = 0;
        RecordDestoryThreadCount();
        return pthread_join(thread.thread, nullptr);
    } else {
        return -1;
    }
}

#endif

int32_t HWE_SetThreadAffinityMask(const HWE_Pthread *thread, uint32_t cpuNum, const uint32_t *cpuIdxArray);
int32_t HWE_SetThreadPriority(const HWE_Pthread *thread, int32_t schedPriority);

static HWE_INLINE void *HWE_Malloc(size_t size)
{
    if (size == 0 || size >= INT_MAX) {
        return nullptr;
    }

    void *p = malloc(size);

    if (p != nullptr) {
        RecordMallocMemCount();
        return p;
    } else {
        return nullptr;
    }
}

#ifdef _WIN32
static HWE_INLINE uint64_t HWE_GetCurrentTime(void)
{
    clock_t time = clock();
    return (uint64_t)time;
}
#else
#define TIME_FACTOR 1000000
static HWE_INLINE uint64_t HWE_GetCurrentTime(void)
{
    uint64_t time;
    struct timeval t;
    gettimeofday(&t, nullptr);

    time = (uint64_t)t.tv_sec * TIME_FACTOR + (uint64_t)t.tv_usec;
    return time;
}
#endif
#endif