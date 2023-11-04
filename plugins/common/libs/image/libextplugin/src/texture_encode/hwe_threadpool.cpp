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

#include "hwe_threadpool.h"
#include <cstdio>

namespace OHOS {
namespace ImagePlugin {
static void HWE_Free(HWE_ThreadPool *p)
{
    if (p != nullptr) {
        RecordFreeMemCount();
        free(p);
        p = nullptr;
    }
}

// worker thread function for thread pool, always run until exit condition is met
static int32_t *HWE_ThreadPoolWorkerFunc(int32_t *pool)
{
    if (!pool) {
        return nullptr;
    }

    HWE_ThreadPool *threadPool = (HWE_ThreadPool *)pool;
    if (threadPool->initFunc) {
        threadPool->initFunc(threadPool->initArg);
    }

    HWE_ThreadPoolJobQueue *jobQ = &threadPool->jobQueue;
    HWE_JobNode *jobNode = nullptr;

    HWE_PthreadMutexLock(&jobQ->lock); // mutex for race condition
    while (1) {
        while ((!jobQ->actualCount) &&
            (!threadPool->shutdown)) { // goto waiting when job queue is empty and pool is not shutdown
            HWE_PthreadCondWait(&jobQ->notEmpty, &jobQ->lock); // waiting notEmpty condition
        }

        if (threadPool->shutdown) { // thread exit when pool shut down
            HWE_PthreadMutexUnLock(&jobQ->lock);
            break;
        }

        HWE_LIST_POP_HEAD(jobQ->head, jobQ->tail, jobNode); // get job node from job queue list
        if (jobNode != nullptr) {                              // got valid job
            jobQ->actualCount--;
        } else {
            jobQ->actualCount = 0;
            HWE_PthreadCondBroadcast(&jobQ->empty); // broadcast empty condition
            continue;
        }

        if (!jobQ->actualCount) {
            HWE_PthreadCondBroadcast(&jobQ->empty); // broadcast empty condition
        }

        threadPool->busyThreadCount++;  // starting busy, busy thread count increment
        HWE_PthreadMutexUnLock(&jobQ->lock);

        (void)jobNode->func(jobNode->funcArg); // doing job
        if (jobNode) {
            free(jobNode)
            jobNode = nullptr;
        }

        HWE_PthreadMutexLock(&jobQ->lock);
        threadPool->busyThreadCount--; // job done, go to idle, busy thread count decrease

        if (!threadPool->busyThreadCount) { // if busy thread count is zero, broadcast notBusy condition
            HWE_PthreadCondBroadcast(&jobQ->notBusy);
        }
    }

    return nullptr;
}

static void HWE_DestroyThreads(HWE_ThreadPool *pool)
{
    if (!pool) {
        return;
    }

    HWE_ThreadPoolJobQueue *jobQ = &pool->jobQueue;

    HWE_PthreadMutexLock(&jobQ->lock);
    if (pool->shutdown || jobQ->shutdown) {
        HWE_PthreadMutexUnLock(&jobQ->lock);
        return;
    }

    jobQ->shutdown = 1;
    while (jobQ->actualCount) {
        HWE_PthreadCondWait(&jobQ->empty, &jobQ->lock);
    }

    pool->shutdown = 1;
    HWE_PthreadMutexUnLock(&jobQ->lock);
    HWE_PthreadCondBroadcast(&jobQ->notEmpty);

    int32_t i;
    for (i = 0; i < pool->threadCount; i++) {
        HWE_PthreadJoin(pool->pthreads[i]);
    }

    return;
}


HWE_ThreadPool *HWE_CreateThreadPool(int32_t threadCount, HWE_ThreadPoolParam *threadParam)
{
    if (threadCount <= 0) {
        return nullptr;
    }

    HWE_ThreadPool *pool = (HWE_ThreadPool *)HWE_Malloc(sizeof(HWE_ThreadPool));
    if (!pool) {
        return nullptr;
    }

    HWE_ThreadPoolJobQueue *jobQ = &pool->jobQueue;
    jobQ->actualCount = jobQ->shutdown = 0;
    jobQ->head = jobQ->tail = nullptr;

    pool->threadCount = pool->busyThreadCount = pool->shutdown = 0;
    pool->pthreads = (HWE_Pthread *)HWE_Malloc(sizeof(HWE_Pthread) * threadCount);
    if (!pool->pthreads) {
        HWE_Free(pool);
        return nullptr;
    }

    pool->initArg = nullptr;
    pool->initFunc = nullptr;
    if (threadParam) {
        pool->initArg = threadParam->initArg;
        pool->initFunc = threadParam->initFunc;
    }

    HWE_PthreadMutexInit(&jobQ->lock);
    HWE_PthreadCondInit(&jobQ->notEmpty);
    HWE_PthreadCondInit(&jobQ->empty);
    HWE_PthreadCondInit(&jobQ->notBusy);

    for (int32_t i = 0; i < threadCount; i++) {
        int32_t ret = HWE_PthreadCreate(&(pool->pthreads[i]), HWE_ThreadPoolWorkerFunc, (void *)pool);
        if (ret) {
            HWE_DestroyThreadPool(pool);
            return nullptr;
        } else {
            pool->threadCount++;
        }
#if !HWE_IANDROID_ARM
        if (threadParam) {
            HWE_SetThreadAffinityMask(&(pool->pthreads[i]), threadParam->cpuNum, threadParam->cpuIdxArray);
            HWE_SetThreadPriority(&(pool->pthreads[i]), threadParam->schedPriority);
        }
#endif
    }

    return pool;
}


void HWE_ThreadPoolPushJob(HWE_ThreadPool *pool, HWE_ThreadFunc func, int32_t *funcArg)
{
    if ((!pool) || (!func)) {
        return;
    }

    HWE_ThreadPoolJobQueue *jobQ = &pool->jobQueue;

    HWE_PthreadMutexLock(&jobQ->lock);
    if (pool->shutdown || jobQ->shutdown) {
        HWE_PthreadMutexUnLock(&jobQ->lock);
        return;
    }

    HWE_JobNode *jobNode = (HWE_JobNode *)HWE_Malloc(sizeof(HWE_JobNode));
    if (!jobNode) {
        HWE_PthreadMutexUnLock(&jobQ->lock);
        return;
    }

    jobNode->func = func;
    jobNode->funcArg = funcArg;
    jobNode->next = nullptr;
    HWE_LIST_PUSH_TAIL(jobQ->head, jobQ->tail, jobNode);
    HWE_PthreadCondBroadcast(&jobQ->notEmpty);
    jobQ->actualCount++;
    HWE_PthreadMutexUnLock(&jobQ->lock);
    return;
}


void HWE_ThreadPoolWaitAllJobDone(HWE_ThreadPool *pool)
{
    if (!pool) {
        return;
    }

    HWE_ThreadPoolJobQueue *jobQ = &pool->jobQueue;

    HWE_PthreadMutexLock(&jobQ->lock);
    while (jobQ->actualCount) {
        HWE_PthreadCondWait(&jobQ->empty, &jobQ->lock);
    }

    while (pool->busyThreadCount) {
        HWE_PthreadCondWait(&jobQ->notBusy, &jobQ->lock);
    }
    
    HWE_PthreadMutexUnLock(&jobQ->lock);
    return;
}


void HWE_DestroyThreadPool(HWE_ThreadPool *pool)
{
    if (!pool) {
        return;
    }

    HWE_ThreadPoolJobQueue *jobQ = &pool->jobQueue;

    HWE_DestroyThreads(pool);
    HWE_PthreadCondDestroy(&jobQ->notEmpty);
    HWE_PthreadCondDestroy(&jobQ->empty);
    HWE_PthreadCondDestroy(&jobQ->notBusy);
    HWE_PthreadMutexDestroy(&jobQ->lock);
    HWE_Free(pool);
    return;
}
} // namespace ImagePlugin
} // namespace OHOS
