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

#include <cstdio.h>
#include "hwe_osdep.h"
#include "hwe_source_record.h"

namespace OHOS {
namespace ImagePlugin {
static HWE_PthreadMutex g_mutex;

static int32_t g_mallocMemCount = 0;
static int32_t g_freeMemCount = 0;

static int32_t g_initMutexCount = 0;
static int32_t g_destoryMutexCount = 0;

static int32_t g_initCondCount = 0;
static int32_t g_destoryCondCount = 0;

static int32_t g_initThreadCount = 0;
static int32_t g_destoryThreadCount = 0;

void RecordMallocMemCount()
{
    HWE_PthreadMutexLock(&g_mutex);
    g_mallocMemCount++;
    HWE_PthreadMutexUnLock(&g_mutex);
}

void RecordFreeMemCount()
{
    HWE_PthreadMutexLock(&g_mutex);
    g_freeMemCount++;
    HWE_PthreadMutexUnLock(&g_mutex);
}

void RecordInitMutexCount()
{
    HWE_PthreadMutexLock(&g_mutex);
    g_initMutexCount++;
    HWE_PthreadMutexUnLock(&g_mutex);
}

void RecordDestoryMutexCount()
{
    HWE_PthreadMutexLock(&g_mutex);
    g_destoryMutexCount++;
    HWE_PthreadMutexUnLock(&g_mutex);
}

void RecordInitCondCount()
{
    HWE_PthreadMutexLock(&g_mutex);
    g_initCondCount++;
    HWE_PthreadMutexUnLock(&g_mutex);
}

void RecordDestoryCondCount()
{
    HWE_PthreadMutexLock(&g_mutex);
    g_destoryCondCount++;
    HWE_PthreadMutexUnLock(&g_mutex);
}

void RecordInitThreadCount()
{
    HWE_PthreadMutexLock(&g_mutex);
    g_initThreadCount++;
    HWE_PthreadMutexUnLock(&g_mutex);
}

void RecordDestoryThreadCount()
{
    HWE_PthreadMutexLock(&g_mutex);
    g_destoryThreadCount++;
    HWE_PthreadMutexUnLock(&g_mutex);
}

void InitResourceInfo()
{
    HWE_PthreadMutexInit(&g_mutex);
}

void DestroyResourceInfo()
{
    HWE_PthreadMutexDestroy(&g_mutex);
    HWE_LOGI("Memroy Info: malloc %d free %d", g_mallocMemCount, g_freeMemCount);
    HWE_LOGI("Mutex Info: init %d destroy %d", g_initMutexCount, g_destoryMutexCount);
    HWE_LOGI("Cond Info: init %d destroy %d", g_initCondCount, g_destoryCondCount);
    HWE_LOGI("Thread Info: init %d destroy %d", g_initThreadCount, g_destoryThreadCount);
}
} // namespace ImagePlugin
} // namespace OHOS