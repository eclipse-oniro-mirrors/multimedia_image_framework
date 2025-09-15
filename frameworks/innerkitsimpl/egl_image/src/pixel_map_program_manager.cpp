/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "pixel_map_program_manager.h"

#include <memory>

#undef LOG_TAG
#define LOG_TAG "PixelMapProgramManager"

namespace OHOS {
namespace Media {
static const int MAX_GL_INSTANCE_NUM = 8;
constexpr int32_t MAX_CONTEXT_EXPIRED_TIME_SEC = 120;
constexpr int32_t MIN_CONTEXT_EXPIRED_TIME_SEC = 10;
static vector<PixelMapGLPostProcProgram *> g_availInstances;
static std::mutex g_contextMutex;
static std::mutex g_shaderBuildMutex;
static std::atomic<int> g_nowInstanceNum = 0;
static std::atomic<bool> g_destroyThreadIsRunning = false;
static std::atomic<long> g_lastTouchInstanceTime = 0;
static std::condition_variable g_dataCond;

PixelMapProgramManager::PixelMapProgramManager() noexcept
{
}

PixelMapProgramManager::~PixelMapProgramManager() noexcept
{
}

PixelMapProgramManager &PixelMapProgramManager::GetInstance() noexcept
{
    static PixelMapProgramManager instance;
    return instance;
}

PixelMapGLPostProcProgram* PixelMapProgramManager::GetProgram()
{
    ImageTrace imageTrace("PixelMapProgramManager::GetProgram");
    PixelMapGLPostProcProgram *program = nullptr;
    std::unique_lock<std::mutex> locker(g_contextMutex);
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    g_lastTouchInstanceTime = tv.tv_sec;
    if (g_availInstances.size() > 0) {
        program = g_availInstances.back();
        g_availInstances.pop_back();
    }
    if (program != nullptr) {
        return program;
    }
    if (g_nowInstanceNum >= MAX_GL_INSTANCE_NUM) {
        int num = g_nowInstanceNum;
        while (program == nullptr) {
            if (g_dataCond.wait_for(locker, std::chrono::seconds(1)) == std::cv_status::timeout) {
                IMAGE_LOGE("slr_gpu %{public}s GetInstance failed for wait timeout(%{public}d)", __func__, num);
                return nullptr;
            }
            if (g_availInstances.size() > 0) {
                program = g_availInstances.back();
                g_availInstances.pop_back();
            }
        }
    } else {
        g_nowInstanceNum++;
        locker.unlock();
        program = new PixelMapGLPostProcProgram();
        if (!program->Init()) {
            std::unique_lock<std::mutex> locker(g_contextMutex);
            g_nowInstanceNum--;
            delete program;
            program = nullptr;
        } else {
            int num = g_nowInstanceNum;
            IMAGE_LOGI("slr_gpu %{public}s new instance(%{public}d)", __func__, num);
        }
    }
    return program;
}

void PixelMapProgramManager::ReleaseInstance(PixelMapGLPostProcProgram *program)
{
    {
        std::unique_lock<std::mutex> locker(g_contextMutex);
        g_availInstances.push_back(program);
    }
    g_dataCond.notify_one();
    bool oldValue = false;
    if (g_destroyThreadIsRunning.compare_exchange_weak(oldValue, true, std::memory_order_relaxed)) {
        std::thread destroyInstanceThread(PixelMapProgramManager::DestoryInstanceThreadFunc);
        destroyInstanceThread.detach();
    }
}

void PixelMapProgramManager::DestoryInstanceThreadFunc()
{
    while (g_nowInstanceNum != 0) {
        struct timespec tv;
        clock_gettime(CLOCK_MONOTONIC, &tv);
        long expiredTime = tv.tv_sec - g_lastTouchInstanceTime;
        if (expiredTime < 0) {
            expiredTime = 0;
        }

        if (g_nowInstanceNum > 1) {
            if (expiredTime < MIN_CONTEXT_EXPIRED_TIME_SEC * (MAX_GL_INSTANCE_NUM + 1 - g_nowInstanceNum)) {
                sleep(MIN_CONTEXT_EXPIRED_TIME_SEC);
                continue;
            }
        } else {
            if (expiredTime < MAX_CONTEXT_EXPIRED_TIME_SEC) {
                sleep(MAX_CONTEXT_EXPIRED_TIME_SEC);
                continue;
            }
        }
        DestroyOneInstance();
    }
    g_destroyThreadIsRunning = false;
}

void PixelMapProgramManager::DestroyOneInstance()
{
    std::unique_lock<std::mutex> locker(g_contextMutex);
    PixelMapGLPostProcProgram *instance = nullptr;
    if (g_availInstances.size() > 0) {
        instance = g_availInstances.back();
        g_availInstances.pop_back();
        g_nowInstanceNum--;
        if (instance != nullptr) delete instance;
    }
    int num = g_nowInstanceNum;
    IMAGE_LOGE("slr_gpu %{public}s destroy opengl context(%{public}d)", __func__, num);
}

bool PixelMapProgramManager::BuildShader()
{
    return PixelMapGLPostProcProgram::BuildShader();
}

bool PixelMapProgramManager::ExecutProgram(PixelMapGLPostProcProgram *program)
{
    if (program == nullptr) {
        IMAGE_LOGE("slr_gpu ExecutProgram program is nullptr");
        return false;
    }
    bool ret = program->Execute();
    if (!ret) {
        IMAGE_LOGE("slr_gpu ExecutProgram failed");
        {
            std::unique_lock<std::mutex> locker(g_contextMutex);
            g_nowInstanceNum--;
        }
        delete program;
        program = nullptr;
        return false;
    }
    ReleaseInstance(program);
    return ret;
}
} // namespace Media
} // namespace OHOS