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

#include <chrono>
#include <ctime>
#include <memory>
#include <thread>
#include <vector>

#include "pixel_map_program_manager_utils.h"

#undef LOG_TAG
#define LOG_TAG "PixelMapProgramManager"

namespace OHOS {
namespace Media {
using PixelMapProgramManagerUtils::MAX_GL_INSTANCE_NUM;
static std::vector<std::unique_ptr<PixelMapGLPostProcProgram>> g_availInstances;
static std::mutex g_contextMutex;
static int g_nowInstanceNum = 0;
static bool g_destroyThreadIsRunning = false;
static long g_lastTouchInstanceTime = 0;
static std::condition_variable g_dataCond;

static long GetMonotonicTimeSec()
{
    struct timespec tv {};
    clock_gettime(CLOCK_MONOTONIC, &tv);
    return tv.tv_sec;
}

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
    bool needCreateProgram = false;
    std::unique_lock<std::mutex> locker(g_contextMutex);
    g_lastTouchInstanceTime = GetMonotonicTimeSec();
    program = TakeAvailableProgramLocked();
    if (program != nullptr) {
        return program;
    }
    if (PixelMapProgramManagerUtils::ShouldWaitForAvailableProgram(
        g_nowInstanceNum, MAX_GL_INSTANCE_NUM, g_availInstances.size())) {
        const int num = g_nowInstanceNum;
        while (program == nullptr &&
            PixelMapProgramManagerUtils::ShouldWaitForAvailableProgram(
                g_nowInstanceNum, MAX_GL_INSTANCE_NUM, g_availInstances.size())) {
            if (g_dataCond.wait_for(locker, std::chrono::seconds(1)) == std::cv_status::timeout) {
                IMAGE_LOGE("slr_gpu %{public}s GetInstance failed for wait timeout(%{public}d)", __func__, num);
                return nullptr;
            }
            program = TakeAvailableProgramLocked();
        }
        if (program != nullptr) {
            return program;
        }
    }
    if (PixelMapProgramManagerUtils::CanCreateProgram(g_nowInstanceNum, MAX_GL_INSTANCE_NUM)) {
        g_nowInstanceNum++;
        needCreateProgram = true;
    }
    locker.unlock();

    if (needCreateProgram) {
        std::unique_ptr<PixelMapGLPostProcProgram> newProgram(new (std::nothrow) PixelMapGLPostProcProgram());
        if (newProgram == nullptr || !newProgram->Init()) {
            std::unique_lock<std::mutex> retryLocker(g_contextMutex);
            g_nowInstanceNum--;
            g_dataCond.notify_one();
            return nullptr;
        } else {
            const int num = g_nowInstanceNum;
            IMAGE_LOGI("slr_gpu %{public}s new instance(%{public}d)", __func__, num);
            program = newProgram.release();
        }
    }
    return program;
}

void PixelMapProgramManager::ReleaseInstance(PixelMapGLPostProcProgram *program)
{
    if (program == nullptr) {
        return;
    }
    bool needStartDestroyThread = false;
    {
        std::unique_lock<std::mutex> locker(g_contextMutex);
        g_availInstances.emplace_back(program);
        g_lastTouchInstanceTime = GetMonotonicTimeSec();
        if (!g_destroyThreadIsRunning) {
            g_destroyThreadIsRunning = true;
            needStartDestroyThread = true;
        }
    }
    g_dataCond.notify_one();
    if (needStartDestroyThread) {
        std::thread destroyInstanceThread(PixelMapProgramManager::DestoryInstanceThreadFunc);
        destroyInstanceThread.detach();
    }
}

void PixelMapProgramManager::DestoryInstanceThreadFunc()
{
    while (true) {
        long sleepSeconds = 0;
        {
            std::unique_lock<std::mutex> locker(g_contextMutex);
            if (PixelMapProgramManagerUtils::ShouldStopDestroyThread(g_nowInstanceNum, g_availInstances.size())) {
                g_destroyThreadIsRunning = false;
                return;
            }
            sleepSeconds = PixelMapProgramManagerUtils::ComputeDestroySleepSeconds(
                GetMonotonicTimeSec(), g_lastTouchInstanceTime, g_nowInstanceNum, MAX_GL_INSTANCE_NUM);
        }
        if (sleepSeconds > 0) {
            std::this_thread::sleep_for(std::chrono::seconds(sleepSeconds));
            continue;
        }
        DestroyOneInstance();
    }
}

void PixelMapProgramManager::DestroyOneInstance()
{
    std::unique_ptr<PixelMapGLPostProcProgram> instance;
    int num = 0;
    {
        std::unique_lock<std::mutex> locker(g_contextMutex);
        if (g_availInstances.empty()) {
            return;
        }
        instance = std::move(g_availInstances.back());
        g_availInstances.pop_back();
        g_nowInstanceNum--;
        num = g_nowInstanceNum;
    }
    g_dataCond.notify_one();
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
        g_dataCond.notify_one();
        delete program;
        program = nullptr;
        return false;
    }
    ReleaseInstance(program);
    return ret;
}

PixelMapGLPostProcProgram *PixelMapProgramManager::TakeAvailableProgramLocked()
{
    if (g_availInstances.empty()) {
        return nullptr;
    }
    PixelMapGLPostProcProgram *program = g_availInstances.back().release();
    g_availInstances.pop_back();
    return program;
}
} // namespace Media
} // namespace OHOS
