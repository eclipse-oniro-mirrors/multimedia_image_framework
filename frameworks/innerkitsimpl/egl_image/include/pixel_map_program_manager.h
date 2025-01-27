/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_PROGRAM_MANAGER_H
#define FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_PROGRAM_MANAGER_H
#include <cstdint>
#include <mutex>
#include "pixel_map_gl_post_proc_program.h"

namespace OHOS {
namespace Media {
class PixelMapProgramManager {
public:
    static PixelMapProgramManager &GetInstance() noexcept;
    static bool BuildShader();
    PixelMapGLPostProcProgram* GetProgram();
    static bool ExecutProgram(PixelMapGLPostProcProgram *program);

private:
    PixelMapProgramManager() noexcept;
    ~PixelMapProgramManager() noexcept;
    PixelMapProgramManager(const PixelMapProgramManager &) = delete;
    void operator=(const PixelMapProgramManager &) = delete;
    PixelMapProgramManager(const PixelMapProgramManager &&) = delete;
    void operator=(const PixelMapProgramManager &&) = delete;
    static void ReleaseInstance(PixelMapGLPostProcProgram *program);
    static void DestoryInstanceThreadFunc();
    static void DestroyOneInstance();
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_PROGRAM_MANAGER_H
