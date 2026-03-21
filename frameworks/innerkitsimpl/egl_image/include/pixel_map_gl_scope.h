/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_SCOPE_H
#define FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_SCOPE_H

#include <utility>

namespace OHOS {
namespace Media {
namespace PixelMapGlScope {
template<typename F>
class ScopeExit {
public:
    explicit ScopeExit(F &&func) : func_(std::forward<F>(func)) {}

    ScopeExit(ScopeExit &&other) noexcept : func_(std::move(other.func_)), active_(other.active_)
    {
        other.active_ = false;
    }

    ScopeExit(const ScopeExit &) = delete;
    ScopeExit &operator=(const ScopeExit &) = delete;
    ScopeExit &operator=(ScopeExit &&) = delete;

    ~ScopeExit()
    {
        if (active_) {
            func_();
        }
    }

    void Release()
    {
        active_ = false;
    }

private:
    F func_;
    bool active_ = true;
};

template<typename F>
ScopeExit<F> MakeScopeExit(F &&func)
{
    return ScopeExit<F>(std::forward<F>(func));
}
} // namespace PixelMapGlScope
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_SCOPE_H
