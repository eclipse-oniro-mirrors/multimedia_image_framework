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

#include "yuv_helper.h"

#include <dlfcn.h>
#include <string>
#include "image_log.h"

namespace OHOS {
namespace ImagePlugin {

const std::string YUV_LIB_PATH = "libyuv.z.so";

YuvHelper& YuvHelper::GetInstance()
{
    static YuvHelper instance;
    return instance;
}

YuvHelper::YuvHelper()
{
    dlHandler_ = dlopen(YUV_LIB_PATH.c_str(), RTLD_LAZY | RTLD_NODELETE);
    if (dlHandler_ != nullptr) {
        I444ToI420 = (FUNC_I444ToI420)dlsym(dlHandler_, "I444ToI420");
        I444ToNV21 = (FUNC_I444ToNV21)dlsym(dlHandler_, "I444ToNV21");
        I422ToI420 = (FUNC_I422ToI420)dlsym(dlHandler_, "I422ToI420");
        I422ToNV21 = (FUNC_I422ToNV21)dlsym(dlHandler_, "I422ToNV21");
        I420ToNV21 = (FUNC_I420ToNV21)dlsym(dlHandler_, "I420ToNV21");
        I400ToI420 = (FUNC_I400ToI420)dlsym(dlHandler_, "I400ToI420");
    } else {
        IMAGE_LOGI("%{public}s LoadLibYuv failed", __func__);
    }
}

YuvHelper::~YuvHelper()
{
    if (dlHandler_ != nullptr) {
        dlclose(dlHandler_);
        dlHandler_ = nullptr;
    }
    I444ToI420 = nullptr;
    I444ToNV21 = nullptr;
    I422ToI420 = nullptr;
    I422ToNV21 = nullptr;
    I420ToNV21 = nullptr;
    I400ToI420 = nullptr;
}
}
}

