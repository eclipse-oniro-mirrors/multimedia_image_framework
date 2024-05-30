/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "image_convert_tools.h"

#include <chrono>
#include <dlfcn.h>
#include <string>

#include "image_log.h"
#include "log_tags.h"

namespace OHOS {
namespace Media {
namespace {
#if (defined(__aarch64__) || defined(__x86_64__))
const std::string YUV_LIB_PATH = "libyuv.z.so";
#else
const std::string YUV_LIB_PATH = "/system/lib/chipset-pub-sdk/libyuv.z.so";
#endif
const std::string GET_IMAGE_CONVERTER_FUNC = "GetImageConverter";
}

#ifdef EXT_PIXEL
using GetImageConverterFunc = OHOS::OpenSourceLibyuv::ImageConverter (*)();
#endif

#ifdef EXT_PIXEL
ConverterHandle& ConverterHandle::GetInstance()
{
    static ConverterHandle instance;
    return instance;
}

void ConverterHandle::InitConverter()
{
    dlHandler_ = dlopen(YUV_LIB_PATH.c_str(), RTLD_LAZY | RTLD_NODELETE);
    if (dlHandler_ == nullptr) {
        IMAGE_LOGD("Dlopen failed.");
        return;
    }
    GetImageConverterFunc getConverter = (GetImageConverterFunc)dlsym(dlHandler_, GET_IMAGE_CONVERTER_FUNC.c_str());
    if (getConverter == nullptr) {
        IMAGE_LOGD("Function of converter is null.");
        dlclose(dlHandler_);
        dlHandler_ = nullptr;
        return;
    }
    converter_ = getConverter();
    isInited_.store(true);
    IMAGE_LOGD("Initialize image converter success.");
}

void ConverterHandle::DeInitConverter()
{
    if (dlHandler_) {
        dlclose(dlHandler_);
        dlHandler_ = nullptr;
    }
    isInited_.store(false);
}

const OHOS::OpenSourceLibyuv::ImageConverter &ConverterHandle::GetHandle()
{
    if (!isInited_.load()) {
        InitConverter();
    }
    return converter_;
}
#endif
} // namespace Media
} // namespace OHOS
