/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_CONVERTER_TOOLS_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_CONVERTER_TOOLS_H

#include <atomic>

#ifdef EXT_PIXEL
#include "image_converter.h"
#endif

namespace OHOS {
namespace Media {
#ifdef EXT_PIXEL
class ConverterHandle {
public:
    static ConverterHandle& GetInstance();
    void InitConverter();
    void DeInitConverter();
    const OHOS::OpenSourceLibyuv::ImageConverter &GetHandle();
    using DlHandle = void *;

private:
    ConverterHandle(const ConverterHandle&) = delete;
    ConverterHandle& operator= (const ConverterHandle&) = delete;
    ConverterHandle(ConverterHandle&&) = delete;
    ConverterHandle& operator= (ConverterHandle&&) = delete;
    ConverterHandle() = default;
    virtual ~ConverterHandle() = default;
    std::atomic<bool> isInited_ = false;
    DlHandle dlHandler_ = nullptr;
    OHOS::OpenSourceLibyuv::ImageConverter converter_ = {0};
};
#endif
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_CONVERTER_TOOLS_H