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
#ifndef FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_NATIVE_IMPL_H
#define FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_NATIVE_IMPL_H
#include <stdint.h>
#include "image_source.h"
#include "image_source_native.h"

#ifdef __cplusplus
extern "C" {
#endif

struct OH_ImageSourceNative {
public:
    OH_ImageSourceNative(std::shared_ptr<OHOS::Media::ImageSource> imageSource);
    OH_ImageSourceNative(char *uri, size_t size, OHOS::Media::SourceOptions ops);
    OH_ImageSourceNative(int32_t fd, OHOS::Media::SourceOptions ops);
    OH_ImageSourceNative(uint8_t *data, size_t dataSize, OHOS::Media::SourceOptions ops);
    OH_ImageSourceNative(RawFileDescriptor rawFile, OHOS::Media::SourceOptions ops);
    ~OH_ImageSourceNative();
    std::shared_ptr<OHOS::Media::ImageSource> GetInnerImageSource();
    std::string filePath_ = "";
    int fileDescriptor_ = -1;
    void *fileBuffer_ = nullptr;
    size_t fileBufferSize_ = 0;
private:
    std::string UrlToPath(const std::string &path);
    std::shared_ptr<OHOS::Media::ImageSource> innerImageSource_;
};

#ifdef __cplusplus
};
#endif
/** @} */
#endif // FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_NATIVE_IMPL_H