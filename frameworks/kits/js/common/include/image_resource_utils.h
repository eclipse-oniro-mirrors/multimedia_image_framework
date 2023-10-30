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

#ifndef FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_TYPE_UTILS_H_
#define FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_TYPE_UTILS_H_
#include <string>

namespace OHOS {
namespace Media {
enum class ImageResourceType : int32_t {
    IMAGE_RESOURCE_INVAILD = 0,
    IMAGE_RESOURCE_FD = 1,
    IMAGE_RESOURCE_PATH = 2,
    IMAGE_RESOURCE_BUFFER = 3,
    IMAGE_RESOURCE_RAW_FILE = 4
};

struct ImageResource {
    ImageResourceType type = ImageResourceType::IMAGE_RESOURCE_INVAILD;
    int32_t fd = -1;
    std::string path;
    uint8_t* buffer = nullptr;
    size_t bufferSize = 0;
    long fileStart = 0;
    long fileLength = 0;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_TYPE_UTILS_H_