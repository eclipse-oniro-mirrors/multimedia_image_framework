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


#ifndef FRAMEWORKS_INNERKITSIMPL_TEST_UNITTEST_IMAGE_SOURCE_UTIL_H
#define FRAMEWORKS_INNERKITSIMPL_TEST_UNITTEST_IMAGE_SOURCE_UTIL_H
#include <fstream>
#include "image_source.h"
#include "pixel_map.h"

namespace OHOS {
namespace ImageSourceUtil {
int64_t PackImage(const std::string &filePath, std::unique_ptr<OHOS::Media::PixelMap> pixelMap);
int64_t PackImage(std::unique_ptr<OHOS::Media::ImageSource> imageSource);
bool ReadFileToBuffer(const std::string &filePath, uint8_t *buffer, size_t bufferSize);
}
}
#endif // FRAMEWORKS_INNERKITSIMPL_TEST_UNITTEST_IMAGE_SOURCE_UTIL_H
