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
#ifndef FRAMEWORKS_INNERKITSIMPL_TEST_FUZZTEST_COMMON_FUZZTEST_FUNCTION_H
#define FRAMEWORKS_INNERKITSIMPL_TEST_FUZZTEST_COMMON_FUZZTEST_FUNCTION_H

#include <cstdint>
#include <stddef.h>
#include <string>
namespace OHOS {
namespace Media {
    class PixelMap;
}
}

// create pixelMap by data, and encode to the file descriptor
int ConvertDataToFd(const uint8_t* data, size_t size, std::string encodeFormat = "image/jpeg");

std::string GetNowTimeStr();

bool WriteDataToFile(const uint8_t* data, size_t size, const std::string& filename);

void PixelMapTest001(OHOS::Media::PixelMap* pixelMap);

void PixelMapTest002(OHOS::Media::PixelMap* pixelMap);

void PixelYuvTest001(OHOS::Media::PixelMap* pixelMap);

void PixelYuvTest002(OHOS::Media::PixelMap* pixelMap);

#endif