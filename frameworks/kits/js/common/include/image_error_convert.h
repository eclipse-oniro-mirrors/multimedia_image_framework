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

#ifndef FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_ERROR_CONVERT_H
#define FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_ERROR_CONVERT_H

#include <string>

namespace OHOS {
namespace Media {
class ImageErrorConvert {
public:
    static std::pair<int32_t, std::string> CreatePictureAtIndexMakeErrMsg(uint32_t errorCode);
    static std::pair<int32_t, std::string> ModifyImagePropertiesEnhancedMakeErrMsg(uint32_t errorCode,
        std::string &exMessage);
    static std::pair<int32_t, std::string> ModifyImagePropertyArrayMakeErrMsg(uint32_t errorCode,
        std::string exMessage);
    static std::pair<int32_t, std::string> CreateThumbnailMakeErrMsg(uint32_t errorCode);
    static std::pair<int32_t, std::string> ReadXMPMetadataMakeErrMsg(uint32_t errorCode);
    static std::pair<int32_t, std::string> WriteXMPMetadataMakeErrMsg(uint32_t errorCode);
    static std::pair<int32_t, std::string> XMPMetadataMakeErrMsg(uint32_t errorCode);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_ERROR_CONVERT_H
