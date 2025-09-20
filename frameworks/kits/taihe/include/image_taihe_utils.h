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

#ifndef FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_TAIHE_UTILS_H
#define FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_TAIHE_UTILS_H

#include "image_source.h"
#include "image_type.h"
#include "message_parcel.h"
#include "ohos.multimedia.image.image.proj.hpp"
#include "ohos.multimedia.image.image.impl.hpp"
#include "taihe/runtime.hpp"

namespace ANI::Image {
using namespace taihe;
using namespace ohos::multimedia::image::image;

class ImageTaiheUtils {
public:
    static void HicheckerReport();
    static void ThrowExceptionError(const std::string &errMsg);
    static void ThrowExceptionError(const int32_t errCode, const std::string &errMsg);
    struct ImagePropertyOptions {
        uint32_t index = 0;
        std::string defaultValueStr;
    };

    static bool GetPropertyInt(ani_env *env, ani_object obj, const std::string &name, int32_t &value);
    static bool GetPropertyLong(ani_env *env, ani_object obj, const std::string &name, int64_t &value);
    static bool GetPropertyDouble(ani_env *env, ani_object obj, const std::string &name, double &value);
    static ani_object ToBusinessError(ani_env *env, int32_t code, const std::string &message);

    static OHOS::Media::SourceOptions ParseSourceOptions(SourceOptions const& options);
    static ImageInfo ToTaiheImageInfo(const OHOS::Media::ImageInfo &src, bool isHdr);
    static array<string> ToTaiheArrayString(const std::vector<std::string> &src);
    static array<uint8_t> CreateTaiheArrayBuffer(uint8_t* src, size_t srcLen);
    static uintptr_t GetUndefinedPtr(ani_env *env);

    static OHOS::MessageParcel* UnwrapMessageParcel(uintptr_t sequence);

    template <typename EnumType, typename ValueType>
    static bool GetEnumKeyByValue(ValueType value, typename EnumType::key_t &key);

    template <typename T>
    static bool IsValidPtr(T data);
};
} // namespace ANI::Image

#endif // FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_TAIHE_UTILS_H