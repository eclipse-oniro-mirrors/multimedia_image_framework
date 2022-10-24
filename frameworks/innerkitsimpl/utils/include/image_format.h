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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_FORMAT_H_
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_FORMAT_H_

namespace OHOS {
namespace Media {
enum class ImageFormat : int32_t {
    UNKNOWN = 0,
    NV21 = 1,
    YUV420_888 = 2,
    RAW10 = 4,
    RAW16 = 5,
    H264 = 6,
    H265 = 7,
    YCBCR_422_SP = 1000,
    JPEG = 2000
};

enum class ComponentType {
    UNKNOWN = 0,
    YUV_Y = 1,
    YUV_U = 2,
    YUV_V = 3,
    JPEG = 4,
    RAW10 = 5,
    RAW16 = 6,
    H264 = 7,
    H265 = 8
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_FORMAT_H_
