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

/**
 * @addtogroup image
 * @{
 *
 * @brief Provides APIs for access to the image interface.
 *
 * @Syscap SystemCapability.Multimedia.Image
 * @since 10
 * @version 2.0
 */

/**
 * @file image_mdk_common.h
 *
 * @brief Declares the common enums and structs used by the image interface.
 *
 * @since 10
 * @version 2.0
 */

#ifndef INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_COMMON_H_
#define INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_COMMON_H_
namespace OHOS {
namespace Media {
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumerates the return values that may be used by the interface.
 *
 * @since 10
 * @version 2.0
 */
enum {
    /** Operation success. */
    OHOS_IMAGE_RESULT_SUCCESS = 0,
    /** Invalid parameter. */
    OHOS_IMAGE_RESULT_BAD_PARAMETER = -1,
};

/**
 * @brief Defines the image size.
 *
 * @since 10
 * @version 2.0
 */
struct OhosImageSize {
    /** Image width, in pixels. */
    int32_t width;
    /** Image height, in pixels. */
    int32_t height;
};

#ifdef __cplusplus
};
#endif
/** @} */
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_COMMON_H_