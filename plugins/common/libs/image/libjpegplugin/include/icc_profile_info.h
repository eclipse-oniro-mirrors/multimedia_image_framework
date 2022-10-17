/*
 * Copyright (C) 2021 - 2022 Huawei Device Co., Ltd.
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

#ifndef ICC_PROFILE_INFO_H
#define ICC_PROFILE_INFO_H

#include <string>
#ifdef IMAGE_COLORSPACE_FLAG
#include "color_space.h"
#endif
#include "hilog/log.h"
#include "image_plugin_type.h"
#include "include/core/SkData.h"
#include "include/core/SkColorSpace.h"
#include "include/core/SkImageInfo.h"
#include "include/third_party/skcms/skcms.h"
#include "jpeg_utils.h"
#include "jpeglib.h"
#include "log_tags.h"
#include "media_errors.h"
#include "src/images/SkImageEncoderFns.h"
namespace OHOS {
namespace ImagePlugin {
/*
 * Class responsible for storing and parsing ICC profile information from JPEG
 */
class ICCProfileInfo {
public:
    ICCProfileInfo();
    ~ICCProfileInfo();
#ifdef IMAGE_COLORSPACE_FLAG
    /**
     * @brief get icc data.
     * @param cinfo jpeg decompress pointer.
     * @return parse result data.
     */
    sk_sp<SkData> GetICCData(j_decompress_ptr cinfo);

    /**
     * @brief paser icc profile data form jpeg.
     * @param cinfo jpeg decompress pointer.
     * @return parse result data.
     */
    uint32_t ParsingICCProfile(j_decompress_ptr cinfo);

    /**
     * @brief get graphiccolorspace info.
     * @return SkColorSpace Object.
     */
    OHOS::ColorManager::ColorSpace getGrColorSpace();

    /**
     * @brief get whether ICC data exists in the current source
     * @return is support icc profile or not.
     */
    bool IsSupportICCProfile();

    /**
     * @brief packing icc profile data
     * @param cinfo jpeg decompress pointer.
     * @param SkImageInfo.
     * @return packing result data.
     */
    uint32_t PackingICCProfile(j_compress_ptr cinfo, const SkImageInfo& info);
#endif
private:
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace grColorSpace_ =
        OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
#endif
    bool isSupportICCProfile_;
};
} // namespace ImagePlugin
} // namespace OHOS
#endif // ICC_PROFILE_INFO_H
