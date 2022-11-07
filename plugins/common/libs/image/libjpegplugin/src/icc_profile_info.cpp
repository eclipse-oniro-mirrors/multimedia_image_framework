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
#include "icc_profile_info.h"
#include <algorithm>
#include <cstdio>
#include <cstddef>
#include <unistd.h>
#include "securec.h"
#include "jerror.h"

namespace OHOS {
namespace ImagePlugin {
namespace {
    using namespace OHOS::HiviewDFX;
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_IMAGE, "IccProfile" };
    static constexpr uint32_t ICC_MARKER = JPEG_APP0 + 2;
    static constexpr uint32_t ICC_MARKER_HEADER_SIZE = 14;
    static constexpr uint8_t ICC_SIGNATURE[] = {
        'I', 'C', 'C', '_', 'P', 'R', 'O', 'F', 'I', 'L', 'E', '\0',
    }; // Corresponding hexadecimal: { 0x49, 0x43, 0x43, 0x5F, 0x50, 0x52, 0x4F, 0x46, 0x49, 0x4C, 0x45, 0x00 }
}

ICCProfileInfo::ICCProfileInfo(): isSupportICCProfile_(false)
{
}

ICCProfileInfo::~ICCProfileInfo()
{
}
#ifdef IMAGE_COLORSPACE_FLAG
sk_sp<SkData> ICCProfileInfo::GetICCData(j_decompress_ptr cinfo)
{
    HiLog::Info(LABEL, "%{public}s begin", __func__);
    unsigned char *icc_profile = NULL;
    unsigned int icc_data_len = 0;
    bool isReadIccProfile = false;
    sk_sp<SkData> data;
    isReadIccProfile = jpeg_read_icc_profile(cinfo, &icc_profile, &icc_data_len);
    if (isReadIccProfile) {
        // copy ICC profile data
        data = SkData::MakeWithCopy(icc_profile, icc_data_len);
    } else {
        HiLog::Error(LABEL, "ERROR: jpeg_read_icc_profile failed!");
    }

    // clean up
    free(icc_profile);
    return data;
}

uint32_t ICCProfileInfo::ParsingICCProfile(j_decompress_ptr cinfo)
{
    HiLog::Info(LABEL, "%{public}s begin", __func__);

    // read icc data to skdata
    sk_sp<SkData> profile = GetICCData(cinfo);
    skcms_ICCProfile parsed;
    uint32_t parseResult = OHOS::Media::ERR_IMAGE_DENCODE_ICC_FAILED;
    sk_sp<SkColorSpace> skColorSpace = nullptr;
    if (profile != nullptr && skcms_Parse(profile->data(), profile->size(), &parsed)) {
        skColorSpace = SkColorSpace::Make(parsed);
        if (skColorSpace != nullptr) {
            isSupportICCProfile_ = true;
        }
    } else {
        skColorSpace = SkColorSpace::MakeRGB(SkNamedTransferFn::k2Dot2, SkNamedGamut::kAdobeRGB);
        isSupportICCProfile_ = false;
    }
    if (skColorSpace != nullptr) {
        parseResult = OHOS::Media::SUCCESS;
    } else {
        HiLog::Error(LABEL, "ERROR: ParsingICCProfile skColorSpace is Null!");
    }
    grColorSpace_ = OHOS::ColorManager::ColorSpace(skColorSpace);
    return parseResult;
}

OHOS::ColorManager::ColorSpace ICCProfileInfo::getGrColorSpace()
{
    return grColorSpace_;
}

bool ICCProfileInfo::IsSupportICCProfile()
{
    return isSupportICCProfile_;
}

uint32_t ICCProfileInfo::PackingICCProfile(j_compress_ptr cinfo, const SkImageInfo& info)
{
    HiLog::Info(LABEL, "%{public}s begin", __func__);
    uint32_t packingResult = OHOS::Media::ERR_IMAGE_ENCODE_ICC_FAILED;

    // write colorspace to SKData
    sk_sp<SkData> icc = icc_from_color_space(info);

    if (icc) {
        // get a contiguous block of profile memory with the icc signature
        sk_sp<SkData> jpegMarkerData =
                SkData::MakeUninitialized(ICC_MARKER_HEADER_SIZE + icc->size());
        uint8_t* ptrMaker = static_cast<uint8_t*>(jpegMarkerData->writable_data());
        (void)memcpy_s(ptrMaker, sizeof(*ptrMaker), ICC_SIGNATURE, sizeof(ICC_SIGNATURE));
        ptrMaker += sizeof(ICC_SIGNATURE);
        // first marker
        *ptrMaker++ = 1;
         // total markers
        *ptrMaker++ = 1;
        (void)memcpy_s(ptrMaker, sizeof(*ptrMaker), icc->data(), icc->size());
        jpeg_write_marker(cinfo, ICC_MARKER, jpegMarkerData->bytes(), jpegMarkerData->size());
        packingResult = OHOS::Media::SUCCESS;
    } else {
        HiLog::Error(LABEL, "ERROR: PackingICCProfile icc profile is Null!");
    }
    return packingResult;
}
#endif
} // namespace ImagePlugin
} // namespace OHOS
