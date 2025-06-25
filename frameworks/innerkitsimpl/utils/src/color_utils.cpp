/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "color_utils.h"
#if !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;
#endif

namespace OHOS {
namespace Media {
enum CicpColorPrimaries {
    CICP_COLORPRIMARIES_UNKNOWN = 0,
    CICP_COLORPRIMARIES_SRGB = 1,
    CICP_COLORPRIMARIES_BT601_P = 5,
    CICP_COLORPRIMARIES_BT601_N = 6,
    CICP_COLORPRIMARIES_BT2020 = 9,
    CICP_COLORPRIMARIES_BT2100 = 9,
    CICP_COLORPRIMARIES_P3_DCI = 11,
    CICP_COLORPRIMARIES_P3_D65 = 12,
};

enum CicpTransfer {
    CICP_TRANSFER_UNKNOWN = 2,
    CICP_TRANSFER_BT709_1 = 1,
    CICP_TRANSFER_BT709_6 = 6,
    CICP_TRANSFER_BT709_14 = 14,
    CICP_TRANSFER_BT709_15 = 15,
    CICP_TRANSFER_SRGB = 13,
    CICP_TRANSFER_LINEAR = 8,
    CICP_TRANSFER_PQ = 16,
    CICP_TRANSFER_HLG = 18,
};

enum CicpFullRangeFLag {
    CICP_FULL_RANGE_UNKNOWN = 2,
    CICP_FULL_RANGE_FULL = 1,
    CICP_FULL_RANGE_LIMIT = 0,
};

enum CicpMatrix {
    CICP_MATRIX_BT709 = 1,
    CICP_MATRIX_BT601_P = 5,
    CICP_MATRIX_BT601_N = 6,
    CICP_MATRIX_P3 = 6,
    CICP_MATRIX_BT2020 = 9,
    CICP_MATRIX_BT2100_ICTCP = 14,
};

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
std::map<ColorManager::ColorSpaceName, CM_ColorSpaceInfo> ColorUtils::COLORSPACE_NAME_TO_COLORINFO_MAP = {
    { ColorManager::BT601_EBU,
        CM_ColorSpaceInfo {COLORPRIMARIES_BT601_P, TRANSFUNC_BT709, MATRIX_BT601_P, RANGE_FULL} },
    { ColorManager::BT601_SMPTE_C,
        CM_ColorSpaceInfo {COLORPRIMARIES_BT601_N, TRANSFUNC_BT709, MATRIX_BT601_N, RANGE_FULL} },
    { ColorManager::BT709, CM_ColorSpaceInfo {COLORPRIMARIES_BT709, TRANSFUNC_BT709, MATRIX_BT709, RANGE_FULL} },
    { ColorManager::BT2020_HLG, CM_ColorSpaceInfo {COLORPRIMARIES_BT2020, TRANSFUNC_HLG, MATRIX_BT2020, RANGE_FULL} },
    { ColorManager::BT2020_PQ, CM_ColorSpaceInfo {COLORPRIMARIES_BT2020, TRANSFUNC_PQ, MATRIX_BT2020, RANGE_FULL} },
    { ColorManager::BT601_EBU_LIMIT,
        CM_ColorSpaceInfo {COLORPRIMARIES_BT601_P, TRANSFUNC_BT709, MATRIX_BT601_P, RANGE_LIMITED} },
    { ColorManager::BT601_SMPTE_C_LIMIT,
        CM_ColorSpaceInfo {COLORPRIMARIES_BT601_N, TRANSFUNC_BT709, MATRIX_BT601_N, RANGE_LIMITED} },
    { ColorManager::BT709_LIMIT,
        CM_ColorSpaceInfo {COLORPRIMARIES_BT709, TRANSFUNC_BT709, MATRIX_BT709, RANGE_LIMITED} },
    { ColorManager::BT2020_HLG_LIMIT,
        CM_ColorSpaceInfo {COLORPRIMARIES_BT2020, TRANSFUNC_HLG, MATRIX_BT2020, RANGE_LIMITED} },
    { ColorManager::BT2020_PQ_LIMIT,
        CM_ColorSpaceInfo {COLORPRIMARIES_BT2020, TRANSFUNC_PQ, MATRIX_BT2020, RANGE_LIMITED} },
    { ColorManager::SRGB, CM_ColorSpaceInfo {COLORPRIMARIES_SRGB, TRANSFUNC_SRGB, MATRIX_BT601_N, RANGE_FULL} },
    { ColorManager::DISPLAY_P3,
        CM_ColorSpaceInfo {COLORPRIMARIES_P3_D65, TRANSFUNC_SRGB, MATRIX_P3, RANGE_FULL} },
    { ColorManager::P3_HLG, CM_ColorSpaceInfo {COLORPRIMARIES_P3_D65, TRANSFUNC_HLG, MATRIX_P3, RANGE_FULL} },
    { ColorManager::P3_PQ, CM_ColorSpaceInfo {COLORPRIMARIES_P3_D65, TRANSFUNC_PQ, MATRIX_P3, RANGE_FULL} },
    { ColorManager::ADOBE_RGB,
        CM_ColorSpaceInfo {COLORPRIMARIES_ADOBERGB, TRANSFUNC_ADOBERGB, MATRIX_ADOBERGB, RANGE_FULL} },
    { ColorManager::SRGB_LIMIT,
        CM_ColorSpaceInfo {COLORPRIMARIES_SRGB, TRANSFUNC_SRGB, MATRIX_BT601_N, RANGE_LIMITED} },
    { ColorManager::DISPLAY_P3_LIMIT,
        CM_ColorSpaceInfo {COLORPRIMARIES_P3_D65, TRANSFUNC_SRGB, MATRIX_P3, RANGE_LIMITED} },
    { ColorManager::P3_HLG_LIMIT,
        CM_ColorSpaceInfo {COLORPRIMARIES_P3_D65, TRANSFUNC_HLG, MATRIX_P3, RANGE_LIMITED} },
    { ColorManager::P3_PQ_LIMIT, CM_ColorSpaceInfo {COLORPRIMARIES_P3_D65, TRANSFUNC_PQ, MATRIX_P3, RANGE_LIMITED} },
    { ColorManager::ADOBE_RGB_LIMIT,
        CM_ColorSpaceInfo {COLORPRIMARIES_ADOBERGB, TRANSFUNC_ADOBERGB, MATRIX_ADOBERGB, RANGE_LIMITED} },
    { ColorManager::LINEAR_SRGB,
        CM_ColorSpaceInfo {COLORPRIMARIES_SRGB, TRANSFUNC_LINEAR, MATRIX_BT709, RANGE_LIMITED} },
    { ColorManager::LINEAR_BT709,
        CM_ColorSpaceInfo {COLORPRIMARIES_SRGB, TRANSFUNC_LINEAR, MATRIX_BT709, RANGE_LIMITED} },
    { ColorManager::LINEAR_P3,
        CM_ColorSpaceInfo {COLORPRIMARIES_P3_D65, TRANSFUNC_LINEAR, MATRIX_BT709, RANGE_LIMITED} },
    { ColorManager::LINEAR_BT2020,
        CM_ColorSpaceInfo {COLORPRIMARIES_BT2020, TRANSFUNC_LINEAR, MATRIX_BT709, RANGE_LIMITED} },
    { ColorManager::DISPLAY_SRGB,
        CM_ColorSpaceInfo {COLORPRIMARIES_SRGB, TRANSFUNC_SRGB, MATRIX_BT601_N, RANGE_FULL} },
    { ColorManager::DISPLAY_P3_SRGB,
        CM_ColorSpaceInfo {COLORPRIMARIES_P3_D65, TRANSFUNC_SRGB, MATRIX_P3, RANGE_FULL} },
    { ColorManager::DISPLAY_P3_HLG, CM_ColorSpaceInfo {COLORPRIMARIES_P3_D65, TRANSFUNC_HLG, MATRIX_P3, RANGE_FULL} },
    { ColorManager::DISPLAY_P3_PQ, CM_ColorSpaceInfo {COLORPRIMARIES_P3_D65, TRANSFUNC_PQ, MATRIX_P3, RANGE_FULL} },
    { ColorManager::DISPLAY_BT2020_SRGB,
        CM_ColorSpaceInfo {COLORPRIMARIES_BT2020, TRANSFUNC_SRGB, MATRIX_BT2020, RANGE_FULL} },
    { ColorManager::DISPLAY_BT2020_HLG,
        CM_ColorSpaceInfo {COLORPRIMARIES_BT2020, TRANSFUNC_HLG, MATRIX_BT2020, RANGE_FULL} },
    { ColorManager::DISPLAY_BT2020_PQ,
        CM_ColorSpaceInfo {COLORPRIMARIES_BT2020, TRANSFUNC_PQ, MATRIX_BT2020, RANGE_FULL} },
};
#endif

ColorManager::ColorSpaceName P3ToColorSpace(uint16_t transfer, uint8_t range)
{
    if (transfer == CICP_TRANSFER_PQ) {
        return range == CICP_FULL_RANGE_LIMIT ? ColorManager::P3_PQ_LIMIT : ColorManager::P3_PQ;
    } else if (transfer == CICP_TRANSFER_HLG) {
        return range == CICP_FULL_RANGE_LIMIT ? ColorManager::P3_HLG_LIMIT : ColorManager::P3_HLG;
    } else if (transfer == CICP_TRANSFER_SRGB) {
        return range == CICP_FULL_RANGE_LIMIT ? ColorManager::DISPLAY_P3_LIMIT : ColorManager::DISPLAY_P3;
    }
    return ColorManager::NONE;
}

ColorManager::ColorSpaceName BT2020ToColorSpace(uint16_t transfer, uint8_t range)
{
    if (transfer == CICP_TRANSFER_PQ) {
        return range == CICP_FULL_RANGE_LIMIT ? ColorManager::BT2020_PQ_LIMIT : ColorManager::BT2020_PQ;
    } else if (transfer == CICP_TRANSFER_HLG) {
        return range == CICP_FULL_RANGE_LIMIT ? ColorManager::BT2020_HLG_LIMIT : ColorManager::BT2020_HLG;
    }
    return ColorManager::NONE;
}

template <>
ColorManager::ColorSpaceName ColorUtils::CicpToColorSpace(uint8_t primaries, uint8_t transfer,
    uint8_t matrix, uint8_t range)
{
    switch (primaries) {
        case CICP_COLORPRIMARIES_SRGB:
            return range == CICP_FULL_RANGE_LIMIT ? ColorManager::SRGB_LIMIT : ColorManager::SRGB;
        case CICP_COLORPRIMARIES_P3_D65:
            return P3ToColorSpace(transfer, range);
        case CICP_COLORPRIMARIES_BT2020:
            return BT2020ToColorSpace(transfer, range);
        case CICP_COLORPRIMARIES_BT601_N:
            return range == CICP_FULL_RANGE_LIMIT ? ColorManager::BT601_SMPTE_C_LIMIT : ColorManager::BT601_SMPTE_C;
        case CICP_COLORPRIMARIES_BT601_P:
            return range == CICP_FULL_RANGE_LIMIT ? ColorManager::BT601_EBU_LIMIT : ColorManager::BT601_EBU;
        case CICP_COLORPRIMARIES_P3_DCI:
            return ColorManager::DCI_P3;
        default:
            break;
    }
    return ColorManager::NONE;
}

template <>
ColorManager::ColorSpaceName ColorUtils::CicpToColorSpace(uint16_t primaries, uint16_t transfer,
    uint16_t matrix, uint8_t range)
{
    switch (primaries) {
        case CICP_COLORPRIMARIES_SRGB:
            return range == CICP_FULL_RANGE_LIMIT ? ColorManager::SRGB_LIMIT : ColorManager::SRGB;
        case CICP_COLORPRIMARIES_P3_D65:
            return P3ToColorSpace(transfer, range);
        case CICP_COLORPRIMARIES_BT2020:
            return BT2020ToColorSpace(transfer, range);
        case CICP_COLORPRIMARIES_BT601_N:
            return range == CICP_FULL_RANGE_LIMIT ? ColorManager::BT601_SMPTE_C_LIMIT : ColorManager::BT601_SMPTE_C;
        case CICP_COLORPRIMARIES_BT601_P:
            return range == CICP_FULL_RANGE_LIMIT ? ColorManager::BT601_EBU_LIMIT : ColorManager::BT601_EBU;
        case CICP_COLORPRIMARIES_P3_DCI:
            return ColorManager::DCI_P3;
        default:
            break;
    }
    return ColorManager::NONE;
}

uint16_t ColorUtils::GetPrimaries(ColorManager::ColorSpaceName name)
{
    switch (name) {
        case ColorManager::ColorSpaceName::SRGB:
        case ColorManager::ColorSpaceName::SRGB_LIMIT:
            return CICP_COLORPRIMARIES_SRGB;
        case ColorManager::ColorSpaceName::DISPLAY_P3:
        case ColorManager::ColorSpaceName::DISPLAY_P3_LIMIT:
        case ColorManager::ColorSpaceName::DCI_P3:
            return CICP_COLORPRIMARIES_P3_D65;
        case ColorManager::ColorSpaceName::BT2020:
        case ColorManager::ColorSpaceName::BT2020_HLG:
        case ColorManager::ColorSpaceName::BT2020_HLG_LIMIT:
        case ColorManager::ColorSpaceName::BT2020_PQ:
        case ColorManager::ColorSpaceName::BT2020_PQ_LIMIT:
            return CICP_COLORPRIMARIES_BT2020;
        default:
            return CICP_COLORPRIMARIES_UNKNOWN;
    }
}

uint16_t GetTransfer(ColorManager::ColorSpaceName name)
{
    switch (name) {
        case ColorManager::ColorSpaceName::SRGB:
        case ColorManager::ColorSpaceName::SRGB_LIMIT:
        case ColorManager::ColorSpaceName::DISPLAY_P3:
        case ColorManager::ColorSpaceName::DISPLAY_P3_LIMIT:
        case ColorManager::ColorSpaceName::DCI_P3:
            return CICP_TRANSFER_SRGB;
        case ColorManager::ColorSpaceName::BT2020:
        case ColorManager::ColorSpaceName::BT2020_HLG:
        case ColorManager::ColorSpaceName::BT2020_HLG_LIMIT:
            return CICP_TRANSFER_HLG;
        case ColorManager::ColorSpaceName::BT2020_PQ:
        case ColorManager::ColorSpaceName::BT2020_PQ_LIMIT:
            return CICP_TRANSFER_PQ;
        default:
            return CICP_TRANSFER_UNKNOWN;
    }
}

uint16_t GetMatrix(ColorManager::ColorSpaceName name)
{
    switch (name) {
        case ColorManager::ColorSpaceName::SRGB:
        case ColorManager::ColorSpaceName::SRGB_LIMIT:
            return CICP_MATRIX_BT601_N;
        case ColorManager::ColorSpaceName::DISPLAY_P3:
        case ColorManager::ColorSpaceName::DISPLAY_P3_LIMIT:
        case ColorManager::ColorSpaceName::DCI_P3:
            return CICP_MATRIX_P3;
        case ColorManager::ColorSpaceName::BT2020:
        case ColorManager::ColorSpaceName::BT2020_HLG:
        case ColorManager::ColorSpaceName::BT2020_HLG_LIMIT:
        case ColorManager::ColorSpaceName::BT2020_PQ:
        case ColorManager::ColorSpaceName::BT2020_PQ_LIMIT:
            return CICP_MATRIX_BT2020;
        default:
            return CICP_TRANSFER_UNKNOWN;
    }
}

uint16_t GetRangeFlag(ColorManager::ColorSpaceName name)
{
    switch (name) {
        case ColorManager::ColorSpaceName::SRGB:
        case ColorManager::ColorSpaceName::DISPLAY_P3:
        case ColorManager::ColorSpaceName::DCI_P3:
        case ColorManager::ColorSpaceName::BT2020:
        case ColorManager::ColorSpaceName::BT2020_HLG:
        case ColorManager::ColorSpaceName::BT2020_PQ:
            return CICP_FULL_RANGE_FULL;
        case ColorManager::ColorSpaceName::SRGB_LIMIT:
        case ColorManager::ColorSpaceName::DISPLAY_P3_LIMIT:
        case ColorManager::ColorSpaceName::BT2020_HLG_LIMIT:
        case ColorManager::ColorSpaceName::BT2020_PQ_LIMIT:
            return CICP_FULL_RANGE_LIMIT;
        default:
            return CICP_FULL_RANGE_FULL;
    }
}

template <>
void ColorUtils::ColorSpaceGetCicp(ColorManager::ColorSpaceName name, uint8_t& primaries, uint8_t& transfer,
    uint8_t& matrix, uint8_t& range)
{
    primaries = GetPrimaries(name);
    transfer = GetTransfer(name);
    matrix = GetMatrix(name);
    range = GetRangeFlag(name);
}

template <>
void ColorUtils::ColorSpaceGetCicp(ColorManager::ColorSpaceName name, uint16_t& primaries, uint16_t& transfer,
    uint16_t& matrix, uint8_t& range)
{
    primaries = GetPrimaries(name);
    transfer = GetTransfer(name);
    matrix = GetMatrix(name);
    range = GetRangeFlag(name);
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType ColorUtils::ConvertToCMColor(ColorManager::ColorSpaceName name)
{
    switch (name) {
        case ColorManager::ColorSpaceName::SRGB :
            return HDI::Display::Graphic::Common::V1_0::CM_SRGB_FULL;
        case ColorManager::ColorSpaceName::SRGB_LIMIT :
            return HDI::Display::Graphic::Common::V1_0::CM_SRGB_LIMIT;
        case ColorManager::ColorSpaceName::DISPLAY_P3 :
        case ColorManager::ColorSpaceName::DCI_P3 :
            return HDI::Display::Graphic::Common::V1_0::CM_P3_FULL;
        case ColorManager::ColorSpaceName::DISPLAY_P3_LIMIT :
            return HDI::Display::Graphic::Common::V1_0::CM_P3_LIMIT;
        case ColorManager::ColorSpaceName::BT2020 :
        case ColorManager::ColorSpaceName::BT2020_HLG :
            return HDI::Display::Graphic::Common::V1_0::CM_BT2020_HLG_FULL;
        case ColorManager::ColorSpaceName::BT2020_HLG_LIMIT :
            return HDI::Display::Graphic::Common::V1_0::CM_BT2020_HLG_LIMIT;
        case ColorManager::ColorSpaceName::BT2020_PQ :
            return HDI::Display::Graphic::Common::V1_0::CM_BT2020_PQ_FULL;
        case ColorManager::ColorSpaceName::BT2020_PQ_LIMIT :
            return HDI::Display::Graphic::Common::V1_0::CM_BT2020_PQ_LIMIT;
        default:
            return HDI::Display::Graphic::Common::V1_0::CM_COLORSPACE_NONE;
    }
    return HDI::Display::Graphic::Common::V1_0::CM_COLORSPACE_NONE;
}
#endif

} // namespace Media
} // namespace OHOS