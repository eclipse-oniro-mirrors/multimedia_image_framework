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
#include "image_log.h"
#include "image_utils.h"

#if !defined(CROSS_PLATFORM)
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

#if !defined(CROSS_PLATFORM)
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

static constexpr uint8_t SIZE_4 = 4;
constexpr static uint32_t OFFSET_5 = 5;
constexpr static uint32_t DESC_SIGNATURE = 0x64657363;
constexpr static uint64_t ICC_HEADER_SIZE = 132;
constexpr static uint32_t RXYZ_SIGNATURE = 0x7258595A;  // 'rXYZ'
constexpr static uint32_t GXYZ_SIGNATURE = 0x6758595A;  // 'gXYZ'
constexpr static uint32_t BXYZ_SIGNATURE = 0x6258595A;  // 'bXYZ'
constexpr static uint32_t RTRC_SIGNATURE = 0x72545243;  // 'rTRC'
constexpr static uint32_t GTRC_SIGNATURE = 0x67545243;  // 'gTRC'
constexpr static uint32_t BTRC_SIGNATURE = 0x62545243;  // 'bTRC'
constexpr static uint32_t TERC_TAG = 0x74657263; // 'TERC'
constexpr static uint32_t OFFSET_0 = 0;
constexpr static uint32_t OFFSET_1 = 1;
constexpr static uint32_t OFFSET_2 = 2;
constexpr static uint32_t OFFSET_3 = 3;
constexpr static uint32_t OFFSET_4 = 4;
constexpr static uint32_t OFFSET_12 = 12;
constexpr static uint32_t SHIFT_BITS_4 = 4;
constexpr static uint32_t SHIFT_BITS_8 = 8;
constexpr static uint32_t SHIFT_BITS_9 = 9;
constexpr static uint32_t SHIFT_BITS_10 = 10;
constexpr static uint32_t SHIFT_BITS_11 = 11;
constexpr static uint32_t SHIFT_BITS_12 = 12;
constexpr static uint32_t SHIFT_BITS_16 = 16;
constexpr static uint32_t SHIFT_BITS_24 = 24;
constexpr static uint32_t XYZ_TAG_LENGTH = 20;
constexpr static uint32_t TOLERANCE_NUMBER = 3;
constexpr static uint32_t MAX_TAG_COUNT = 1000;
constexpr static float DEFAULT_SRGB_GAMMA = 2.2f;
constexpr static float DEFAULT_XYZ_NUMBER = 0.0f;
constexpr static float OVERFLOW_CHECK = 65536.0f;
constexpr static float XYZ_EPSILON = 1e-6f;
struct ColorSpaceNameEnum {
    std::string desc;
    OHOS::ColorManager::ColorSpaceName name;
};

struct ICCTag {
    uint8_t signature[SIZE_4];
    uint8_t offset[SIZE_4];
    uint8_t size[SIZE_4];
};

struct XYZValues {
    float x;
    float y;
    float z;
};

static std::vector<ColorSpaceNameEnum> sColorSpaceNamedMap = {
    {"Display P3", OHOS::ColorManager::ColorSpaceName::DISPLAY_P3},
    {"sRGB EOTF with DCI-P3 Color Gamut", OHOS::ColorManager::ColorSpaceName::DISPLAY_P3},
    {"DCI-P3 D65 Gamut with sRGB Transfer", OHOS::ColorManager::ColorSpaceName::DISPLAY_P3},
    {"Adobe RGB (1998)", OHOS::ColorManager::ColorSpaceName::ADOBE_RGB},
    {"DCI P3", OHOS::ColorManager::ColorSpaceName::DCI_P3},
    {"sRGB", OHOS::ColorManager::ColorSpaceName::SRGB},
    {"BT.2020", OHOS::ColorManager::ColorSpaceName::BT2020},
    {"DCI-P3", OHOS::ColorManager::ColorSpaceName::DCI_P3},
    {"Rec2020 Gamut with HLG Transfer", OHOS::ColorManager::ColorSpaceName::BT2020_HLG},
    {"REC. 2020", OHOS::ColorManager::ColorSpaceName::BT2020_HLG}
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
        case ColorManager::ColorSpaceName::ADOBE_RGB :
            return HDI::Display::Graphic::Common::V1_0::CM_ADOBERGB_FULL;
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

HDI::Display::Graphic::Common::V1_0::CM_ColorPrimaries ColorUtils::ConvertCicpToCMColor(uint16_t name)
{
    switch (name) {
        case CICP_COLORPRIMARIES_SRGB:
            return HDI::Display::Graphic::Common::V1_0::COLORPRIMARIES_SRGB;
        case CICP_COLORPRIMARIES_BT601_P:
            return HDI::Display::Graphic::Common::V1_0::COLORPRIMARIES_BT601_P;
        case CICP_COLORPRIMARIES_BT601_N:
            return HDI::Display::Graphic::Common::V1_0::COLORPRIMARIES_BT601_N;
        case CICP_COLORPRIMARIES_BT2020:
            return HDI::Display::Graphic::Common::V1_0::COLORPRIMARIES_BT2020;
        case CICP_COLORPRIMARIES_P3_DCI:
            return HDI::Display::Graphic::Common::V1_0::COLORPRIMARIES_P3_DCI;
        case CICP_COLORPRIMARIES_P3_D65:
            return HDI::Display::Graphic::Common::V1_0::COLORPRIMARIES_P3_D65;
        default:
            return HDI::Display::Graphic::Common::V1_0::COLORPRIMARIES_SRGB;
    }
}

uint16_t ColorUtils::ConvertCMColorToCicp(uint16_t name)
{
    switch (name) {
        case HDI::Display::Graphic::Common::V1_0::COLORPRIMARIES_SRGB:
            return CICP_COLORPRIMARIES_SRGB;
        case HDI::Display::Graphic::Common::V1_0::COLORPRIMARIES_BT601_P:
            return CICP_COLORPRIMARIES_BT601_P;
        case HDI::Display::Graphic::Common::V1_0::COLORPRIMARIES_BT601_N:
            return CICP_COLORPRIMARIES_BT601_N;
        case HDI::Display::Graphic::Common::V1_0::COLORPRIMARIES_BT2020:
            return CICP_COLORPRIMARIES_BT2020;
        case HDI::Display::Graphic::Common::V1_0::COLORPRIMARIES_P3_DCI:
            return CICP_COLORPRIMARIES_P3_DCI;
        case HDI::Display::Graphic::Common::V1_0::COLORPRIMARIES_P3_D65:
            return CICP_COLORPRIMARIES_P3_D65;
        default:
            return CICP_COLORPRIMARIES_SRGB;
    }
}

bool ColorUtils::MatchColorSpaceName(const uint8_t* buf, uint32_t size, OHOS::ColorManager::ColorSpaceName &name)
{
    bool cond = buf == nullptr || size <= OFFSET_5;
    CHECK_ERROR_RETURN_RET(cond, false);
    std::vector<char> desc;
    // We need skip desc type
    for (uint32_t i = OFFSET_5; i < size; i++) {
        if (buf[i] != '\0') {
            desc.push_back(buf[i]);
        }
    }
    cond = desc.size() <= 1;
    CHECK_INFO_RETURN_RET_LOG(cond, false, "empty buffer");
    std::string descText(desc.begin() + 1, desc.end());
    for (auto nameEnum : sColorSpaceNamedMap) {
        IMAGE_LOGD("descText is %{public}s.", descText.c_str());
        if (descText.find(nameEnum.desc) == std::string::npos) {
            continue;
        }
        name = nameEnum.name;
        return true;
    }
    IMAGE_LOGE("Failed to match desc");
    return false;
}

bool ColorUtils::GetColorSpaceName(const skcms_ICCProfile* profile, OHOS::ColorManager::ColorSpaceName &name)
{
    if (profile == nullptr || profile->buffer == nullptr || profile->tag_count > MAX_TAG_COUNT) {
        IMAGE_LOGD("profile is nullptr or too many tagcount");
        return false;
    }
    auto tags = reinterpret_cast<const ICCTag*>(profile->buffer + ICC_HEADER_SIZE);
    for (uint32_t i = 0; i < profile->tag_count; i++) {
        uint32_t tmpOffset = 0;
        auto signature = ImageUtils::BytesToUint32(const_cast<uint8_t*>(tags[i].signature),
            tmpOffset, SIZE_4, true);
        if (signature != DESC_SIGNATURE) {
            continue;
        }
        tmpOffset = 0;
        auto size = ImageUtils::BytesToUint32(const_cast<uint8_t*>(tags[i].size),
            tmpOffset, SIZE_4, true);
        tmpOffset = 0;
        auto offset = ImageUtils::BytesToUint32(const_cast<uint8_t*>(tags[i].offset),
            tmpOffset, SIZE_4, true);
        if (size == 0 || offset >= profile->size || offset + size >= profile->size) {
            continue;
        }
        tmpOffset = 0;
        auto buffer = ImageUtils::BytesToUint32(const_cast<uint8_t*>(tags[i].offset),
            tmpOffset, SIZE_4, true) + profile->buffer;
        if (MatchColorSpaceName(buffer, size, name)) {
            return true;
        }
    }
    return false;
}

OHOS::ColorManager::ColorSpaceName ColorUtils::GetSrcColorSpace(const skcms_ICCProfile* profile)
{
    if (profile == nullptr) {
        return OHOS::ColorManager::ColorSpaceName::NONE;
    }
    OHOS::ColorManager::ColorSpaceName name = OHOS::ColorManager::ColorSpaceName::NONE;
    OHOS::Media::ColorUtils::GetColorSpaceName(profile, name);
    if (profile->has_CICP) {
        ColorManager::ColorSpaceName cName = OHOS::Media::ColorUtils::CicpToColorSpace(profile->CICP.color_primaries,
            profile->CICP.transfer_characteristics, profile->CICP.matrix_coefficients,
            profile->CICP.video_full_range_flag);
        if (cName != ColorManager::NONE) {
            IMAGE_LOGD("%{public}s profile has CICP, cName: %{public}u", __func__, static_cast<uint32_t>(cName));
            return cName;
        }
    }
    IMAGE_LOGD("%{public}s Parse ColorSpaceName is not support.", __func__);
    return name;
}

static uint32_t U8ToU32(const uint8_t* p)
{
    return (static_cast<uint32_t>(p[OFFSET_0]) << SHIFT_BITS_24) |
        (static_cast<uint32_t>(p[OFFSET_1]) << SHIFT_BITS_16) |
        (static_cast<uint32_t>(p[OFFSET_2]) << SHIFT_BITS_8) | p[OFFSET_3];
}

static bool GetXYZFromTag(const uint8_t* buffer, uint32_t offset, uint32_t size, XYZValues* xyz)
{
    CHECK_ERROR_RETURN_RET(buffer == nullptr || xyz == nullptr, false);
    CHECK_ERROR_RETURN_RET(offset + XYZ_TAG_LENGTH > size, false);
    // s15Fixed16Number to float
    auto toFixed16 = [](const uint8_t* p) -> float {
        int32_t val = (p[OFFSET_0] << SHIFT_BITS_24) | (p[OFFSET_1] << SHIFT_BITS_16) |
            (p[OFFSET_2] << SHIFT_BITS_8) | p[OFFSET_3];
        return static_cast<float>(val) / OVERFLOW_CHECK;
    };

    xyz->x = toFixed16(buffer + offset + SHIFT_BITS_8);
    xyz->y = toFixed16(buffer + offset + SHIFT_BITS_12);
    xyz->z = toFixed16(buffer + offset + SHIFT_BITS_16);
    return true;
}

static bool GetGammaFromTRCTag(const uint8_t* buffer, uint32_t offset, uint32_t size, float* gamma)
{
    CHECK_ERROR_RETURN_RET(buffer == nullptr || gamma == nullptr, false);
    CHECK_ERROR_RETURN_RET(offset + SHIFT_BITS_4 > size, false);
    uint32_t curveType = (buffer[offset] << SHIFT_BITS_24) | (buffer[offset + OFFSET_1] << SHIFT_BITS_16) |
        (buffer[offset + OFFSET_2] << SHIFT_BITS_8) | buffer[offset + OFFSET_3];

    if (curveType == TERC_TAG) {
        CHECK_ERROR_RETURN_RET(offset + OFFSET_12 > size, false);
        int32_t val = (buffer[offset + SHIFT_BITS_8] << SHIFT_BITS_24) |
            (buffer[offset + SHIFT_BITS_9] << SHIFT_BITS_16) |
            (buffer[offset + SHIFT_BITS_10] << SHIFT_BITS_8) | buffer[offset + SHIFT_BITS_11];
        *gamma = static_cast<float>(val) / OVERFLOW_CHECK;
        return true;
    }
    *gamma = DEFAULT_SRGB_GAMMA;  // default sRGB gamma
    return true;
}

struct ICCProfileData {
    XYZValues rXYZ;
    XYZValues gXYZ;
    XYZValues bXYZ;
    float gamma;
    bool hasRXYZ;
    bool hasGXYZ;
    bool hasBXYZ;
    bool hasTRC;
};

static bool ExtractICCProfileData(const skcms_ICCProfile* profile, ICCProfileData& data)
{
    CHECK_ERROR_RETURN_RET(profile == nullptr || profile->buffer == nullptr || profile->tag_count == 0, false);
    CHECK_ERROR_RETURN_RET(profile->tag_count > MAX_TAG_COUNT, false);
    data.rXYZ = {DEFAULT_XYZ_NUMBER, DEFAULT_XYZ_NUMBER, DEFAULT_XYZ_NUMBER};
    data.gXYZ = {DEFAULT_XYZ_NUMBER, DEFAULT_XYZ_NUMBER, DEFAULT_XYZ_NUMBER};
    data.bXYZ = {DEFAULT_XYZ_NUMBER, DEFAULT_XYZ_NUMBER, DEFAULT_XYZ_NUMBER};
    data.gamma = DEFAULT_SRGB_GAMMA;
    data.hasRXYZ = false;
    data.hasGXYZ = false;
    data.hasBXYZ = false;
    data.hasTRC = false;

    auto tags = reinterpret_cast<const ICCTag*>(profile->buffer + ICC_HEADER_SIZE);
    for (uint32_t i = 0; i < profile->tag_count; i++) {
        auto signature = U8ToU32(tags[i].signature);
        auto size = U8ToU32(tags[i].size);
        auto offset = U8ToU32(tags[i].offset);
        if (size == 0 || offset >= profile->size) {
            continue;
        }
        if (signature == RXYZ_SIGNATURE) {
            data.hasRXYZ = GetXYZFromTag(profile->buffer, offset, profile->size, &data.rXYZ);
        } else if (signature == GXYZ_SIGNATURE) {
            data.hasGXYZ = GetXYZFromTag(profile->buffer, offset, profile->size, &data.gXYZ);
        } else if (signature == BXYZ_SIGNATURE) {
            data.hasBXYZ = GetXYZFromTag(profile->buffer, offset, profile->size, &data.bXYZ);
        } else if (signature == RTRC_SIGNATURE || signature == GTRC_SIGNATURE || signature == BTRC_SIGNATURE) {
            if (!data.hasTRC) {
                data.hasTRC = GetGammaFromTRCTag(profile->buffer, offset, profile->size, &data.gamma);
            }
        }
    }

    CHECK_DEBUG_RETURN_RET_LOG(!data.hasRXYZ || !data.hasGXYZ || !data.hasBXYZ, false,
        "Incomplete primaries data in ICC profile");
    return true;
}

struct PrimariesXY {
    float rX;
    float rY;
    float gX;
    float gY;
    float bX;
    float bY;
};

static bool CalculatePrimariesXY(const ICCProfileData& data, PrimariesXY& primaries)
{
    float rSum = data.rXYZ.x + data.rXYZ.y + data.rXYZ.z;
    float gSum = data.gXYZ.x + data.gXYZ.y + data.gXYZ.z;
    float bSum = data.bXYZ.x + data.bXYZ.y + data.bXYZ.z;
    CHECK_ERROR_RETURN_RET(std::abs(rSum) < XYZ_EPSILON, false);
    CHECK_ERROR_RETURN_RET(std::abs(gSum) < XYZ_EPSILON, false);
    CHECK_ERROR_RETURN_RET(std::abs(bSum) < XYZ_EPSILON, false);
    primaries.rX = data.rXYZ.x / rSum;
    primaries.rY = data.rXYZ.y / rSum;
    primaries.gX = data.gXYZ.x / gSum;
    primaries.gY = data.gXYZ.y / gSum;
    primaries.bX = data.bXYZ.x / bSum;
    primaries.bY = data.bXYZ.y / bSum;
    return true;
}

struct StandardColorSpace {
    const char* name;
    float rX;
    float rY;
    float gX;
    float gY;
    float bX;
    float bY;
};

static const StandardColorSpace STANDARD_COLOR_SPACES[] = {
    {"sRGB", 0.64f, 0.33f, 0.30f, 0.60f, 0.15f, 0.06f},
    {"Display P3", 0.680f, 0.320f, 0.265f, 0.690f, 0.150f, 0.060f},
    {"BT.2020", 0.708f, 0.292f, 0.170f, 0.797f, 0.131f, 0.046f},
    {"Adobe RGB", 0.640f, 0.330f, 0.210f, 0.710f, 0.150f, 0.060f},
    {"DCI-P3", 0.680f, 0.320f, 0.265f, 0.690f, 0.150f, 0.060f}
};

static float CalculateColorSpaceDistance(const PrimariesXY& primaries, const StandardColorSpace& standard)
{
    auto calcDistance = [](float x1, float y1, float x2, float y2) -> float {
        return std::sqrt((x1 - x2) * (x1 - x2) + (y1 - y2) * (y1 - y2));
    };

    return calcDistance(primaries.rX, primaries.rY, standard.rX, standard.rY) +
           calcDistance(primaries.gX, primaries.gY, standard.gX, standard.gY) +
           calcDistance(primaries.bX, primaries.bY, standard.bX, standard.bY);
}

enum class GammaType {
    SRGB,
    HLG,
    UNKNOWN
};

static GammaType DetermineGammaType(float gamma)
{
    constexpr float SRGB_GAMMA = 2.2f;
    constexpr float LINEAR_GAMMA = 1.0f;
    constexpr float HLG_GAMMA = 1.2f;
    constexpr float HLG_GAMMA_LOW = 0.5f;
    constexpr float GAMMA_TOLERANCE = 0.1f;

    if ((std::abs(gamma - SRGB_GAMMA) < GAMMA_TOLERANCE) ||
        (std::abs(gamma - LINEAR_GAMMA) < GAMMA_TOLERANCE)) {
        return GammaType::SRGB;
    }
    if ((std::abs(gamma - HLG_GAMMA) < GAMMA_TOLERANCE) ||
        (std::abs(gamma - HLG_GAMMA_LOW) < GAMMA_TOLERANCE)) {
        return GammaType::HLG;
    }
    return GammaType::UNKNOWN;
}

static bool MatchColorSpaceByDistance(const PrimariesXY& primaries, float gamma,
    OHOS::ColorManager::ColorSpaceName& name)
{
    constexpr float TOLERANCE = 0.02f;
    constexpr float TOLERANCE_THRESHOLD = TOLERANCE * TOLERANCE_NUMBER;
    constexpr int COLORSPACE_NUM = 5;

    float distances[COLORSPACE_NUM];
    for (int i = 0; i < COLORSPACE_NUM; i++) {
        distances[i] = CalculateColorSpaceDistance(primaries, STANDARD_COLOR_SPACES[i]);
    }
    GammaType gammaType = DetermineGammaType(gamma);
    // Match sRGB
    if (distances[OFFSET_0] < TOLERANCE_THRESHOLD && gammaType == GammaType::SRGB) {
        name = OHOS::ColorManager::ColorSpaceName::SRGB;
        IMAGE_LOGD("Matched sRGB by primaries and gamma");
        return true;
    }

    // Match Display P3
    if (distances[OFFSET_1] < TOLERANCE_THRESHOLD) {
        name = OHOS::ColorManager::ColorSpaceName::DISPLAY_P3;
        IMAGE_LOGD("Matched Display P3 by primaries");
        return true;
    }

    // Match BT.2020
    if (distances[OFFSET_2] < TOLERANCE_THRESHOLD) {
        //The logic for "2020" is relatively complex, so use the original flow for matching.
        return false;
    }

    // Match Adobe RGB
    if (distances[OFFSET_3] < TOLERANCE_THRESHOLD) {
        name = OHOS::ColorManager::ColorSpaceName::ADOBE_RGB;
        IMAGE_LOGD("Matched Adobe RGB by primaries");
        return true;
    }

    // Match DCI-P3
    if (distances[OFFSET_4] < TOLERANCE_THRESHOLD) {
        name = OHOS::ColorManager::ColorSpaceName::DCI_P3;
        IMAGE_LOGD("Matched DCI-P3 by primaries");
        return true;
    }

    IMAGE_LOGI("No standard color space matched by primaries and gamma");
    return false;
}

// Match color space by primaries and gamma
bool ColorUtils::MatchColorSpaceByPrimariesAndGamma(const skcms_ICCProfile* profile,
    OHOS::ColorManager::ColorSpaceName &name)
{
    ICCProfileData profileData;
    CHECK_ERROR_RETURN_RET(!ExtractICCProfileData(profile, profileData), false);

    PrimariesXY primaries;
    CHECK_ERROR_RETURN_RET(!CalculatePrimariesXY(profileData, primaries), false);
    return MatchColorSpaceByDistance(primaries, profileData.gamma, name);
}

#endif

} // namespace Media
} // namespace OHOS