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

uint16_t GetPrimaries(ColorManager::ColorSpaceName name)
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

void ColorUtils::ColorSpaceGetCicp(ColorManager::ColorSpaceName name, uint16_t& primaries, uint16_t& transfer,
    uint16_t& matrix, uint8_t& range)
{
    primaries = GetPrimaries(name);
    transfer = GetTransfer(name);
    matrix = GetMatrix(name);
    range = GetRangeFlag(name);
}

} // namespace Media
} // namespace OHOS