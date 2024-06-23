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

#include <gtest/gtest.h>
#include "color_utils.h"

using namespace testing::ext;
using namespace OHOS::Media;
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

class ColorUtilsTest : public testing::Test {
public:
    ColorUtilsTest() {}
    ~ColorUtilsTest() {}
};

/**
@tc.name: CicpToColorSpaceTest001
@tc.desc: test CicpToColorSpace
@tc.type: FUNC
*/
HWTEST_F(ColorUtilsTest, CicpToColorSpaceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ColorUtilsTest: CicpToColorSpaceTest001 start";
    ASSERT_EQ(ColorUtils::CicpToColorSpace(CICP_COLORPRIMARIES_SRGB, 0, 0, CICP_FULL_RANGE_LIMIT),
        ColorManager::SRGB_LIMIT);
    ASSERT_EQ(ColorUtils::CicpToColorSpace(CICP_COLORPRIMARIES_P3_D65, CICP_TRANSFER_PQ, 0, CICP_FULL_RANGE_LIMIT),
        ColorManager::P3_PQ_LIMIT);
    ASSERT_EQ(ColorUtils::CicpToColorSpace(CICP_COLORPRIMARIES_P3_D65, CICP_TRANSFER_HLG, 0, CICP_FULL_RANGE_LIMIT),
        ColorManager::P3_HLG_LIMIT);
    ASSERT_EQ(ColorUtils::CicpToColorSpace(CICP_COLORPRIMARIES_P3_D65, CICP_TRANSFER_SRGB, 0, CICP_FULL_RANGE_LIMIT),
        ColorManager::DISPLAY_P3_LIMIT);
    ASSERT_EQ(ColorUtils::CicpToColorSpace(CICP_COLORPRIMARIES_P3_D65, CICP_TRANSFER_UNKNOWN, 0, 0),
        ColorManager::NONE);

    ASSERT_EQ(ColorUtils::CicpToColorSpace(CICP_COLORPRIMARIES_BT2020, CICP_TRANSFER_PQ, 0, CICP_FULL_RANGE_LIMIT),
        ColorManager::BT2020_PQ_LIMIT);
    ASSERT_EQ(ColorUtils::CicpToColorSpace(CICP_COLORPRIMARIES_BT2020, CICP_TRANSFER_HLG, 0, CICP_FULL_RANGE_LIMIT),
        ColorManager::BT2020_HLG_LIMIT);
    ASSERT_EQ(ColorUtils::CicpToColorSpace(CICP_COLORPRIMARIES_BT2020, CICP_TRANSFER_UNKNOWN, 0, 0),
        ColorManager::NONE);

    ASSERT_EQ(ColorUtils::CicpToColorSpace(CICP_COLORPRIMARIES_BT601_N, 0, 0, CICP_FULL_RANGE_LIMIT),
        ColorManager::BT601_SMPTE_C_LIMIT);
    ASSERT_EQ(ColorUtils::CicpToColorSpace(CICP_COLORPRIMARIES_BT601_P, 0, 0, CICP_FULL_RANGE_LIMIT),
        ColorManager::BT601_EBU_LIMIT);
    ASSERT_EQ(ColorUtils::CicpToColorSpace(CICP_COLORPRIMARIES_P3_DCI, 0, 0, 0), ColorManager::DCI_P3);
    ASSERT_EQ(ColorUtils::CicpToColorSpace(CICP_COLORPRIMARIES_UNKNOWN, 0, 0, 0), ColorManager::NONE);
    GTEST_LOG_(INFO) << "ColorUtilsTest: CicpToColorSpaceTest001 end";
}

/**
@tc.name: ColorSpaceGetCicpTest001
@tc.desc: test ColorSpaceGetCicp
@tc.type: FUNC
*/
HWTEST_F(ColorUtilsTest, ColorSpaceGetCicpTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ColorUtilsTest: ColorSpaceGetCicpTest001 start";
    uint16_t primaries = 0;
    uint16_t transfer = 0;
    uint16_t matrix = 0;
    uint8_t range = 0;
    ColorUtils::ColorSpaceGetCicp(ColorManager::ColorSpaceName::SRGB, primaries, transfer, matrix, range);
    ColorUtils::ColorSpaceGetCicp(ColorManager::ColorSpaceName::SRGB_LIMIT, primaries, transfer, matrix, range);
    ColorUtils::ColorSpaceGetCicp(ColorManager::ColorSpaceName::DISPLAY_P3, primaries, transfer, matrix, range);
    ColorUtils::ColorSpaceGetCicp(ColorManager::ColorSpaceName::DISPLAY_P3_LIMIT, primaries, transfer, matrix, range);
    ColorUtils::ColorSpaceGetCicp(ColorManager::ColorSpaceName::DCI_P3, primaries, transfer, matrix, range);
    ColorUtils::ColorSpaceGetCicp(ColorManager::ColorSpaceName::BT2020, primaries, transfer, matrix, range);
    ColorUtils::ColorSpaceGetCicp(ColorManager::ColorSpaceName::BT2020_HLG, primaries, transfer, matrix, range);
    ColorUtils::ColorSpaceGetCicp(ColorManager::ColorSpaceName::BT2020_HLG_LIMIT, primaries, transfer, matrix, range);
    ColorUtils::ColorSpaceGetCicp(ColorManager::ColorSpaceName::BT2020_PQ, primaries, transfer, matrix, range);
    ColorUtils::ColorSpaceGetCicp(ColorManager::ColorSpaceName::BT2020_PQ_LIMIT, primaries, transfer, matrix, range);
    GTEST_LOG_(INFO) << "ColorUtilsTest: ColorSpaceGetCicpTest001 end";
}
}
}