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

#include <gtest/gtest.h>
#include <fstream>
#include <fcntl.h>
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "incremental_pixel_map.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "image_source_util.h"
#include "scan_line_filter.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
class ScanLineFilterTest : public testing::Test {
public:
    ScanLineFilterTest() {}
    ~ScanLineFilterTest() {}
};

/**
 * @tc.name: ScanLineFilterTest001
 * @tc.desc: GetFilterRowType
 * @tc.type: FUNC
 */
HWTEST_F(ScanLineFilterTest, ScanLineFilterTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ScanLineFilterTest: ScanLineFilterTest001 start";
    ScanlineFilter scanlineFilter;
    int32_t scanLine = 0;
    FilterRowType filterRow = scanlineFilter.GetFilterRowType(scanLine);
    ASSERT_EQ(filterRow, FilterRowType::LAST_REFERENCE_ROW);
    GTEST_LOG_(INFO) << "ScanLineFilterTest: ScanLineFilterTest001 end";
}

/**
 * @tc.name: ScanLineFilterTest002
 * @tc.desc: GetFilterRowType
 * @tc.type: FUNC
 */
HWTEST_F(ScanLineFilterTest, ScanLineFilterTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ScanLineFilterTest: ScanLineFilterTest002 start";
    ScanlineFilter scanlineFilter;
    int32_t scanLine = 1000;
    FilterRowType filterRow = scanlineFilter.GetFilterRowType(scanLine);
    ASSERT_EQ(filterRow, FilterRowType::NON_REFERENCE_ROW);
    GTEST_LOG_(INFO) << "ScanLineFilterTest: ScanLineFilterTest002 end";
}

/**
 * @tc.name: ScanLineFilterTest003
 * @tc.desc: SetSrcPixelFormat
 * @tc.type: FUNC
 */
HWTEST_F(ScanLineFilterTest, ScanLineFilterTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ScanLineFilterTest: ScanLineFilterTest003 start";
    ScanlineFilter scanlineFilter;
    PixelFormat srcPixelFormat = PixelFormat::UNKNOWN;
    scanlineFilter.SetSrcPixelFormat(srcPixelFormat);
    GTEST_LOG_(INFO) << "ScanLineFilterTest: ScanLineFilterTest003 end";
}

/**
 * @tc.name: ScanLineFilterTest004
 * @tc.desc: SetSrcRegion
 * @tc.type: FUNC
 */
HWTEST_F(ScanLineFilterTest, ScanLineFilterTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ScanLineFilterTest: ScanLineFilterTest004 start";
    ScanlineFilter scanlineFilter;
    Rect rect;
    rect.left = 0;
    rect.top = 0;
    rect.height = 1;
    rect.width = 1;
    scanlineFilter.SetSrcRegion(rect);
    GTEST_LOG_(INFO) << "ScanLineFilterTest: ScanLineFilterTest004 end";
}

/**
 * @tc.name: ScanLineFilterTest005
 * @tc.desc: SetPixelConvert
 * @tc.type: FUNC
 */
HWTEST_F(ScanLineFilterTest, ScanLineFilterTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ScanLineFilterTest: ScanLineFilterTest005 start";
    ScanlineFilter scanlineFilter;
    ImageInfo srcImageInfo;
    ImageInfo dstImageInfo;
    scanlineFilter.SetPixelConvert(srcImageInfo, dstImageInfo);
    GTEST_LOG_(INFO) << "ScanLineFilterTest: ScanLineFilterTest005 end";
}

/**
 * @tc.name: ScanLineFilterTest006
 * @tc.desc: SetPixelConvert
 * @tc.type: FUNC
 */
HWTEST_F(ScanLineFilterTest, ScanLineFilterTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ScanLineFilterTest: ScanLineFilterTest006 start";
    ScanlineFilter scanlineFilter;
    void *destRowPixels = nullptr;
    uint32_t destRowBytes = 0;
    void *srcRowPixels = nullptr;
    uint32_t ret = scanlineFilter.FilterLine(destRowPixels, destRowBytes, srcRowPixels);
    ASSERT_EQ(ret, ERR_IMAGE_CROP);
    GTEST_LOG_(INFO) << "ScanLineFilterTest: ScanLineFilterTest006 end";
}
}
}

