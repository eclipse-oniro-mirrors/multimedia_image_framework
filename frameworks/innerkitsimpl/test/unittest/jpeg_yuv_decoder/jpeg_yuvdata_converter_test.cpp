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
#include "jpeg_yuvdata_converter.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {
static unsigned char g_numZero = 48;
static const uint32_t INFO_DATA = 5;
static const uint32_t IMAGE_HEIGHT = 1;
static const uint8_t INVALID_SRCX = 5;
static const uint8_t VALID_SRCX = 4;
static const int FAIL_CODE = -1;

int I4xxToI420_c(const YuvPlaneInfo &src, const YuvPlaneInfo &dest,
    uint8_t srcXScale, uint8_t srcYScale, bool outfmtIsYU12);

class JpegYuvdataConverterTest : public testing::Test {
public:
    JpegYuvdataConverterTest() {}
    ~JpegYuvdataConverterTest() {}
};

/**
 * @tc.name: IsValidYuvGrayDataTest001
 * @tc.desc: Test IsValidYuvGrayData, return false when input invalid parameters.
 * @tc.type: FUNC
 */
HWTEST_F(JpegYuvdataConverterTest, IsValidYuvGrayDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: IsValidYuvGrayDataTest001 start";
    YuvPlaneInfo srcPlaneInfo;
    YuvPlaneInfo destPlaneInfo;

    int ret = I400ToI420_wrapper(srcPlaneInfo, destPlaneInfo);
    EXPECT_EQ(ret, FAIL_CODE);

    srcPlaneInfo.planes[YCOM] = &g_numZero;
    ret = I400ToI420_wrapper(srcPlaneInfo, destPlaneInfo);
    EXPECT_EQ(ret, FAIL_CODE);
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: IsValidYuvGrayDataTest001 end";
}

/**
 * @tc.name: IsValidSizeTest001
 * @tc.desc: Test IsValidSize, return false when input invalid parameters.
 * @tc.type: FUNC
 */
HWTEST_F(JpegYuvdataConverterTest, IsValidSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: IsValidSizeTest001 start";
    YuvPlaneInfo srcPlaneInfo;
    srcPlaneInfo.planes[YCOM] = &g_numZero;
    srcPlaneInfo.strides[YCOM] = INFO_DATA;
    YuvPlaneInfo destPlaneInfo;
    destPlaneInfo.planes[YCOM] = &g_numZero;
    destPlaneInfo.planes[UCOM] = &g_numZero;
    destPlaneInfo.planes[VCOM] = &g_numZero;
    destPlaneInfo.strides[YCOM] = INFO_DATA;
    destPlaneInfo.strides[UCOM] = INFO_DATA;
    destPlaneInfo.strides[VCOM] = INFO_DATA;

    int ret = I400ToI420_wrapper(srcPlaneInfo, destPlaneInfo);
    EXPECT_EQ(ret, FAIL_CODE);

    srcPlaneInfo.imageWidth = INFO_DATA;
    ret = I400ToI420_wrapper(srcPlaneInfo, destPlaneInfo);
    EXPECT_EQ(ret, FAIL_CODE);
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: IsValidSizeTest001 end";
}

/**
 * @tc.name: IsValidScaleFactorTest001
 * @tc.desc: Test IsValidScaleFactor, return false when input invalid parameters.
 * @tc.type: FUNC
 */
HWTEST_F(JpegYuvdataConverterTest, IsValidScaleFactorTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: IsValidScaleFactorTest001 start";
    YuvPlaneInfo srcPlaneInfo;
    srcPlaneInfo.planes[YCOM] = &g_numZero;
    srcPlaneInfo.planes[UCOM] = &g_numZero;
    srcPlaneInfo.planes[VCOM] = &g_numZero;
    srcPlaneInfo.strides[YCOM] = INFO_DATA;
    srcPlaneInfo.strides[UCOM] = INFO_DATA;
    srcPlaneInfo.strides[VCOM] = INFO_DATA;
    srcPlaneInfo.imageWidth = INFO_DATA;
    srcPlaneInfo.imageHeight = IMAGE_HEIGHT;
    YuvPlaneInfo destPlaneInfo;

    int ret = I4xxToI420_c(srcPlaneInfo, destPlaneInfo, INVALID_SRCX, 0, true);
    EXPECT_EQ(ret, FAIL_CODE);

    ret = I4xxToI420_c(srcPlaneInfo, destPlaneInfo, 0, 0, true);
    EXPECT_EQ(ret, FAIL_CODE);
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: IsValidScaleFactorTest001 end";
}

/**
 * @tc.name: CopyLineDataTest001
 * @tc.desc: Test CopyLineData, return true when destStride > srcStride.
 * @tc.type: FUNC
 */
HWTEST_F(JpegYuvdataConverterTest, CopyLineDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: CopyLineDataTest001 start";
    YuvPlaneInfo srcPlaneInfo;
    srcPlaneInfo.planes[YCOM] = &g_numZero;
    srcPlaneInfo.strides[YCOM] = INFO_DATA;
    srcPlaneInfo.imageWidth = INFO_DATA;
    srcPlaneInfo.imageHeight = IMAGE_HEIGHT;
    YuvPlaneInfo destPlaneInfo;
    destPlaneInfo.planes[YCOM] = &g_numZero;
    destPlaneInfo.planes[UCOM] = &g_numZero;
    destPlaneInfo.planes[VCOM] = &g_numZero;
    destPlaneInfo.strides[YCOM] = INFO_DATA + INFO_DATA;
    destPlaneInfo.strides[UCOM] = INFO_DATA;
    destPlaneInfo.strides[VCOM] = INFO_DATA;

    int ret = I400ToYUV420Sp(srcPlaneInfo, destPlaneInfo);
    EXPECT_EQ(ret, FAIL_CODE);
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: CopyLineDataTest001 end";
}

/**
 * @tc.name: CopyYDataTest001
 * @tc.desc: Test CopyYData, return true when input valid parameters.
 * @tc.type: FUNC
 */
HWTEST_F(JpegYuvdataConverterTest, CopyYDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: CopyYDataTest001 start";
    YuvPlaneInfo srcPlaneInfo;
    srcPlaneInfo.planes[YCOM] = &g_numZero;
    srcPlaneInfo.planes[UCOM] = &g_numZero;
    srcPlaneInfo.planes[VCOM] = &g_numZero;
    srcPlaneInfo.strides[YCOM] = INFO_DATA;
    srcPlaneInfo.strides[UCOM] = INFO_DATA;
    srcPlaneInfo.strides[VCOM] = INFO_DATA;
    srcPlaneInfo.imageWidth = INFO_DATA;
    srcPlaneInfo.imageHeight = IMAGE_HEIGHT;
    YuvPlaneInfo destPlaneInfo;
    destPlaneInfo.planes[YCOM] = &g_numZero;
    destPlaneInfo.planes[UCOM] = &g_numZero;
    destPlaneInfo.planes[VCOM] = &g_numZero;
    destPlaneInfo.strides[YCOM] = INFO_DATA;
    destPlaneInfo.strides[UCOM] = INFO_DATA;
    destPlaneInfo.strides[VCOM] = INFO_DATA;
    destPlaneInfo.planeHeight[YCOM] = INFO_DATA + INFO_DATA;

    int ret = I4xxToI420_c(srcPlaneInfo, destPlaneInfo, VALID_SRCX, VALID_SRCX, true);
    EXPECT_EQ(ret, 0);

    destPlaneInfo.planeHeight[YCOM] = INFO_DATA;
    ret = I4xxToI420_c(srcPlaneInfo, destPlaneInfo, VALID_SRCX, VALID_SRCX, true);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: CopyYDataTest001 end";
}

/**
 * @tc.name: I444ToI420_wrapperTest001
 * @tc.desc: Test I444ToI420_wrapper, call I4xxToI420_c when I444ToI420 is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(JpegYuvdataConverterTest, I444ToI420_wrapperTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: I444ToI420_wrapperTest001 start";
    YuvPlaneInfo srcPlaneInfo;
    YuvPlaneInfo destPlaneInfo;

    int ret = I444ToI420_wrapper(srcPlaneInfo, destPlaneInfo);
    EXPECT_EQ(ret, FAIL_CODE);
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: I444ToI420_wrapperTest001 end";
}

/**
 * @tc.name: I444ToNV21_wrapperTest001
 * @tc.desc: Test I444ToNV21_wrapper, call I4xxToI420_c when I444ToNV21 is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(JpegYuvdataConverterTest, I444ToNV21_wrapperTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: I444ToNV21_wrapperTest001 start";
    YuvPlaneInfo srcPlaneInfo;
    YuvPlaneInfo destPlaneInfo;

    int ret = I444ToNV21_wrapper(srcPlaneInfo, destPlaneInfo);
    EXPECT_EQ(ret, FAIL_CODE);
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: I444ToNV21_wrapperTest001 end";
}

/**
 * @tc.name: I422ToI420_wrapperTest001
 * @tc.desc: Test I422ToI420_wrapper, call I4xxToI420_c when I422ToI420 is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(JpegYuvdataConverterTest, I422ToI420_wrapperTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: I422ToI420_wrapperTest001 start";
    YuvPlaneInfo srcPlaneInfo;
    YuvPlaneInfo destPlaneInfo;

    int ret = I422ToI420_wrapper(srcPlaneInfo, destPlaneInfo);
    EXPECT_EQ(ret, FAIL_CODE);
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: I422ToI420_wrapperTest001 end";
}

/**
 * @tc.name: I400ToI420_wrapperTest001
 * @tc.desc: Test I400ToI420_wrapper, fall back to the self-implemented logic when I400ToI420 is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(JpegYuvdataConverterTest, I400ToI420_wrapperTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: I400ToI420_wrapperTest001 start";
    YuvPlaneInfo srcPlaneInfo;
    srcPlaneInfo.planes[YCOM] = &g_numZero;
    srcPlaneInfo.strides[YCOM] = INFO_DATA;
    srcPlaneInfo.imageWidth = INFO_DATA;
    srcPlaneInfo.imageHeight = IMAGE_HEIGHT;
    YuvPlaneInfo destPlaneInfo;
    destPlaneInfo.planes[YCOM] = &g_numZero;
    destPlaneInfo.planes[UCOM] = &g_numZero;
    destPlaneInfo.planes[VCOM] = &g_numZero;
    destPlaneInfo.strides[YCOM] = INFO_DATA;
    destPlaneInfo.strides[UCOM] = INFO_DATA;
    destPlaneInfo.strides[VCOM] = INFO_DATA;
    destPlaneInfo.planeHeight[YCOM] = INFO_DATA + INFO_DATA;

    int ret = I400ToI420_wrapper(srcPlaneInfo, destPlaneInfo);
    EXPECT_EQ(ret, 0);

    destPlaneInfo.planeHeight[YCOM] = 0;
    ret = I400ToI420_wrapper(srcPlaneInfo, destPlaneInfo);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: I400ToI420_wrapperTest001 end";
}

/**
 * @tc.name: I400ToYUV420SpTest001
 * @tc.desc: Test I400ToYUV420Sp, verify it fails on invalid size then succeeds or keeps 0 on valid or edge cases.
 * @tc.type: FUNC
 */
HWTEST_F(JpegYuvdataConverterTest, I400ToYUV420SpTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: I400ToYUV420SpTest001 start";
    YuvPlaneInfo srcPlaneInfo;
    srcPlaneInfo.planes[YCOM] = &g_numZero;
    srcPlaneInfo.strides[YCOM] = INFO_DATA;
    YuvPlaneInfo destPlaneInfo;
    destPlaneInfo.planes[YCOM] = &g_numZero;
    destPlaneInfo.planes[UCOM] = &g_numZero;
    destPlaneInfo.planes[VCOM] = &g_numZero;
    destPlaneInfo.strides[YCOM] = INFO_DATA;
    destPlaneInfo.strides[UCOM] = INFO_DATA;
    destPlaneInfo.strides[VCOM] = INFO_DATA;
    destPlaneInfo.planeHeight[YCOM] = INFO_DATA + INFO_DATA;

    int ret = I400ToYUV420Sp(srcPlaneInfo, destPlaneInfo);
    EXPECT_EQ(ret, FAIL_CODE);

    srcPlaneInfo.imageWidth = INFO_DATA;
    srcPlaneInfo.imageHeight = IMAGE_HEIGHT;
    ret = I400ToYUV420Sp(srcPlaneInfo, destPlaneInfo);
    EXPECT_EQ(ret, FAIL_CODE);

    destPlaneInfo.planeHeight[YCOM] = 0;
    ret = I400ToYUV420Sp(srcPlaneInfo, destPlaneInfo);
    EXPECT_EQ(ret, FAIL_CODE);
    GTEST_LOG_(INFO) << "JpegYuvdataConverterTest: I400ToYUV420SpTest001 end";
}
} // namespace ImagePlugin
} // namespace OHOS
