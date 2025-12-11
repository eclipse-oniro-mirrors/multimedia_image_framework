/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "jpeg_decoder_yuv.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
constexpr uint32_t TEST_JPEG_WIDTH = 100;
constexpr uint32_t TEST_JPEG_HEIGHT = 80;
constexpr uint32_t TEST_INVALID_WIDTH = 99;
constexpr uint32_t TEST_INVALID_HEIGHT = 39;
constexpr uint32_t TEST_YUV_BUFFER_SIZE_SMALL = 100;
constexpr uint32_t TEST_YUV_BUFFER_SIZE_420_STANDARD = 15000;

static int DummyTo420(const YuvPlaneInfo&, const YuvPlaneInfo&) { return 0; }
static int DummyToNV21(const YuvPlaneInfo&, const YuvPlaneInfo&) { return 0; }

class JpegDecoderYuvTest : public testing::Test {
public:
    JpegDecoderYuvTest() {}
    ~JpegDecoderYuvTest() {}
};

/**
 * @tc.name: IsOutSizeValidTest001
 * @tc.desc: Test IsOutSizeValid when width is not equal to jpgwidth
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderYuvTest, IsOutSizeValidTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: IsOutSizeValidTest001 start";
    JpegDecoderYuv decoder;
    decoder.decodeParameter_.jpgwidth_ = TEST_JPEG_WIDTH;
    decoder.decodeParameter_.jpgheight_ = TEST_JPEG_HEIGHT;
    bool res = decoder.IsOutSizeValid(TEST_INVALID_WIDTH, TEST_JPEG_HEIGHT);
    EXPECT_FALSE(res);
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: IsOutSizeValidTest001 end";
}

/**
 * @tc.name: IsOutSizeValidTest002
 * @tc.desc: Test IsOutSizeValid when height is not equal to jpgheight
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderYuvTest, IsOutSizeValidTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: IsOutSizeValidTest002 start";
    JpegDecoderYuv decoder;
    decoder.decodeParameter_.jpgwidth_ = TEST_JPEG_WIDTH;
    decoder.decodeParameter_.jpgheight_ = TEST_JPEG_HEIGHT;
    bool res = decoder.IsOutSizeValid(TEST_JPEG_WIDTH, TEST_INVALID_HEIGHT);
    EXPECT_FALSE(res);
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: IsOutSizeValidTest002 end";
}

/**
 * @tc.name: DecodeFrom420To420Test001
 * @tc.desc: Test DecodeFrom420To420 when width and height is zero and size is not same as jpg size
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderYuvTest, DecodeFrom420To420Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: DecodeFrom420To420Test001 start";
    JpegDecoderYuv decoder;
    decoder.decodeParameter_.yuvBufferSize_ = TEST_YUV_BUFFER_SIZE_SMALL;
    DecodeContext context;
    tjhandle dehandle = nullptr;
    uint32_t width = 0;
    uint32_t height = 0;
    int ret = decoder.DecodeFrom420To420(context, dehandle, width, height);
    EXPECT_EQ(ret, JpegYuvDecodeError_MemoryNotEnoughToSaveResult);
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: DecodeFrom420To420Test001 end";
}

/**
 * @tc.name: DecodeFrom420To420Test002
 * @tc.desc: Test DecodeFrom420To420 expect return JpegYuvDecodeError_DecodeFailed
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderYuvTest, DecodeFrom420To420Test002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: DecodeFrom420To420Test002 start";
    JpegDecoderYuv decoder;
    decoder.decodeParameter_.yuvBufferSize_ = TEST_YUV_BUFFER_SIZE_420_STANDARD;
    decoder.decodeParameter_.outfmt_ = JpegYuvFmt::OutFmt_NV12;
    DecodeContext context;
    tjhandle dehandle = nullptr;
    uint32_t width = TEST_JPEG_WIDTH;
    uint32_t height = TEST_JPEG_WIDTH;
    int ret = decoder.DecodeFrom420To420(context, dehandle, width, height);
    EXPECT_EQ(ret, JpegYuvDecodeError_DecodeFailed);
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: DecodeFrom420To420Test002 end";
}

/**
 * @tc.name: ValidateParameterTest001
 * @tc.desc: Test ValidateParameter when planeWidth is zero
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderYuvTest, ValidateParameterTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: ValidateParameterTest001 start";
    JpegDecoderYuv decoder;
    ConverterPair converter { DummyTo420, DummyToNV21 };
    YuvPlaneInfo srcPlaneInfo {};
    srcPlaneInfo.imageWidth = TEST_JPEG_WIDTH;
    srcPlaneInfo.imageHeight = TEST_JPEG_HEIGHT;
    srcPlaneInfo.planes[YCOM] = reinterpret_cast<unsigned char*>(0x1);;
    srcPlaneInfo.planes[UCOM] = reinterpret_cast<unsigned char*>(0x1);;
    srcPlaneInfo.planes[VCOM] = reinterpret_cast<unsigned char*>(0x1);;
    srcPlaneInfo.planeWidth[YCOM] = 0;
    srcPlaneInfo.planeWidth[UCOM] = TEST_JPEG_WIDTH;
    srcPlaneInfo.planeWidth[VCOM] = TEST_JPEG_WIDTH;
    bool res = decoder.ValidateParameter(srcPlaneInfo, converter);
    EXPECT_FALSE(res);

    srcPlaneInfo.planeWidth[YCOM] = TEST_JPEG_WIDTH;
    srcPlaneInfo.planeWidth[UCOM] = 0;
    srcPlaneInfo.planeWidth[VCOM] = TEST_JPEG_WIDTH;
    res = decoder.ValidateParameter(srcPlaneInfo, converter);
    EXPECT_FALSE(res);

    srcPlaneInfo.planeWidth[YCOM] = TEST_JPEG_WIDTH;
    srcPlaneInfo.planeWidth[UCOM] = TEST_JPEG_WIDTH;
    srcPlaneInfo.planeWidth[VCOM] = 0;
    res = decoder.ValidateParameter(srcPlaneInfo, converter);
    EXPECT_FALSE(res);
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: ValidateParameterTest001 end";
}

/**
 * @tc.name: ValidateParameterTest002
 * @tc.desc: Test ValidateParameter when planeHeight is zero
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderYuvTest, ValidateParameterTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: ValidateParameterTest002 start";
    JpegDecoderYuv decoder;
    ConverterPair converter { DummyTo420, DummyToNV21 };
    YuvPlaneInfo srcPlaneInfo {};
    srcPlaneInfo.imageWidth = TEST_JPEG_WIDTH;
    srcPlaneInfo.imageHeight = TEST_JPEG_HEIGHT;
    srcPlaneInfo.planes[YCOM] = reinterpret_cast<unsigned char*>(0x1);
    srcPlaneInfo.planes[UCOM] = reinterpret_cast<unsigned char*>(0x1);
    srcPlaneInfo.planes[VCOM] = reinterpret_cast<unsigned char*>(0x1);
    srcPlaneInfo.planeWidth[YCOM] = TEST_JPEG_WIDTH;
    srcPlaneInfo.planeWidth[UCOM] = TEST_JPEG_WIDTH;
    srcPlaneInfo.planeWidth[VCOM] = TEST_JPEG_WIDTH;
    srcPlaneInfo.planeHeight[YCOM] = 0;
    srcPlaneInfo.planeHeight[UCOM] = TEST_JPEG_HEIGHT;
    srcPlaneInfo.planeHeight[VCOM] = TEST_JPEG_HEIGHT;
    bool res = decoder.ValidateParameter(srcPlaneInfo, converter);
    EXPECT_FALSE(res);

    srcPlaneInfo.planeHeight[YCOM] = TEST_JPEG_HEIGHT;
    srcPlaneInfo.planeHeight[UCOM] = 0;
    srcPlaneInfo.planeHeight[VCOM] = TEST_JPEG_HEIGHT;
    res = decoder.ValidateParameter(srcPlaneInfo, converter);
    EXPECT_FALSE(res);

    srcPlaneInfo.planeHeight[YCOM] = TEST_JPEG_HEIGHT;
    srcPlaneInfo.planeHeight[UCOM] = TEST_JPEG_HEIGHT;
    srcPlaneInfo.planeHeight[VCOM] = 0;
    res = decoder.ValidateParameter(srcPlaneInfo, converter);
    EXPECT_FALSE(res);
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: ValidateParameterTest002 end";
}

/**
 * @tc.name: ValidateParameterTest003
 * @tc.desc: Test ValidateParameter when yuvBufferSize is small than outSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderYuvTest, ValidateParameterTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: ValidateParameterTest003 start";
    JpegDecoderYuv decoder;
    ConverterPair converter { DummyTo420, DummyToNV21 };
    YuvPlaneInfo srcPlaneInfo {};
    srcPlaneInfo.imageWidth = TEST_JPEG_WIDTH;
    srcPlaneInfo.imageHeight = TEST_JPEG_HEIGHT;
    srcPlaneInfo.planes[YCOM] = reinterpret_cast<unsigned char*>(0x1);
    srcPlaneInfo.planes[UCOM] = reinterpret_cast<unsigned char*>(0x1);
    srcPlaneInfo.planes[VCOM] = reinterpret_cast<unsigned char*>(0x1);
    srcPlaneInfo.planeWidth[YCOM] = TEST_JPEG_WIDTH;
    srcPlaneInfo.planeWidth[UCOM] = TEST_JPEG_WIDTH;
    srcPlaneInfo.planeWidth[VCOM] = TEST_JPEG_WIDTH;
    srcPlaneInfo.planeHeight[YCOM] = TEST_JPEG_HEIGHT;
    srcPlaneInfo.planeHeight[UCOM] = TEST_JPEG_HEIGHT;
    srcPlaneInfo.planeHeight[VCOM] = TEST_JPEG_HEIGHT;
    decoder.decodeParameter_.yuvBufferSize_ = TEST_YUV_BUFFER_SIZE_SMALL;
    bool res = decoder.ValidateParameter(srcPlaneInfo, converter);
    EXPECT_FALSE(res);
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: ValidateParameterTest003 end";
}

/**
 * @tc.name: ConvertFromGrayTest001
 * @tc.desc: Test ConvertFromGray when yuvBufferSize is small than outSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderYuvTest, ConvertFromGrayTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: ConvertFromGrayTest001 start";
    JpegDecoderYuv decoder;
    YuvPlaneInfo srcPlaneInfo {};
    srcPlaneInfo.planes[YCOM] = reinterpret_cast<unsigned char*>(0x1);
    srcPlaneInfo.imageWidth = TEST_JPEG_WIDTH;
    srcPlaneInfo.imageHeight = TEST_JPEG_HEIGHT;
    srcPlaneInfo.planeWidth[YCOM] = TEST_JPEG_WIDTH;
    srcPlaneInfo.planeHeight[YCOM] = TEST_JPEG_HEIGHT;
    DecodeContext context {};
    decoder.decodeParameter_.yuvBufferSize_ = TEST_YUV_BUFFER_SIZE_SMALL;
    int res = decoder.ConvertFromGray(srcPlaneInfo, context);
    EXPECT_EQ(res, JpegYuvDecodeError_MemoryNotEnoughToSaveResult);
    GTEST_LOG_(INFO) << "JpegDecoderYuvTest: ConvertFromGrayTest001 end";
}
}
}
