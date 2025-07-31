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

#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>

#define protected public
#include "abs_image_decoder.h"
#include "jpeg_decoder_yuv.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::ImagePlugin;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPG_PATH = "/data/local/tmp/image/";
#define TREE_ORIGINAL_WIDTH 480
#define TREE_ORIGINAL_HEIGHT 360
#define ODDTREE_ORIGINAL_WIDTH 481
#define ODDTREE_ORIGINAL_HEIGHT 361
#define YUV_BUFF_SIZE 20
#define JPG_WIDTH 800
#define JPG_HEIGHT 600
#define OUT_WIDTH 1024
#define OUT_HEIGHT 768
#define PLANE_SIZE 240000
class JpgYuvDecoderTest : public testing::Test {
public:
    JpgYuvDecoderTest() {}
    ~JpgYuvDecoderTest() {}

    bool ReadImageData(std::string jpgpath, uint8_t*& jpegBuffer, uint32_t& jpegBufferSize);
    void DecodeToYUV(std::string srcjpg, int width, int height, JpegYuvFmt outfmt);
};

bool JpgYuvDecoderTest::ReadImageData(std::string jpgpath, uint8_t*& jpegBuffer, uint32_t& jpegBufferSize)
{
    FILE* jpgFile = fopen(jpgpath.c_str(), "rb");
    if (jpgFile == nullptr) {
        return false;
    }
    int ret = fseek(jpgFile, 0, SEEK_END);
    if (ret != 0) {
        fclose(jpgFile);
        return false;
    }
    jpegBufferSize = static_cast<int>(ftell(jpgFile));
    ret = fseek(jpgFile, 0, SEEK_SET);
    if (ret != 0) {
        fclose(jpgFile);
        return false;
    }
    if (jpegBufferSize == 0 || jpegBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        fclose(jpgFile);
        return false;
    } else {
        jpegBuffer = new uint8_t[jpegBufferSize];
    }
    if (jpegBuffer == nullptr) {
        fclose(jpgFile);
        return false;
    }
    uint32_t readSize = fread(jpegBuffer, 1, jpegBufferSize, jpgFile);
    if (readSize == 0) {
        delete[] jpegBuffer;
        jpegBuffer = nullptr;
        fclose(jpgFile);
        return false;
    }
    jpegBufferSize = readSize;

    ret = fclose(jpgFile);
    if (ret != 0) {
        delete[] jpegBuffer;
        jpegBuffer = nullptr;
        return false;
    }
    return true;
}

void JpgYuvDecoderTest::DecodeToYUV(std::string srcjpg, int width, int height, JpegYuvFmt outfmt)
{
    std::string jpgpath = IMAGE_INPUT_JPG_PATH;
    jpgpath.append(srcjpg);
    uint32_t jpegBufferSize = 0;
    uint8_t* jpegBuffer = nullptr;
    bool readret = ReadImageData(jpgpath, jpegBuffer, jpegBufferSize);
    ASSERT_TRUE(readret);
    ASSERT_NE(jpegBufferSize, 0);
    ASSERT_NE(jpegBuffer, nullptr);

    uint32_t yuvBufferSize = JpegDecoderYuv::GetYuvOutSize(width, height);
    ASSERT_NE(yuvBufferSize, 0);
    if (yuvBufferSize == 0 || yuvBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        ASSERT_TRUE(false);
        return;
    }
    uint8_t* yuvBuffer = new uint8_t[yuvBufferSize];
    if (yuvBuffer == nullptr) {
        ASSERT_TRUE(false);
        return;
    }
    std::unique_ptr<JpegDecoderYuv> decoderPtr = std::make_unique<JpegDecoderYuv>();
    JpegDecoderYuvParameter para = { 0, 0, jpegBuffer, jpegBufferSize, yuvBuffer, yuvBufferSize,
        outfmt, width, height };
    DecodeContext context;
    int ret = decoderPtr->DoDecode(context, para);
    ASSERT_EQ(ret, SUCCESS);
    ASSERT_NE(context.yuvInfo.imageSize.width, 0);
    ASSERT_NE(context.yuvInfo.imageSize.height, 0);
    ASSERT_NE(context.yuvInfo.yWidth, 0);
    ASSERT_NE(context.yuvInfo.yHeight, 0);
    ASSERT_NE(context.yuvInfo.uvWidth, 0);
    ASSERT_NE(context.yuvInfo.uvHeight, 0);
    if (outfmt == JpegYuvFmt::OutFmt_YU12 || outfmt == JpegYuvFmt::OutFmt_YV12) {
        ASSERT_NE(context.yuvInfo.yStride, 0);
        ASSERT_NE(context.yuvInfo.uStride, 0);
        ASSERT_NE(context.yuvInfo.vStride, 0);
    } else {
        ASSERT_NE(context.yuvInfo.yStride, 0);
        ASSERT_NE(context.yuvInfo.uvStride, 0);
    }
    delete[] yuvBuffer;
    delete[] jpegBuffer;
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest001, TestSize.Level3)
{
    int32_t jpegwidth = 480;
    int32_t jpegheight = 360;
    int32_t width = jpegwidth;
    int32_t height = jpegheight;
    bool ret = JpegDecoderYuv::GetScaledSize(jpegwidth, jpegheight, width, height);
    ASSERT_EQ(ret, true);

    ret = JpegDecoderYuv::GetScaledSize(0, jpegheight, width, height);
    ASSERT_EQ(ret, false);
    ret = JpegDecoderYuv::GetScaledSize(jpegwidth, 0, width, height);
    ASSERT_EQ(ret, false);

    width = 0;
    height = jpegheight;
    ret = JpegDecoderYuv::GetScaledSize(jpegwidth, jpegheight, width, height);
    ASSERT_EQ(ret, true);
    width = jpegwidth;
    height = 0;
    ret = JpegDecoderYuv::GetScaledSize(jpegwidth, jpegheight, width, height);
    ASSERT_EQ(ret, true);

    int testScale = 4;
    width = jpegwidth * testScale;
    height = jpegheight * testScale;
    ret = JpegDecoderYuv::GetScaledSize(jpegwidth, jpegheight, width, height);
    ASSERT_EQ(ret, true);
    width = jpegwidth / testScale;
    height = jpegheight / testScale;
    ret = JpegDecoderYuv::GetScaledSize(jpegwidth, jpegheight, width, height);
    ASSERT_EQ(ret, true);

    int offset = 11;
    width = jpegwidth + offset;
    height = jpegheight + offset;
    ret = JpegDecoderYuv::GetScaledSize(jpegwidth, jpegheight, width, height);
    ASSERT_EQ(ret, true);
    width = jpegwidth - offset;
    height = jpegheight - offset;
    ret = JpegDecoderYuv::GetScaledSize(jpegwidth, jpegheight, width, height);
    ASSERT_EQ(ret, true);
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest002, TestSize.Level3)
{
    JpegYuvFmt outfmtList[] = { JpegYuvFmt::OutFmt_YU12, JpegYuvFmt::OutFmt_YV12,
        JpegYuvFmt::OutFmt_NV12, JpegYuvFmt::OutFmt_NV21};
    for (uint32_t j = 0; j < sizeof(outfmtList) / sizeof(JpegYuvFmt); j++) {
        DecodeToYUV("test-tree-444.jpg", TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT, outfmtList[j]);
    }
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest003, TestSize.Level3)
{
    JpegYuvFmt outfmtList[] = { JpegYuvFmt::OutFmt_YU12, JpegYuvFmt::OutFmt_YV12,
        JpegYuvFmt::OutFmt_NV12, JpegYuvFmt::OutFmt_NV21};
    for (uint32_t j = 0; j < sizeof(outfmtList) / sizeof(JpegYuvFmt); j++) {
        DecodeToYUV("test-tree-422.jpg", TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT, outfmtList[j]);
    }
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest004, TestSize.Level3)
{
    JpegYuvFmt outfmtList[] = { JpegYuvFmt::OutFmt_YU12, JpegYuvFmt::OutFmt_YV12,
        JpegYuvFmt::OutFmt_NV12, JpegYuvFmt::OutFmt_NV21};
    for (uint32_t j = 0; j < sizeof(outfmtList) / sizeof(JpegYuvFmt); j++) {
        DecodeToYUV("test-tree-420.jpg", TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT, outfmtList[j]);
    }
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest005, TestSize.Level3)
{
    JpegYuvFmt outfmtList[] = { JpegYuvFmt::OutFmt_YU12, JpegYuvFmt::OutFmt_YV12,
        JpegYuvFmt::OutFmt_NV12, JpegYuvFmt::OutFmt_NV21};
    for (uint32_t j = 0; j < sizeof(outfmtList) / sizeof(JpegYuvFmt); j++) {
        DecodeToYUV("test-tree-400.jpg", TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT, outfmtList[j]);
    }
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest006, TestSize.Level3)
{
    JpegYuvFmt outfmtList[] = { JpegYuvFmt::OutFmt_YU12, JpegYuvFmt::OutFmt_YV12,
        JpegYuvFmt::OutFmt_NV12, JpegYuvFmt::OutFmt_NV21};
    for (uint32_t j = 0; j < sizeof(outfmtList) / sizeof(JpegYuvFmt); j++) {
        DecodeToYUV("test-tree-440.jpg", TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT, outfmtList[j]);
    }
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest007, TestSize.Level3)
{
    JpegYuvFmt outfmtList[] = { JpegYuvFmt::OutFmt_YU12, JpegYuvFmt::OutFmt_YV12,
        JpegYuvFmt::OutFmt_NV12, JpegYuvFmt::OutFmt_NV21};
    for (uint32_t j = 0; j < sizeof(outfmtList) / sizeof(JpegYuvFmt); j++) {
        DecodeToYUV("test-tree-411.jpg", TREE_ORIGINAL_WIDTH, TREE_ORIGINAL_HEIGHT, outfmtList[j]);
    }
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest008, TestSize.Level3)
{
    JpegYuvFmt outfmtList[] = { JpegYuvFmt::OutFmt_YU12, JpegYuvFmt::OutFmt_YV12,
        JpegYuvFmt::OutFmt_NV12, JpegYuvFmt::OutFmt_NV21};
    for (uint32_t j = 0; j < sizeof(outfmtList) / sizeof(JpegYuvFmt); j++) {
        DecodeToYUV("test-treeodd-444.jpg", ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, outfmtList[j]);
    }
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest009, TestSize.Level3)
{
    JpegYuvFmt outfmtList[] = { JpegYuvFmt::OutFmt_YU12, JpegYuvFmt::OutFmt_YV12,
        JpegYuvFmt::OutFmt_NV12, JpegYuvFmt::OutFmt_NV21};
    for (uint32_t j = 0; j < sizeof(outfmtList) / sizeof(JpegYuvFmt); j++) {
        DecodeToYUV("test-treeodd-422.jpg", ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, outfmtList[j]);
    }
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest010, TestSize.Level3)
{
    JpegYuvFmt outfmtList[] = { JpegYuvFmt::OutFmt_YU12, JpegYuvFmt::OutFmt_YV12,
        JpegYuvFmt::OutFmt_NV12, JpegYuvFmt::OutFmt_NV21};
    for (uint32_t j = 0; j < sizeof(outfmtList) / sizeof(JpegYuvFmt); j++) {
        DecodeToYUV("test-treeodd-420.jpg", ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, outfmtList[j]);
    }
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest011, TestSize.Level3)
{
    JpegYuvFmt outfmtList[] = { JpegYuvFmt::OutFmt_YU12, JpegYuvFmt::OutFmt_YV12,
        JpegYuvFmt::OutFmt_NV12, JpegYuvFmt::OutFmt_NV21};
    for (uint32_t j = 0; j < sizeof(outfmtList) / sizeof(JpegYuvFmt); j++) {
        DecodeToYUV("test-treeodd-400.jpg", ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, outfmtList[j]);
    }
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest012, TestSize.Level3)
{
    JpegYuvFmt outfmtList[] = { JpegYuvFmt::OutFmt_YU12, JpegYuvFmt::OutFmt_YV12,
        JpegYuvFmt::OutFmt_NV12, JpegYuvFmt::OutFmt_NV21};
    for (uint32_t j = 0; j < sizeof(outfmtList) / sizeof(JpegYuvFmt); j++) {
        DecodeToYUV("test-treeodd-440.jpg", ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, outfmtList[j]);
    }
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest013, TestSize.Level3)
{
    JpegYuvFmt outfmtList[] = { JpegYuvFmt::OutFmt_YU12, JpegYuvFmt::OutFmt_YV12,
        JpegYuvFmt::OutFmt_NV12, JpegYuvFmt::OutFmt_NV21};
    for (uint32_t j = 0; j < sizeof(outfmtList) / sizeof(JpegYuvFmt); j++) {
        DecodeToYUV("test-treeodd-411.jpg", ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, outfmtList[j]);
    }
}

HWTEST_F(JpgYuvDecoderTest, JpgYuvDecoderTest014, TestSize.Level3)
{
    int32_t jpegwidth = 480;
    int32_t jpegheight = 360;
    float maxScale = 2.5;
    float minScale = 0.05;
    float step = 0.01;
    for (float scaleFactor = maxScale; scaleFactor > minScale; scaleFactor -= step) {
        int32_t width = jpegwidth * scaleFactor;
        int32_t height = jpegheight * scaleFactor;
        bool ret = JpegDecoderYuv::GetScaledSize(jpegwidth, jpegheight, width, height);
        ASSERT_EQ(ret, true);
        DecodeToYUV("test-tree-444.jpg", width, height, JpegYuvFmt::OutFmt_NV21);
    }
}

/**
 * @tc.name: IsSupportedSubSample001
 * @tc.desc: test the IsSupportedSubSample of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, IsSupportedSubSample001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: IsSupportedSubSample001 start";
    JpegDecoderYuv jpegDecoderYuv;
    int jpegSubsamp = 10;
    bool ret = jpegDecoderYuv.IsSupportedSubSample(jpegSubsamp);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: IsSupportedSubSample001 end";
}

/**
 * @tc.name: GetScaledFactor001
 * @tc.desc: test the GetScaledFactor of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, GetScaledFactor001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: GetScaledFactor001 start";
    JpegDecoderYuv jpegDecoderYuv;
    uint32_t jpgwidth = 0;
    uint32_t jpgheight = 0;
    uint32_t width = 1;
    uint32_t height = 1;
    tjscalingfactor factor = jpegDecoderYuv.GetScaledFactor(jpgwidth, jpgheight, width, height);
    ASSERT_EQ(factor.num, 1);
    ASSERT_EQ(factor.denom, 1);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: GetScaledFactor001 end";
}

/**
 * @tc.name: GetScaledFactor002
 * @tc.desc: test the GetScaledFactor of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, GetScaledFactor002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: GetScaledFactor002 start";
    JpegDecoderYuv jpegDecoderYuv;
    uint32_t jpgwidth = 1;
    uint32_t jpgheight = 1;
    uint32_t width = 0;
    uint32_t height = 0;
    tjscalingfactor factor = jpegDecoderYuv.GetScaledFactor(jpgwidth, jpgheight, width, height);
    ASSERT_EQ(factor.num, 1);
    ASSERT_EQ(factor.denom, 1);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: GetScaledFactor002 end";
}

/**
 * @tc.name: Get420OutPlaneWidth001
 * @tc.desc: test the Get420OutPlaneWidth of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, Get420OutPlaneWidth001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: Get420OutPlaneWidth001 start";
    JpegDecoderYuv jpegDecoderYuv;
    YuvComponentIndex com = YuvComponentIndex::YCOM;
    int imageWidth = 0;
    uint32_t ret = jpegDecoderYuv.Get420OutPlaneWidth(com, imageWidth);
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: Get420OutPlaneWidth001 end";
}

/**
 * @tc.name: Get420OutPlaneHeight001
 * @tc.desc: test the Get420OutPlaneHeight of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, Get420OutPlaneHeight001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: Get420OutPlaneHeight001 start";
    JpegDecoderYuv jpegDecoderYuv;
    YuvComponentIndex com = YuvComponentIndex::YCOM;
    int imageHeight = 0;
    uint32_t ret = jpegDecoderYuv.Get420OutPlaneHeight(com, imageHeight);
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: Get420OutPlaneHeight001 end";
}

/**
 * @tc.name: Get420OutPlaneSize001
 * @tc.desc: test the Get420OutPlaneSize of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, Get420OutPlaneSize001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: Get420OutPlaneSize001 start";
    JpegDecoderYuv jpegDecoderYuv;
    YuvComponentIndex com = YuvComponentIndex::YCOM;
    int imageWidth = 0;
    int imageHeight = 0;
    uint32_t ret = jpegDecoderYuv.Get420OutPlaneSize(com, imageWidth, imageHeight);
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: Get420OutPlaneSize001 end";
}

/**
 * @tc.name: GetYuvOutSize001
 * @tc.desc: test the GetYuvOutSize of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, GetYuvOutSize001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: GetYuvOutSize001 start";
    JpegDecoderYuv jpegDecoderYuv;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t ret = jpegDecoderYuv.GetYuvOutSize(width, height);
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: GetYuvOutSize001 end";
}

/**
 * @tc.name: GetJpegDecompressedYuvSize001
 * @tc.desc: test the GetJpegDecompressedYuvSize of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, GetJpegDecompressedYuvSize001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: GetJpegDecompressedYuvSize001 start";
    JpegDecoderYuv jpegDecoderYuv;
    uint32_t width = 0;
    uint32_t height = 0;
    int subsample = 0;
    uint32_t ret = jpegDecoderYuv.GetJpegDecompressedYuvSize(width, height, subsample);
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: GetJpegDecompressedYuvSize001 end";
}

/**
 * @tc.name: InitYuvDataOutInfoTo420001
 * @tc.desc: test the InitYuvDataOutInfoTo420 of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, InitYuvDataOutInfoTo420001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: InitYuvDataOutInfoTo420001 start";
    JpegDecoderYuv jpegDecoderYuv;
    uint32_t width = 0;
    uint32_t height = 0;
    YUVDataInfo info;
    info.imageSize.width = 1;
    info.imageSize.height = 1;
    JpegYuvFmt fmt = JpegYuvFmt::OutFmt_YU12;
    jpegDecoderYuv.InitYuvDataOutInfoTo420(width, height, info, fmt);
    ASSERT_EQ(info.imageSize.width, 1);
    ASSERT_EQ(info.imageSize.height, 1);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: InitYuvDataOutInfoTo420001 end";
}

/**
 * @tc.name: InitYuvDataOutInfoTo420NV001
 * @tc.desc: test the InitYuvDataOutInfoTo420NV of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, InitYuvDataOutInfoTo420NV001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: InitYuvDataOutInfoTo420NV001 start";
    JpegDecoderYuv jpegDecoderYuv;
    uint32_t width = 0;
    uint32_t height = 0;
    YUVDataInfo info;
    info.imageSize.width = 1;
    info.imageSize.height = 1;
    jpegDecoderYuv.InitYuvDataOutInfoTo420NV(width, height, info);
    ASSERT_EQ(info.imageSize.width, 1);
    ASSERT_EQ(info.imageSize.height, 1);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: InitYuvDataOutInfoTo420NV001 end";
}

/**
 * @tc.name: InitPlaneOutInfoTo420001
 * @tc.desc: test the InitPlaneOutInfoTo420 of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, InitPlaneOutInfoTo420001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: InitPlaneOutInfoTo420001 start";
    JpegDecoderYuv jpegDecoderYuv;
    uint32_t width = 0;
    uint32_t height = 0;
    YuvPlaneInfo info;
    info.imageWidth = 1;
    info.imageHeight = 1;
    jpegDecoderYuv.InitPlaneOutInfoTo420(width, height, info);
    ASSERT_EQ(info.imageWidth, 1);
    ASSERT_EQ(info.imageHeight, 1);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: InitPlaneOutInfoTo420001 end";
}

/**
 * @tc.name: InitPlaneOutInfoTo420NV001
 * @tc.desc: test the InitPlaneOutInfoTo420NV of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, InitPlaneOutInfoTo420NV001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: InitPlaneOutInfoTo420NV001 start";
    JpegDecoderYuv jpegDecoderYuv;
    uint32_t width = 0;
    uint32_t height = 0;
    YuvPlaneInfo info;
    info.imageWidth = 1;
    info.imageHeight = 1;
    jpegDecoderYuv.InitPlaneOutInfoTo420NV(width, height, info);
    ASSERT_EQ(info.imageWidth, 1);
    ASSERT_EQ(info.imageHeight, 1);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: InitPlaneOutInfoTo420NV001 end";
}

/**
 * @tc.name: DecodeHeader001
 * @tc.desc: test the DecodeHeader of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, DecodeHeader001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: DecodeHeader001 start";
    JpegDecoderYuv jpegDecoderYuv;
    tjhandle dehandle = nullptr;
    int retSubsamp = 0;
    int ret = jpegDecoderYuv.DecodeHeader(dehandle, retSubsamp);
    ASSERT_EQ(ret, JpegYuvDecodeError_DecodeFailed);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: DecodeHeader001 end";
}

/**
 * @tc.name: ValidateParameter001
 * @tc.desc: test the ValidateParameter of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, ValidateParameter001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ValidateParameter001 start";
    JpegDecoderYuv jpegDecoderYuv;
    YuvPlaneInfo srcPlaneInfo;
    ConverterPair converter;
    bool ret = jpegDecoderYuv.ValidateParameter(srcPlaneInfo, converter);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ValidateParameter001 end";
}

/**
 * @tc.name: ValidateParameter002
 * @tc.desc: test the ValidateParameter of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, ValidateParameter002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ValidateParameter002 start";
    JpegDecoderYuv jpegDecoderYuv;
    YuvPlaneInfo srcPlaneInfo;
    unsigned char num = 10;
    srcPlaneInfo.planes[YCOM] = &num;
    srcPlaneInfo.planes[UCOM] = &num;
    srcPlaneInfo.planes[VCOM] = &num;
    srcPlaneInfo.imageWidth = 0;
    srcPlaneInfo.imageHeight = 0;
    ConverterPair converter;
    bool ret = jpegDecoderYuv.ValidateParameter(srcPlaneInfo, converter);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ValidateParameter002 end";
}

/**
 * @tc.name: ValidateParameter003
 * @tc.desc: test the ValidateParameter of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, ValidateParameter003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ValidateParameter003 start";
    JpegDecoderYuv jpegDecoderYuv;
    YuvPlaneInfo srcPlaneInfo;
    unsigned char num = 10;
    srcPlaneInfo.planes[YCOM] = &num;
    srcPlaneInfo.planes[UCOM] = &num;
    srcPlaneInfo.planes[VCOM] = &num;
    srcPlaneInfo.imageWidth = 1;
    srcPlaneInfo.imageHeight = 1;
    ConverterPair converter;
    bool ret = jpegDecoderYuv.ValidateParameter(srcPlaneInfo, converter);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ValidateParameter003 end";
}

/**
 * @tc.name: ConvertFromGray001
 * @tc.desc: test the ConvertFromGray of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, ConvertFromGray001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ConvertFromGray001 start";
    JpegDecoderYuv jpegDecoderYuv;
    YuvPlaneInfo srcPlaneInfo;
    int ret = jpegDecoderYuv.ConvertFromGray(srcPlaneInfo);
    ASSERT_EQ(ret, JpegYuvDecodeError_ConvertError);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ConvertFromGray001 end";
}

/**
 * @tc.name: ConvertFromGray002
 * @tc.desc: test the ConvertFromGray of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, ConvertFromGray002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ConvertFromGray002 start";
    JpegDecoderYuv jpegDecoderYuv;
    YuvPlaneInfo srcPlaneInfo;
    unsigned char num = 10;
    srcPlaneInfo.planes[YCOM] = &num;
    srcPlaneInfo.imageWidth = 0;
    srcPlaneInfo.imageHeight = 0;
    int ret = jpegDecoderYuv.ConvertFromGray(srcPlaneInfo);
    ASSERT_EQ(ret, JpegYuvDecodeError_ConvertError);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ConvertFromGray002 end";
}

/**
 * @tc.name: ConvertFromGray003
 * @tc.desc: test the ConvertFromGray of JpegDecoderYuv
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, ConvertFromGray003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ConvertFromGray003 start";
    JpegDecoderYuv jpegDecoderYuv;
    YuvPlaneInfo srcPlaneInfo;
    unsigned char num = 10;
    srcPlaneInfo.planes[YCOM] = &num;
    srcPlaneInfo.imageWidth = 1;
    srcPlaneInfo.imageHeight = 1;
    srcPlaneInfo.planeWidth[YCOM] = 0;
    srcPlaneInfo.planeHeight[YCOM] = 0;
    int ret = jpegDecoderYuv.ConvertFromGray(srcPlaneInfo);
    ASSERT_EQ(ret, JpegYuvDecodeError_ConvertError);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ConvertFromGray003 end";
}

/**
 * @tc.name: Get420OutPlaneSize002
 * @tc.desc: Verify that Get420OutPlaneSize returns 0 when the input parameters are invalid or unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, Get420OutPlaneSize002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: Get420OutPlaneSize002 start";
    JpegDecoderYuv jpegDecoderYuv;
    YuvComponentIndex com = YuvComponentIndex::UVCOM;
    int imageWidth = JPG_WIDTH;
    int imageHeight = JPG_HEIGHT;
    uint32_t ret = jpegDecoderYuv.Get420OutPlaneSize(com, imageWidth, imageHeight);
    EXPECT_EQ(ret, PLANE_SIZE);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: Get420OutPlaneSize002 end";
}

/**
 * @tc.name: DoDecode001
 * @tc.desc: Verify that DoDecode returns JpegYuvDecodeError_InvalidParameter when the input parameters are invalid.
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, DoDecode001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: DoDecode001 start";
    JpegDecoderYuv jpegDecoderYuv;
    JpegDecoderYuvParameter para = { 0, 0, nullptr, 0, nullptr, 0, JpegYuvFmt::OutFmt_YU12, 0, 0 };
    DecodeContext context;
    int ret = jpegDecoderYuv.DoDecode(context, para);
    EXPECT_EQ(ret, JpegYuvDecodeError_InvalidParameter);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: DoDecode001 end";
}

/**
 * @tc.name: DoDecode002
 * @tc.desc: Verify that DoDecode returns JpegYuvDecodeError_InvalidParameter
 *           when the input JPEG buffer is valid but other parameters are invalid.
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, DoDecode002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: DoDecode002 start";
    JpegDecoderYuv jpegDecoderYuv;
    uint8_t* jpegBuffer = new uint8_t[YUV_BUFF_SIZE];
    uint8_t* yuvBuffer = new uint8_t[YUV_BUFF_SIZE];
    JpegDecoderYuvParameter para = { 0, 0, jpegBuffer, YUV_BUFF_SIZE, yuvBuffer, YUV_BUFF_SIZE,
        JpegYuvFmt::OutFmt_YU12, 0, 0 };
    DecodeContext context;
    int ret = jpegDecoderYuv.DoDecode(context, para);
    EXPECT_EQ(ret, JpegYuvDecodeError_InvalidParameter);
    delete[] yuvBuffer;
    delete[] jpegBuffer;
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: DoDecode002 end";
}

/**
 * @tc.name: ConvertFrom4xx001
 * @tc.desc: Verify that ConvertFrom4xx returns JpegYuvDecodeError_ConvertError
 *           when the input parameters are invalid.
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, ConvertFrom4xx001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ConvertFrom4xx001 start";
    YuvPlaneInfo srcPlaneInfo;
    srcPlaneInfo.imageWidth = 0;
    srcPlaneInfo.imageHeight = 0;
    srcPlaneInfo.planes[YCOM] = nullptr;
    srcPlaneInfo.planes[UCOM] = nullptr;
    srcPlaneInfo.planes[VCOM] = nullptr;

    ConverterPair converter;
    JpegDecoderYuv decoder;
    DecodeContext context;
    int ret = decoder.ConvertFrom4xx(srcPlaneInfo, converter, context);

    EXPECT_EQ(ret, JpegYuvDecodeError_ConvertError);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: ConvertFrom4xx001 end";
}

/**
 * @tc.name: JpegYuvDataTest001
 * @tc.desc: Verify that the conversion functions return -1 when the input parameters are invalid.
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, JpegYuvDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: JpegYuvDataTest001 start";
    YuvPlaneInfo src;
    YuvPlaneInfo dst;

    int code = I444ToI420_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    code = I444ToNV21_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    code = I422ToI420_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    code = I422ToNV21_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    code = I420ToNV21_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: JpegYuvDataTest001 end";
}

/**
 * @tc.name: JpegYuvDataTest002
 * @tc.desc: Verify that the conversion functions return -1 when the input parameters are invalid.
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, JpegYuvDataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: JpegYuvDataTest002 start";
    JpegDecoderYuv jpegDecoderYuv;
    jpegDecoderYuv.LoadLibYuv();
    YuvPlaneInfo src;
    YuvPlaneInfo dst;

    int code = I444ToI420_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    code = I444ToNV21_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    code = I422ToI420_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    code = I422ToNV21_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    code = I420ToNV21_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    code = I400ToI420_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: JpegYuvDataTest002 end";
}

/**
 * @tc.name: JpegYuvDataTest003
 * @tc.desc: Verify that the conversion functions return -1 when the input parameters are invalid.
 *           Also ensure proper memory allocation and deallocation for YUV plane data.
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, JpegYuvDataTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: JpegYuvDataTest003 start";
    JpegDecoderYuv jpegDecoderYuv;
    jpegDecoderYuv.LoadLibYuv();

    YuvPlaneInfo src;
    for (int i = 0; i < YUVCOMPONENT_MAX; ++i) {
        src.strides[i] = 1;
        src.planes[i] = new unsigned char[1];
    }
    YuvPlaneInfo dst;

    int code = I440ToNV21_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    src.imageWidth = 1;
    src.imageHeight = 1;
    code = I440ToNV21_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    code = I440ToI420_wrapper(src, dst);
    EXPECT_EQ(code, -1);
    for (int i = 0; i < YUVCOMPONENT_MAX; ++i) {
        delete[] src.planes[i];
        src.planes[i] = nullptr;
    }
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: JpegYuvDataTest003 end";
}

/**
 * @tc.name: JpegYuvDataTest004
 * @tc.desc: Verify that the I400ToI420_wrapper function returns 0 when the input parameters are valid.
 * @tc.type: FUNC
 */
HWTEST_F(JpgYuvDecoderTest, JpegYuvDataTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: JpegYuvDataTest004 start";
    JpegDecoderYuv jpegDecoderYuv;
    jpegDecoderYuv.LoadLibYuv();
    YuvPlaneInfo src;
    YuvPlaneInfo dst;
    src.imageHeight = 1;
    src.imageWidth = 1;
    for (int i = 0; i < YUVCOMPONENT_MAX; ++i) {
        src.strides[i] = 1;
        src.planes[i] = new unsigned char[1];
        dst.strides[i] = 1;
        dst.planes[i] = new unsigned char[1];
    }

    int code = I400ToI420_wrapper(src, dst);
    EXPECT_EQ(code, 0);
    for (int i = 0; i < YUVCOMPONENT_MAX; ++i) {
        delete[] src.planes[i];
        delete[] dst.planes[i];
        src.planes[i] = nullptr;
        dst.planes[i] = nullptr;
    }
    GTEST_LOG_(INFO) << "JpgYuvDecoderTest: JpegYuvDataTest004 end";
}

}
}