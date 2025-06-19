/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define private public
#include "hardware/jpeg_hw_decoder.h"
#include "mock_jpeg_hw_decode_flow.h"
#include "image_system_properties.h"
#include "media_errors.h"

namespace OHOS::Media {
using namespace testing::ext;
using namespace OHOS::ImagePlugin;
using namespace OHOS::HDI::Codec::Image::V2_1;

class JpegHwDecoderTest : public testing::Test {
public:
    static constexpr char JPEG_FORMAT[] = "image/jpeg";
    static constexpr char HEIF_FORMAT[] = "image/heif";
    static constexpr char TEST_JPEG_IMG[] = "/data/local/tmp/image/test_hw1.jpg";
};

HWTEST_F(JpegHwDecoderTest, unsupported_img_empty_format, TestSize.Level1)
{
    JpegHardwareDecoder testObj;
    Size srcImgSize = {
        .width = 8192,
        .height = 8192
    };
    bool ret = testObj.IsHardwareDecodeSupported("", srcImgSize);
    ASSERT_FALSE(ret);
}

HWTEST_F(JpegHwDecoderTest, unsupported_img_unknown_format, TestSize.Level1)
{
    JpegHardwareDecoder testObj;
    Size srcImgSize = {
        .width = 512,
        .height = 512
    };
    bool ret = testObj.IsHardwareDecodeSupported(HEIF_FORMAT, srcImgSize);
    ASSERT_FALSE(ret);
}

HWTEST_F(JpegHwDecoderTest, unsupported_img_size_too_small, TestSize.Level1)
{
    JpegHardwareDecoder testObj;
    Size srcImgSize = {
        .width = 140,
        .height = 512
    };
    bool ret = testObj.IsHardwareDecodeSupported(JPEG_FORMAT, srcImgSize);
    ASSERT_FALSE(ret);
}

HWTEST_F(JpegHwDecoderTest, unsupported_img_size_too_big, TestSize.Level1)
{
    JpegHardwareDecoder testObj;
    Size srcImgSize = {
        .width = 8192,
        .height = 8193
    };
    bool ret = testObj.IsHardwareDecodeSupported(JPEG_FORMAT, srcImgSize);
    ASSERT_FALSE(ret);
}

HWTEST_F(JpegHwDecoderTest, decode_ok, TestSize.Level1)
{
    CommandOpt opt;
    opt.width = 1280;
    opt.height = 768;
    opt.sampleSize = 1;
    opt.inputFile = TEST_JPEG_IMG;
    JpegHwDecoderFlow demo;
    bool ret = true;
    if (ImageSystemProperties::GetHardWareDecodeEnabled()) {
        ret = demo.Run(opt, false);
    }
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: IsHardwareDecodeSupportedTest001
 * @tc.desc: test the IsHardwareDecodeSupported
             when hwDecoder_ is nullptr,return false
 * @tc.type: FUNC
 */
HWTEST_F(JpegHwDecoderTest, IsHardwareDecodeSupportedTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: IsHardwareDecodeSupportedTest001 start";
    JpegHardwareDecoder jpegHardwareDecoder;
    jpegHardwareDecoder.hwDecoder_ = nullptr;
    const std::string srcImgFormat = "jpeg";
    Size srcImgSize = {1, 1};
    bool ret = jpegHardwareDecoder.IsHardwareDecodeSupported(srcImgFormat, srcImgSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: IsHardwareDecodeSupportedTest001 end";
}

/**
 * @tc.name: IsHardwareDecodeSupportedTest002
 * @tc.desc: test the IsHardwareDecodeSupported
             when hwDecoder_->GetImageCapability is empty,return false
 * @tc.type: FUNC
 */
HWTEST_F(JpegHwDecoderTest, IsHardwareDecodeSupportedTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: IsHardwareDecodeSupportedTest002 start";
    JpegHardwareDecoder jpegHardwareDecoder;
    const std::string srcImgFormat = "jpeg";
    Size srcImgSize = {1, 1};
    bool ret = jpegHardwareDecoder.IsHardwareDecodeSupported(srcImgFormat, srcImgSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: IsHardwareDecodeSupportedTest002 end";
}

/**
 * @tc.name: IsHardwareDecodeSupportedTest003
 * @tc.desc: Verify hardware decode support check returns false for empty file path, zero size, and null decoder cases.
 * @tc.type: FUNC
 */
HWTEST_F(JpegHwDecoderTest, IsHardwareDecodeSupportedTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: IsHardwareDecodeSupportedTest003 start";
    JpegHardwareDecoder jpegHardwareDecoder;
    ASSERT_NE(jpegHardwareDecoder.hwDecoder_, nullptr);
    Media::Size size = {0, 0};
    bool ret = jpegHardwareDecoder.IsHardwareDecodeSupported("", size);
    EXPECT_FALSE(ret);
    jpegHardwareDecoder.hwDecoder_ = nullptr;
    ret = jpegHardwareDecoder.IsHardwareDecodeSupported("", size);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: IsHardwareDecodeSupportedTest003 end";
}

/**
 * @tc.name: CheckInputColorFmtTest001
 * @tc.desc: test the CheckInputColorFmt
             when codec is nullptr,return false
 * @tc.type: FUNC
 */
HWTEST_F(JpegHwDecoderTest, CheckInputColorFmtTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: CheckInputColorFmtTest001 start";
    JpegHardwareDecoder jpegHardwareDecoder;
    SkCodec *codec = nullptr;
    bool ret = jpegHardwareDecoder.CheckInputColorFmt(codec);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: CheckInputColorFmtTest001 end";
}

/**
 * @tc.name: DecodeTest001
 * @tc.desc: test the Decode
             when hwDecoder_ is nullptr,return ERR_IMAGE_DECODE_ABNORMAL
 * @tc.type: FUNC
 */
HWTEST_F(JpegHwDecoderTest, DecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: DecodeTest001 start";
    JpegHardwareDecoder jpegHardwareDecoder;
    jpegHardwareDecoder.hwDecoder_ = nullptr;
    SkCodec *codec = nullptr;
    ImagePlugin::InputDataStream *srcStream = nullptr;
    Size srcImgSize = {1, 1};
    uint32_t sampleSize = 0;
    CodecImageBuffer outputBuffer;
    uint32_t ret = jpegHardwareDecoder.Decode(codec, srcStream, srcImgSize, sampleSize, outputBuffer);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_ABNORMAL);
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: DecodeTest001 end";
}

/**
 * @tc.name: DecodeTest002
 * @tc.desc: test the Decode
             when codec is nullptr,return ERR_IMAGE_DATA_UNSUPPORT
 * @tc.type: FUNC
 */
HWTEST_F(JpegHwDecoderTest, DecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: DecodeTest002 start";
    JpegHardwareDecoder jpegHardwareDecoder;
    SkCodec *codec = nullptr;
    ImagePlugin::InputDataStream *srcStream = nullptr;
    Size srcImgSize = {1, 1};
    uint32_t sampleSize = 0;
    CodecImageBuffer outputBuffer;
    uint32_t ret = jpegHardwareDecoder.Decode(codec, srcStream, srcImgSize, sampleSize, outputBuffer);
    ASSERT_EQ(ret, ERR_IMAGE_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: DecodeTest002 end";
}

/**
 * @tc.name: AssembleComponentInfoTest001
 * @tc.desc: test the AssembleComponentInfo
             when num_components is not euqal 1 or 3,return false
 * @tc.type: FUNC
 */
HWTEST_F(JpegHwDecoderTest, AssembleComponentInfoTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: AssembleComponentInfoTest001 start";
    JpegHardwareDecoder jpegHardwareDecoder;
    jpeg_decompress_struct jpegCompressInfo;
    jpegCompressInfo.num_components = 2;
    bool ret = jpegHardwareDecoder.AssembleComponentInfo(&jpegCompressInfo);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: AssembleComponentInfoTest001 end";
}

/**
 * @tc.name: JumpOverCurrentJpegMarkerTest001
 * @tc.desc: test the JumpOverCurrentJpegMarker
             when curPos + JpegMarker::MARKER_LEN > totalLen,return false
 * @tc.type: FUNC
 */
HWTEST_F(JpegHwDecoderTest, JumpOverCurrentJpegMarkerTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: JumpOverCurrentJpegMarkerTest001 start";
    JpegHardwareDecoder jpegHardwareDecoder;
    ImagePlugin::InputDataStream* srcStream = nullptr;
    unsigned int curPos = 1;
    unsigned int totalLen = 1;
    uint16_t marker = 0;
    bool ret = jpegHardwareDecoder.JumpOverCurrentJpegMarker(srcStream, curPos, totalLen, marker);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: JumpOverCurrentJpegMarkerTest001 end";
}

/**
 * @tc.name: PrepareInputDataTest001
 * @tc.desc: test the PrepareInputData
             when srcStream is nullptr,return false
 * @tc.type: FUNC
 */
HWTEST_F(JpegHwDecoderTest, PrepareInputDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: PrepareInputDataTest001 start";
    JpegHardwareDecoder jpegHardwareDecoder;
    SkCodec *codec = nullptr;
    ImagePlugin::InputDataStream *srcStream = nullptr;
    bool ret = jpegHardwareDecoder.PrepareInputData(codec, srcStream);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "JpegHwDecoderTest: PrepareInputDataTest001 end";
}
} // namespace OHOS::Media