/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#define private public
#include <gtest/gtest.h>
#include "buffer_source_stream.h"
#include "image_packer.h"
#include "jpeg_decoder.h"
#include "mock_data_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
static constexpr size_t STREAM_SIZE = 1000;
class JpegDecoderTest : public testing::Test {
public:
    JpegDecoderTest() {}
    ~JpegDecoderTest() {}
};

/**
 * @tc.name: SetSourceTest001
 * @tc.desc: Test of SetSource
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetSourceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetSourceTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    bool result = (jpegDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetSourceTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest001
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetDecodeOptionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = 1;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ASSERT_NE(streamPtr, nullptr);
    jpegDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    PlImageInfo info;
    // goto : return ret
    uint32_t result = jpegDecoder->SetDecodeOptions(0, opts, info);
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest002
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetDecodeOptionsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t result = jpegDecoder->SetDecodeOptions(JPEG_IMAGE_NUM, opts, info);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest002 end";
}

/**
 * @tc.name: SetDecodeOptionsTest003
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetDecodeOptionsTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    jpegDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t result = jpegDecoder->SetDecodeOptions(1, opts, info);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest003 end";
}

/**
 * @tc.name: SetDecodeOptionsTest004
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetDecodeOptionsTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest004 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t result = jpegDecoder->SetDecodeOptions(0, opts, info);
    // goto DecoderHeader return ERR_IMAGE_SOURCE_DATA_INCOMPLETE
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest004 end";
}

/**
 * @tc.name: GetImageSizeTest001
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImageSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = 1;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ASSERT_NE(streamPtr, nullptr);
    jpegDecoder->SetSource(*streamPtr.release());
    ImagePlugin::Size plSize;
    uint32_t result = jpegDecoder->GetImageSize(0, plSize);
    // goto DecodeHeader return ERR_IMAGE_SOURCE_DATA_INCOMPLETE
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest001 end";
}

/**
 * @tc.name: GetImageSizeTest002
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImageSizeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ImagePlugin::Size plSize;
    uint32_t result = jpegDecoder->GetImageSize(0, plSize);
    // goto DecodeHeader return ERR_IMAGE_DECODE_ABNORMAL
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest002 end";
}

/**
 * @tc.name: GetImageSizeTest004
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImageSizeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest004 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ImagePlugin::Size plSize;
    jpegDecoder->SetSource(*streamPtr.release());
    // check input parameter, index = JPEG_IMAGE_NUM
    uint32_t result = jpegDecoder->GetImageSize(JPEG_IMAGE_NUM, plSize);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest004 end";
}

/**
 * @tc.name: DecodeTest001
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    uint32_t result = jpegDecoder->Decode(0, context);
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest001 end";
}

/**
 * @tc.name: DecodeTest002
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    uint32_t result = jpegDecoder->Decode(JPEG_IMAGE_NUM, context);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest002 end";
}

/**
 * @tc.name: GetImagePropertyIntTest003
 * @tc.desc: Test of GetImagePropertyInt
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyIntTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyIntTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = ACTUAL_IMAGE_ENCODED_FORMAT;
    int32_t value = 0;
    uint32_t result = jpegDecoder->GetImagePropertyInt(0, key, value);
    ASSERT_EQ(result, Media::ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyIntTest003 end";
}

/**
 * @tc.name: GetImageSizeTest003
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImageSizeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ImagePlugin::Size plSize;
    ErrCodeOffset(2, 0);
    jpegDecoder->GetImageSize(1, plSize);
    uint32_t ret = jpegDecoder->GetImageSize(0, plSize);
    ASSERT_EQ(ret, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest003 end";
}

/**
 * @tc.name: GetRowBytesTest001
 * @tc.desc: Test of GetRowBytes
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetRowBytesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetRowBytesTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    uint32_t ret = jpegDecoder->GetRowBytes();
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetRowBytesTest001 end";
}

/**
 * @tc.name: ResetTest001
 * @tc.desc: Test of Reset
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ResetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ResetTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    jpegDecoder->JpegDecoder::Reset();
    ASSERT_EQ(jpegDecoder->srcMgr_.inputStream, nullptr);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ResetTest001 end";
}

/**
 * @tc.name: FinishOldDecompressTest001
 * @tc.desc: Test of FinishOldDecompress
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, FinishOldDecompressTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: FinishOldDecompressTest001 start";
    jpeg_decompress_struct jpegCompressInfo;
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    jpegDecoder->decodeInfo_ = jpegCompressInfo;
    jpegDecoder->FinishOldDecompress();
    ASSERT_NE(&(jpegDecoder->decodeInfo_), nullptr);
    GTEST_LOG_(INFO) << "JpegDecoderTest: FinishOldDecompressTest001 end";
}
}
}