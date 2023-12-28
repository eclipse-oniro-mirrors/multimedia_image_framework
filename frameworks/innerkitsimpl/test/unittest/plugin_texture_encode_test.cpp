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
#include <cstdlib>
#include <gtest/gtest.h>
#include "securec.h"

#include "astc_codec.h"
#include "buffer_packer_stream.h"
#include "hilog/log.h"
#include "image_compressor.h"
#include "image_source_util.h"
#include "image_system_properties.h"
#include "image_utils.h"
#include "log_tags.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImagePlugin;
namespace OHOS {
namespace Media {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";
static constexpr int32_t OUTPUT_SIZE_MAX = 200000;
class PluginTextureEncodeTest : public testing::Test {
public:
    PluginTextureEncodeTest() {}
    ~PluginTextureEncodeTest() {}
};

/**
 * @tc.name: ASTCEncode001
 * @tc.desc: Test the AstcSoftwareEncode function
 * @tc.type: FUNC
 */
HWTEST_F(PluginTextureEncodeTest, ASTCEncode001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: ASTCEncode001 start";
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *inputBuffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(inputBuffer, nullptr);
    ret = OHOS::ImageSourceUtil::ReadFileToBuffer("/data/local/tmp/image/test.jpg", inputBuffer, bufferSize);
    ASSERT_EQ(ret, true);
    uint32_t errCode = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(inputBuffer,
        bufferSize, sourceOpts, errCode);
    ASSERT_EQ(errCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t index = 0;
    DecodeOptions decodeOpts;
    errCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, decodeOpts, errCode);
    ASSERT_EQ(errCode, SUCCESS);
    Media::PixelMap *pixelMapPtr = pixelMap.get();
    ASSERT_NE(pixelMapPtr, nullptr);
    uint8_t *output = static_cast<uint8_t *>(malloc(OUTPUT_SIZE_MAX));
    ASSERT_NE(output, nullptr);
    BufferPackerStream *stream = new (std::nothrow) BufferPackerStream(output, OUTPUT_SIZE_MAX);
    ASSERT_NE(stream, nullptr);
    struct PlEncodeOptions option = { "image/astc/4*4", 100, 1 }; // quality set to 100
    AstcCodec astcEncoder;
    uint32_t setRet = astcEncoder.SetAstcEncode(stream, option, pixelMapPtr);
    ASSERT_EQ(setRet, SUCCESS);
    uint32_t astcRet = astcEncoder.ASTCEncode();
    ASSERT_EQ(astcRet, SUCCESS);
    if (inputBuffer != nullptr) {
        free(inputBuffer);
        inputBuffer = nullptr;
    }
    if (output != nullptr) {
        free(output);
        output = nullptr;
    }
    if (stream != nullptr) {
        delete stream;
        stream = nullptr;
    }
    if (pixelMapPtr != nullptr) {
        pixelMapPtr = nullptr;
    }
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: ASTCEncode001 end";
}

/**
 * @tc.name: ASTCEncode002
 * @tc.desc: Test the SetAstcEncode function
 * @tc.desc: Set outputStream to nullptr
 * @tc.type: FUNC
 */
HWTEST_F(PluginTextureEncodeTest, ASTCEncode002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: ASTCEncode002 start";
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_JPEG_PATH, buffer, bufferSize);
    ASSERT_EQ(ret, true);
    uint32_t errCode = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer,
        bufferSize, sourceOpts, errCode);
    ASSERT_EQ(errCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t index = 0;
    DecodeOptions decodeOpts;
    errCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, decodeOpts, errCode);
    ASSERT_EQ(errCode, SUCCESS);
    Media::PixelMap *pixelMapPtr = pixelMap.get();
    ASSERT_NE(pixelMapPtr, nullptr);

    BufferPackerStream *stream = nullptr;

    struct PlEncodeOptions option = { "image/astc/4*4", 100, 1 }; // quality set to 100
    AstcCodec astcEncoder;
    uint32_t setRet = astcEncoder.SetAstcEncode(stream, option, pixelMapPtr);
    ASSERT_EQ(setRet, ERROR);

    if (buffer != nullptr) {
        free(buffer);
        buffer = nullptr;
    }
    if (pixelMapPtr != nullptr) {
        pixelMapPtr = nullptr;
    }
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: ASTCEncode002 end";
}

/**
 * @tc.name: ASTCEncode003
 * @tc.desc: Test the SetAstcEncode function
 * @tc.desc: Set pixelMap to nullptr
 * @tc.type: FUNC
 */
HWTEST_F(PluginTextureEncodeTest, ASTCEncode003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: ASTCEncode003 start";
    Media::PixelMap *pixelMapPtr = nullptr;

    uint8_t *output = static_cast<uint8_t *>(malloc(OUTPUT_SIZE_MAX));
    ASSERT_NE(output, nullptr);
    BufferPackerStream *stream = new (std::nothrow) BufferPackerStream(output, OUTPUT_SIZE_MAX);
    ASSERT_NE(stream, nullptr);

    struct PlEncodeOptions option = { "image/astc/4*4", 100, 1 }; // quality set to 100
    AstcCodec astcEncoder;
    uint32_t setRet = astcEncoder.SetAstcEncode(stream, option, pixelMapPtr);
    ASSERT_EQ(setRet, ERROR);

    if (output != nullptr) {
        free(output);
        output = nullptr;
    }
    if (stream != nullptr) {
        delete stream;
        stream = nullptr;
    }
    if (pixelMapPtr != nullptr) {
        pixelMapPtr = nullptr;
    }
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: ASTCEncode003 end";
}

/**
 * @tc.name: ASTCEncode004
 * @tc.desc: AstcSoftwareEncode return error test
 * @tc.type: FUNC
 */
HWTEST_F(PluginTextureEncodeTest, ASTCEncode004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: ASTCEncode004 start";
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_JPEG_PATH, buffer, bufferSize);
    ASSERT_EQ(ret, true);
    uint32_t errCode = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer,
        bufferSize, sourceOpts, errCode);
    ASSERT_EQ(errCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t index = 0;
    DecodeOptions decodeOpts;
    errCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, decodeOpts, errCode);
    ASSERT_EQ(errCode, SUCCESS);
    Media::PixelMap *pixelMapPtr = pixelMap.get();
    ASSERT_NE(pixelMapPtr, nullptr);
    uint8_t *output = static_cast<uint8_t *>(malloc(OUTPUT_SIZE_MAX));
    ASSERT_NE(output, nullptr);
    BufferPackerStream *stream = new (std::nothrow) BufferPackerStream(output, OUTPUT_SIZE_MAX);
    ASSERT_NE(stream, nullptr);
    struct PlEncodeOptions option = { "image/astc/7*7", 100, 1 }; // quality set to 100
    AstcCodec astcEncoder;
    uint32_t setRet = astcEncoder.SetAstcEncode(stream, option, pixelMapPtr);
    ASSERT_EQ(setRet, SUCCESS);
    uint32_t astcRet = astcEncoder.ASTCEncode();
    ASSERT_EQ(astcRet, ERROR);
    if (buffer != nullptr) {
        free(buffer);
        buffer = nullptr;
    }
    if (output != nullptr) {
        free(output);
        output = nullptr;
    }
    if (stream != nullptr) {
        delete stream;
        stream = nullptr;
    }
    if (pixelMapPtr != nullptr) {
        pixelMapPtr = nullptr;
    }
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: ASTCEncode004 end";
}
} // namespace Multimedia
} // namespace OHOS