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
#include "image_compressor.h"
#include "image_source_util.h"
#include "image_system_properties.h"
#include "image_utils.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImagePlugin;
namespace OHOS {
namespace Media {
static constexpr int32_t RGBA_TEST0001_WIDTH = 256;
static constexpr int32_t RGBA_TEST0001_HEIGHT = 256;
static constexpr uint8_t RGBA_BYTES_PIXEL_LOG2 = 2;
static constexpr int32_t PIXEL_VALUE_MAX = 256;
static constexpr int32_t TEXTURE_BLOCK_BYTES = 16;
static constexpr int32_t ASTC_BLOCK_WIDTH = 4;
static constexpr int32_t ASTC_BLOCK_HEIGHT = 4;
static constexpr int32_t OUTPUT_SIZE_MAX = 200000;
static constexpr int32_t BYTES_PER_PIXEL = 4;
static constexpr int32_t RGBA_MAX_WIDTH = 8192;
static constexpr int32_t RGBA_MAX_HEIGHT = 4096;
class PluginTextureEncodeTest : public testing::Test {
public:
    PluginTextureEncodeTest() {}
    ~PluginTextureEncodeTest() {}
};

static TextureEncodeOptions SetDefaultOption()
{
    TextureEncodeOptions param;
    param.width_ = RGBA_TEST0001_WIDTH;
    param.height_ = RGBA_TEST0001_HEIGHT;
    param.stride_ = RGBA_TEST0001_WIDTH;
    param.blockX_ = ASTC_BLOCK_WIDTH;
    param.blockY_ = ASTC_BLOCK_HEIGHT;
    return param;
}

static std::unique_ptr<PixelMap> ConstructPixmap(int32_t width, int32_t height)
{
    std::unique_ptr<PixelMap> pixelMap = std::make_unique<PixelMap>();
    ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = PixelFormat::RGBA_8888;
    info.colorSpace = ColorSpace::SRGB;
    info.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    pixelMap->SetImageInfo(info);

    int32_t bytesPerPixel = BYTES_PER_PIXEL;
    int32_t rowDataSize = width * bytesPerPixel;
    uint32_t bufferSize = rowDataSize * height;
    if (bufferSize <= 0) {
        return nullptr;
    }
    void *buffer = malloc(bufferSize);
    if (buffer == nullptr) {
        return nullptr;
    }
    uint8_t *ch = static_cast<uint8_t *>(buffer);
    for (unsigned int i = 0; i < bufferSize; ++i) {
        *(ch++) = static_cast<uint8_t>(i % PIXEL_VALUE_MAX);
    }

    pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);

    return pixelMap;
}

/**
 * @tc.name: ASTCEncode001
 * @tc.desc: Test the AstcSoftwareEncode function
 * @tc.type: FUNC
 */
HWTEST_F(PluginTextureEncodeTest, ASTCEncode001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: ASTCEncode001 start";

    std::unique_ptr<PixelMap> pixelMap = ConstructPixmap(RGBA_TEST0001_WIDTH, RGBA_TEST0001_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    PixelMap *pixelMapPtr = pixelMap.get();
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

    option.quality = 20; // quality 20: HIGH_SPEED_PROFILE
    setRet = astcEncoder.SetAstcEncode(stream, option, pixelMapPtr);
    ASSERT_EQ(setRet, SUCCESS);
    astcRet = astcEncoder.ASTCEncode();
    ASSERT_EQ(astcRet, SUCCESS);

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

    std::unique_ptr<PixelMap> pixelMap = ConstructPixmap(RGBA_TEST0001_WIDTH, RGBA_TEST0001_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    Media::PixelMap *pixelMapPtr = pixelMap.get();
    ASSERT_NE(pixelMapPtr, nullptr);

    BufferPackerStream *stream = nullptr;

    struct PlEncodeOptions option = { "image/astc/4*4", 100, 1 }; // quality set to 100
    AstcCodec astcEncoder;
    uint32_t setRet = astcEncoder.SetAstcEncode(stream, option, pixelMapPtr);
    ASSERT_EQ(setRet, ERROR);

    if (pixelMapPtr != nullptr) {
        pixelMapPtr = nullptr;
    }
    if (stream != nullptr) {
        stream = nullptr;
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

    std::unique_ptr<PixelMap> pixelMap = ConstructPixmap(RGBA_TEST0001_WIDTH, RGBA_TEST0001_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
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

/**
 * @tc.name: AstcSoftwareEncode001
 * @tc.desc: Test the AstcSoftwareEncode function
 * @tc.desc: Set enableQualityCheck to true
 * @tc.type: FUNC
 */
HWTEST_F(PluginTextureEncodeTest, AstcSoftwareEncode001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcSoftwareEncode001 start";

    std::unique_ptr<PixelMap> pixelMap = ConstructPixmap(RGBA_TEST0001_WIDTH, RGBA_TEST0001_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    Media::PixelMap *pixelMapPtr = pixelMap.get();
    ASSERT_NE(pixelMapPtr, nullptr);

    uint8_t *output = static_cast<uint8_t *>(malloc(OUTPUT_SIZE_MAX));
    ASSERT_NE(output, nullptr);
    BufferPackerStream *stream = new (std::nothrow) BufferPackerStream(output, OUTPUT_SIZE_MAX);
    ASSERT_NE(stream, nullptr);

    TextureEncodeOptions param = SetDefaultOption();
    param.privateProfile_ = QualityProfile::HIGH_QUALITY_PROFILE;
    int32_t blocksNum = ((param.width_ + param.blockX_ - 1) / param.blockX_) *
        ((param.height_ + param.blockY_ - 1) / param.blockY_);
    int32_t outSize = blocksNum * TEXTURE_BLOCK_BYTES + TEXTURE_BLOCK_BYTES;

    bool enableQualityCheck = true;

    struct PlEncodeOptions option = { "image/astc/4*4", 100, 1 }; // quality set to 100
    AstcCodec astcEncoder;
    uint32_t setRet = astcEncoder.SetAstcEncode(stream, option, pixelMapPtr);
    ASSERT_EQ(setRet, SUCCESS);
    uint32_t softwareRet = astcEncoder.AstcSoftwareEncode(param, enableQualityCheck, blocksNum, outSize);
    ASSERT_EQ(softwareRet, SUCCESS);

    param.privateProfile_ = QualityProfile::HIGH_SPEED_PROFILE;
    softwareRet = astcEncoder.AstcSoftwareEncode(param, enableQualityCheck, blocksNum, outSize);
    ASSERT_EQ(softwareRet, SUCCESS);

    if (pixelMapPtr != nullptr) {
        pixelMapPtr = nullptr;
    }
    if (output != nullptr) {
        free(output);
        output = nullptr;
    }
    if (stream != nullptr) {
        delete stream;
        stream = nullptr;
    }

    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcSoftwareEncode001 end";
}

/**
 * @tc.name: AstcSoftwareEncode002
 * @tc.desc: GenAstcHeader return error test
 * @tc.desc: size < ASTC_HEADER_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(PluginTextureEncodeTest, AstcSoftwareEncode002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcSoftwareEncode002 start";

    std::unique_ptr<PixelMap> pixelMap = ConstructPixmap(RGBA_TEST0001_WIDTH, RGBA_TEST0001_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    Media::PixelMap *pixelMapPtr = pixelMap.get();
    ASSERT_NE(pixelMapPtr, nullptr);

    uint8_t *output = static_cast<uint8_t *>(malloc(TEXTURE_BLOCK_BYTES - 1));
    ASSERT_NE(output, nullptr);
    BufferPackerStream *stream = new (std::nothrow) BufferPackerStream(output, TEXTURE_BLOCK_BYTES - 1);
    ASSERT_NE(stream, nullptr);

    TextureEncodeOptions param = SetDefaultOption();
    int32_t blocksNum = ((param.width_ + param.blockX_ - 1) / param.blockX_) *
        ((param.height_ + param.blockY_ - 1) / param.blockY_);
    int32_t outSize = blocksNum * TEXTURE_BLOCK_BYTES + TEXTURE_BLOCK_BYTES;

    bool enableQualityCheck = false;

    struct PlEncodeOptions option = { "image/astc/4*4", 100, 1 }; // quality set to 100
    AstcCodec astcEncoder;
    uint32_t setRet = astcEncoder.SetAstcEncode(stream, option, pixelMapPtr);
    ASSERT_EQ(setRet, SUCCESS);
    uint32_t softwareRet = astcEncoder.AstcSoftwareEncode(param, enableQualityCheck, blocksNum, outSize);
    ASSERT_EQ(softwareRet, ERROR);

    if (pixelMapPtr != nullptr) {
        pixelMapPtr = nullptr;
    }
    if (output != nullptr) {
        free(output);
        output = nullptr;
    }
    if (stream != nullptr) {
        delete stream;
        stream = nullptr;
    }

    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcSoftwareEncode002 end";
}

/**
 * @tc.name: AstcSoftwareEncode003
 * @tc.desc: GenAstcHeader return error test
 * @tc.desc: header == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(PluginTextureEncodeTest, AstcSoftwareEncode003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcSoftwareEncode003 start";

    std::unique_ptr<PixelMap> pixelMap = ConstructPixmap(RGBA_TEST0001_WIDTH, RGBA_TEST0001_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    Media::PixelMap *pixelMapPtr = pixelMap.get();
    ASSERT_NE(pixelMapPtr, nullptr);

    BufferPackerStream *stream = new (std::nothrow) BufferPackerStream(nullptr, OUTPUT_SIZE_MAX);
    ASSERT_NE(stream, nullptr);

    TextureEncodeOptions param = SetDefaultOption();
    int32_t blocksNum = ((param.width_ + param.blockX_ - 1) / param.blockX_) *
        ((param.height_ + param.blockY_ - 1) / param.blockY_);
    int32_t outSize = blocksNum * TEXTURE_BLOCK_BYTES + TEXTURE_BLOCK_BYTES;

    bool enableQualityCheck = false;

    struct PlEncodeOptions option = { "image/astc/4*4", 100, 1 }; // quality set to 100
    AstcCodec astcEncoder;
    uint32_t setRet = astcEncoder.SetAstcEncode(stream, option, pixelMapPtr);
    ASSERT_EQ(setRet, SUCCESS);
    uint32_t softwareRet = astcEncoder.AstcSoftwareEncode(param, enableQualityCheck, blocksNum, outSize);
    ASSERT_EQ(softwareRet, ERROR);

    if (pixelMapPtr != nullptr) {
        pixelMapPtr = nullptr;
    }
    if (stream != nullptr) {
        delete stream;
        stream = nullptr;
    }

    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcSoftwareEncode003 end";
}

/**
 * @tc.name: AstcEncBasedOnCl001
 * @tc.desc: Test the AstcClFillImage function
 * @tc.type: FUNC
 */
HWTEST_F(PluginTextureEncodeTest, AstcEncBasedOnCl001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcEncBasedOnCl001 start";

    TextureEncodeOptions param = SetDefaultOption();
    param.stride_ = param.stride_ << RGBA_BYTES_PIXEL_LOG2;
    int32_t inputSize = (param.width_ * param.height_) << RGBA_BYTES_PIXEL_LOG2;
    uint8_t *input = static_cast<uint8_t *>(malloc(inputSize));
    ASSERT_NE(input, nullptr);
    for (int32_t i = 0; i < inputSize; ++i) {
        input[i] = static_cast<uint8_t>(i % PIXEL_VALUE_MAX);
    }

    ClAstcImageOption imageIn;
    uint32_t ret = AstcClFillImage(&imageIn, input, param.stride_, param.width_, param.height_);
    ASSERT_EQ(ret, CL_ASTC_ENC_SUCCESS);

    ret = AstcClFillImage(&imageIn, input, param.stride_, 0, param.height_);
    ASSERT_EQ(ret, CL_ASTC_ENC_FAILED);

    ret = AstcClFillImage(&imageIn, input, param.stride_, param.width_, 0);
    ASSERT_EQ(ret, CL_ASTC_ENC_FAILED);

    ret = AstcClFillImage(&imageIn, input, param.width_ - 1, param.width_, param.height_);
    ASSERT_EQ(ret, CL_ASTC_ENC_FAILED);

    ret = AstcClFillImage(&imageIn, input, param.stride_, RGBA_MAX_WIDTH + 1, param.height_);
    ASSERT_EQ(ret, CL_ASTC_ENC_FAILED);

    ret = AstcClFillImage(&imageIn, input, param.stride_, param.width_, RGBA_MAX_HEIGHT + 1);
    ASSERT_EQ(ret, CL_ASTC_ENC_FAILED);

    ClAstcImageOption *imageInPtr = nullptr;
    ret = AstcClFillImage(imageInPtr, input, param.stride_, param.width_, param.height_);
    ASSERT_EQ(ret, CL_ASTC_ENC_FAILED);

    if (input != nullptr) {
        free(input);
        input = nullptr;
    }
    if (imageInPtr != nullptr) {
        imageInPtr = nullptr;
    }

    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcEncBasedOnCl001 end";
}

/**
 * @tc.name: AstcEncBasedOnCl002
 * @tc.desc: AstcClEncImage return failed test
 * @tc.type: FUNC
 */
HWTEST_F(PluginTextureEncodeTest, AstcEncBasedOnCl002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcEncBasedOnCl002 start";

    ClAstcHandle *astcClEncoder = static_cast<ClAstcHandle *>(malloc(sizeof(ClAstcHandle)));
    uint8_t *buffer = static_cast<uint8_t *>(malloc(OUTPUT_SIZE_MAX));
    ClAstcImageOption imageIn;

    uint32_t ret = AstcClEncImage(nullptr, &imageIn, buffer);
    ASSERT_EQ(ret, CL_ASTC_ENC_FAILED);

    ret = AstcClEncImage(astcClEncoder, nullptr, buffer);
    ASSERT_EQ(ret, CL_ASTC_ENC_FAILED);

    ret = AstcClEncImage(astcClEncoder, &imageIn, nullptr);
    ASSERT_EQ(ret, CL_ASTC_ENC_FAILED);

    astcClEncoder->encObj.blockErrs_ = nullptr;
    ret = AstcClEncImage(astcClEncoder, &imageIn, buffer);
    ASSERT_EQ(ret, CL_ASTC_ENC_FAILED);

    if (astcClEncoder != nullptr) {
        free(astcClEncoder);
        astcClEncoder = nullptr;
    }
    if (buffer != nullptr) {
        free(buffer);
        buffer = nullptr;
    }

    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcEncBasedOnCl002 end";
}

/**
 * @tc.name: AstcEncBasedOnCl003
 * @tc.desc: AstcClClose return failed test
 * @tc.type: FUNC
 */
HWTEST_F(PluginTextureEncodeTest, AstcEncBasedOnCl003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcEncBasedOnCl003 start";

    ClAstcHandle *astcClEncoder = static_cast<ClAstcHandle *>(calloc(1, sizeof(ClAstcHandle)));
    uint32_t ret = AstcClClose(astcClEncoder);
    ASSERT_EQ(ret, CL_ASTC_ENC_SUCCESS);

    ret = AstcClClose(nullptr);
    ASSERT_EQ(ret, CL_ASTC_ENC_FAILED);

    if (astcClEncoder != nullptr) {
        astcClEncoder = nullptr;
    }

    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcEncBasedOnCl003 end";
}
} // namespace Multimedia
} // namespace OHOS