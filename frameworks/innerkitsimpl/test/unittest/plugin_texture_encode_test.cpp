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
#include <securec.h>
#include <sys/time.h>

#include "astc_codec.h"
#include "buffer_packer_stream.h"
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
#include "image_compressor.h"
#endif
#include "image_source_util.h"
#include "image_system_properties.h"
#include "image_utils.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImagePlugin;
namespace OHOS {
namespace Media {

#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
using namespace AstcEncBasedCl;
constexpr uint8_t RGBA_BYTES_PIXEL_LOG2 = 2;
constexpr int32_t RGBA_MAX_WIDTH = 8192;
constexpr int32_t RGBA_MAX_HEIGHT = 8192;
#endif

constexpr int32_t RGBA_TEST0001_WIDTH = 256;
constexpr int32_t RGBA_TEST0001_HEIGHT = 256;
constexpr int32_t PIXEL_VALUE_MAX = 256;
constexpr int32_t TEXTURE_BLOCK_BYTES = 16;
constexpr int32_t TEXTURE_HEAD_BYTES = 16;
constexpr int32_t ASTC_BLOCK_WIDTH = 4;
constexpr int32_t ASTC_BLOCK_HEIGHT = 4;
constexpr int32_t OUTPUT_SIZE_MAX = 200000;
constexpr int32_t BYTES_PER_PIXEL = 4;
constexpr int64_t SECOND_TO_MICROS = 1000000;
constexpr size_t FILE_NAME_LENGTH = 512;
struct AstcEncTestPara {
    TextureEncodeOptions param;
    int32_t width;
    int32_t height;
    uint8_t block;
    size_t frames;
    bool isBasedOnGpu;
    bool isSelfCreatePixMap;
    QualityProfile privateProfile;
    int64_t totalTime;
};

enum class TestEncRet {
    ERR_OK = 0,
    ERR_FILE_NOT_FIND,
    ERR_ENC_FAILED,
    ERR_LOW_LEVEL_FAILED
};

class PluginTextureEncodeTest : public testing::Test {
public:
    PluginTextureEncodeTest() {}
    ~PluginTextureEncodeTest() {}
};

static TextureEncodeOptions CreateDefaultEncParam()
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

static int64_t CurrentTimeInUs(void)
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return tv.tv_sec * SECOND_TO_MICROS + tv.tv_usec;
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

    TextureEncodeOptions param = CreateDefaultEncParam();
    param.privateProfile_ = QualityProfile::HIGH_QUALITY_PROFILE;
    int32_t blocksNum = ((param.width_ + param.blockX_ - 1) / param.blockX_) *
        ((param.height_ + param.blockY_ - 1) / param.blockY_);
    int32_t outSize = blocksNum * TEXTURE_BLOCK_BYTES + TEXTURE_BLOCK_BYTES;
    auto outBuffer = static_cast<uint8_t *>(malloc(outSize));
    ASSERT_NE(outBuffer, nullptr);

    bool enableQualityCheck = true;

    struct PlEncodeOptions option = { "image/astc/4*4", 100, 1 }; // quality set to 100
    AstcCodec astcEncoder;
    uint32_t setRet = astcEncoder.SetAstcEncode(stream, option, pixelMapPtr);
    ASSERT_EQ(setRet, SUCCESS);
    uint32_t softwareRet = astcEncoder.AstcSoftwareEncode(param, enableQualityCheck, blocksNum, outBuffer, outSize);
    ASSERT_EQ(softwareRet, SUCCESS);

    param.privateProfile_ = QualityProfile::HIGH_SPEED_PROFILE;
    softwareRet = astcEncoder.AstcSoftwareEncode(param, enableQualityCheck, blocksNum, outBuffer, outSize);
    ASSERT_EQ(softwareRet, SUCCESS);

    if (output != nullptr) {
        free(output);
        output = nullptr;
    }
    if (stream != nullptr) {
        delete stream;
        stream = nullptr;
    }
    if (outBuffer != nullptr) {
        free(outBuffer);
        outBuffer = nullptr;
    }
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcSoftwareEncode001 end";
}

/**
 * @tc.name: AstcSoftwareEncode002
 * @tc.desc: GenAstcHeader return error test
 * @tc.desc: header == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(PluginTextureEncodeTest, AstcSoftwareEncode002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcSoftwareEncode003 start";

    std::unique_ptr<PixelMap> pixelMap = ConstructPixmap(RGBA_TEST0001_WIDTH, RGBA_TEST0001_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    Media::PixelMap *pixelMapPtr = pixelMap.get();
    ASSERT_NE(pixelMapPtr, nullptr);

    BufferPackerStream *stream = new (std::nothrow) BufferPackerStream(nullptr, OUTPUT_SIZE_MAX);
    ASSERT_NE(stream, nullptr);

    TextureEncodeOptions param = CreateDefaultEncParam();
    int32_t blocksNum = ((param.width_ + param.blockX_ - 1) / param.blockX_) *
        ((param.height_ + param.blockY_ - 1) / param.blockY_);
    int32_t outSize = blocksNum * TEXTURE_BLOCK_BYTES + TEXTURE_BLOCK_BYTES;
    bool enableQualityCheck = false;
    struct PlEncodeOptions option = { "image/astc/4*4", 100, 1 }; // quality set to 100
    AstcCodec astcEncoder;
    uint32_t setRet = astcEncoder.SetAstcEncode(stream, option, pixelMapPtr);
    ASSERT_EQ(setRet, SUCCESS);
    uint32_t softwareRet = astcEncoder.AstcSoftwareEncode(param, enableQualityCheck, blocksNum, nullptr, outSize);
    ASSERT_EQ(softwareRet, ERROR);

    if (stream != nullptr) {
        delete stream;
        stream = nullptr;
    }
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcSoftwareEncode003 end";
}

#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
/**
 * @tc.name: AstcEncBasedOnCl001
 * @tc.desc: Test the AstcClFillImage function
 * @tc.type: FUNC
 */
HWTEST_F(PluginTextureEncodeTest, AstcEncBasedOnCl001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcEncBasedOnCl001 start";

    TextureEncodeOptions param = CreateDefaultEncParam();
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

    GTEST_LOG_(INFO) << "PluginTextureEncodeTest: AstcEncBasedOnCl003 end";
}
#endif

static bool FillEncodeOptions(TextureEncodeOptions &param,
    int32_t width, int32_t height, uint8_t block, QualityProfile privateProfile)
{
    param.enableQualityCheck = false;
    param.hardwareFlag = false;
    param.sutProfile = SutProfile::SKIP_SUT;
    param.width_ = width;
    param.height_ = height;
    param.stride_ = width;
    param.privateProfile_ = privateProfile;
    param.blockX_ = block;
    param.blockY_ = block;
    if ((param.blockX_ != 0) && (param.blockY_ != 0)) {
        param.blocksNum = ((param.width_ + param.blockX_ - 1) / param.blockX_) *
            ((param.height_ + param.blockY_ - 1) / param.blockY_);
    } else {
        return false;
    }
    param.astcBytes = param.blocksNum * TEXTURE_BLOCK_BYTES + TEXTURE_HEAD_BYTES;
    return true;
}

void FreeAllMem(uint8_t **pixMapGroup, uint8_t **astcBuf, size_t frames)
{
    if (pixMapGroup != nullptr) {
        for (size_t idx = 0; idx < frames; idx++) {
            if (pixMapGroup[idx] != nullptr) {
                free(pixMapGroup[idx]);
            }
        }
        free(pixMapGroup);
    }
    if (astcBuf != nullptr) {
        for (size_t idx = 0; idx < frames; idx++) {
            if (astcBuf[idx] != nullptr) {
                free(astcBuf[idx]);
            }
        }
        free(astcBuf);
    }
}

#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
static bool TryAstcEncBasedOnCl(TextureEncodeOptions &param, uint8_t *inData,
    uint8_t *buffer, const std::string &clBinPath)
{
    ClAstcHandle *astcClEncoder = nullptr;
    if ((inData == nullptr) || (buffer == nullptr)) {
        GTEST_LOG_(ERROR) << "astc Please check TryAstcEncBasedOnCl input!";
        return false;
    }
    if (AstcClCreate(&astcClEncoder, clBinPath) != CL_ASTC_ENC_SUCCESS) {
        GTEST_LOG_(ERROR) << "astc AstcClCreate failed!";
        return false;
    }
    ClAstcImageOption imageIn;
    if (AstcClFillImage(&imageIn, inData, param.stride_, param.width_, param.height_) != CL_ASTC_ENC_SUCCESS) {
        GTEST_LOG_(ERROR) << "astc AstcClFillImage failed!";
        AstcClClose(astcClEncoder);
        return false;
    }
    if (AstcClEncImage(astcClEncoder, &imageIn, buffer) != CL_ASTC_ENC_SUCCESS) {
        GTEST_LOG_(ERROR) << "astc AstcClEncImage failed!";
        AstcClClose(astcClEncoder);
        return false;
    }
    if (AstcClClose(astcClEncoder) != CL_ASTC_ENC_SUCCESS) {
        GTEST_LOG_(ERROR) << "astc AstcClClose failed!";
        return false;
    }
    return true;
}
#endif

static void SelfCreatePixMap(uint8_t *pixMap, size_t bytesPerFile, size_t idx)
{
    uint8_t *buf = pixMap;
    for (size_t pixel = 0; pixel < bytesPerFile; pixel++) {
        *buf++ = (pixel + idx) % PIXEL_VALUE_MAX;
    }
}

static bool CheckFileIsExist(const std::string &name)
{
    return (access(name.c_str(), F_OK) != -1); // -1 means that the file is  not exist
}

static TestEncRet ReadFileExtern(uint8_t *pixMap, size_t bytesPerFile, size_t idx, AstcEncTestPara &testPara)
{
    const std::string testPath = "/data/local/tmp";
    char inFile[FILE_NAME_LENGTH];
    if (sprintf_s(inFile, sizeof(inFile), "%s/%dx%d/a%04ld_%dx%d.rgb", testPath.c_str(),
        testPara.width, testPara.height, idx + 1, testPara.width, testPara.height) < 0) {
            return TestEncRet::ERR_LOW_LEVEL_FAILED;
    }
    std::string fileStr(inFile);
    if (!CheckFileIsExist(fileStr)) {
        GTEST_LOG_(ERROR) << "File is not exist: " << inFile;
        return TestEncRet::ERR_FILE_NOT_FIND;
    }
    std::ifstream contents{fileStr};
    std::string fileContent{std::istreambuf_iterator<char>{contents}, {}};
    if (fileContent.length() < bytesPerFile) {
        GTEST_LOG_(ERROR) << "File size is too small: need " << bytesPerFile <<
            " bytes, but the file only " << fileContent.length() << " bytes in " << inFile;
        return TestEncRet::ERR_LOW_LEVEL_FAILED;
    }
    if (memcpy_s(pixMap, bytesPerFile, static_cast<const char *>(fileContent.c_str()), bytesPerFile) != 0) {
        GTEST_LOG_(ERROR) << "file memcpy_s failed";
        return TestEncRet::ERR_LOW_LEVEL_FAILED;
    }
    return TestEncRet::ERR_OK;
}

TestEncRet EncodeMutiFrames(uint8_t **pixMapGroup, uint8_t **astcBuf, AstcEncTestPara &testPara)
{
    if ((pixMapGroup == nullptr) || (astcBuf == nullptr)) {
        return TestEncRet::ERR_LOW_LEVEL_FAILED;
    }
    testPara.totalTime = 0;
    size_t bytesPerFile = testPara.width * testPara.height * BYTES_PER_PIXEL;
    std::string clBinPath = "/sys_prod/etc/graphic/AstcEncShader_ALN-AL00.bin";
    for (size_t idx = 0; idx < testPara.frames; idx++) {
        pixMapGroup[idx] = reinterpret_cast<uint8_t *>(malloc(bytesPerFile * sizeof(uint8_t)));
        if (pixMapGroup[idx] == nullptr) {
            return TestEncRet::ERR_LOW_LEVEL_FAILED;
        }
        astcBuf[idx] = reinterpret_cast<uint8_t *>(malloc(testPara.param.astcBytes * sizeof(uint8_t)));
        if (astcBuf[idx] == nullptr) {
            return TestEncRet::ERR_LOW_LEVEL_FAILED;
        }
        if (testPara.isSelfCreatePixMap) {
            SelfCreatePixMap(pixMapGroup[idx], bytesPerFile, idx);
        } else {
            TestEncRet ret = ReadFileExtern(pixMapGroup[idx], bytesPerFile, idx, testPara);
            if (ret != TestEncRet::ERR_OK) {
                return ret;
            }
        }
        int64_t startTime = CurrentTimeInUs();
        bool isBasedGpu = false;
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
        if (testPara.isBasedOnGpu) {
            if (!TryAstcEncBasedOnCl(testPara.param, pixMapGroup[idx], astcBuf[idx], clBinPath)) {
                GTEST_LOG_(ERROR) << "astc encoding based on GPU failed";
                return TestEncRet::ERR_ENC_FAILED;
            }
            isBasedGpu = true;
        }
#endif
        if (!isBasedGpu && !AstcCodec::AstcSoftwareEncodeCore(testPara.param, pixMapGroup[idx], astcBuf[idx])) {
            GTEST_LOG_(ERROR) << "astc encoding based on CPU failed";
            return TestEncRet::ERR_ENC_FAILED;
        }
        testPara.totalTime += CurrentTimeInUs() - startTime;
    }
    return TestEncRet::ERR_OK;
}

TestEncRet TestCaseMultiFrameEnc(AstcEncTestPara &testPara)
{
    if (!FillEncodeOptions(testPara.param, testPara.width, testPara.height,
        testPara.block, testPara.privateProfile)) {
        GTEST_LOG_(ERROR) << "FillEncodeOptions failed";
        return TestEncRet::ERR_LOW_LEVEL_FAILED;
    }
    uint8_t **pixMapGroup = (uint8_t **) calloc (testPara.frames, sizeof(uint8_t*));
    if (pixMapGroup == nullptr) {
        GTEST_LOG_(ERROR) << "pixMapGroup calloc failed";
        return TestEncRet::ERR_LOW_LEVEL_FAILED;
    }
    uint8_t **astcBuf = (uint8_t **) calloc (testPara.frames, sizeof(uint8_t*));
    if (astcBuf == nullptr) {
        GTEST_LOG_(ERROR) << "astcBuf calloc failed";
        FreeAllMem(pixMapGroup, astcBuf, testPara.frames);
        return TestEncRet::ERR_LOW_LEVEL_FAILED;
    }
    TestEncRet ret = EncodeMutiFrames(pixMapGroup, astcBuf, testPara);
    FreeAllMem(pixMapGroup, astcBuf, testPara.frames);
    if (ret == TestEncRet::ERR_OK) {
        GTEST_LOG_(INFO) << "isGPU:" << testPara.isBasedOnGpu << " SelfPixel:" << testPara.isSelfCreatePixMap <<
            " profile:" << testPara.privateProfile << " " << testPara.param.width_ << "x" <<
            testPara.param.height_ << " frames " <<
            testPara.frames << " gpu astc encoding average time: " <<
            static_cast<float>(testPara.totalTime) / static_cast<float>(testPara.frames) << "us";
    }
    return ret;
}

static AstcEncTestPara CreateAstcEncTestPara(int32_t width, int32_t height,
    uint8_t block, size_t frames, bool isBasedOnGpu)
{
    AstcEncTestPara testPara;
    testPara.width = width;
    testPara.height = height;
    testPara.isBasedOnGpu = isBasedOnGpu;
    testPara.block = block;
    testPara.frames = frames;
    testPara.isSelfCreatePixMap = true;
    testPara.privateProfile = HIGH_SPEED_PROFILE;
    return testPara;
}

/**
 * @tc.name: AstcEncoderTime_001
 * @tc.desc: Calculate the average time
 *         : BasedOnCPU / 64x64 / quality 20 / self-created images / 5000frames
 * @tc.type: Performance
 */
HWTEST_F(PluginTextureEncodeTest, AstcEncoderTime_001, TestSize.Level3)
{
    // test condition: width 64, height 64, block 4x4 , frames 5000, isBasedOnGpu: false
    AstcEncTestPara testPara = CreateAstcEncTestPara(64, 64, 4, 5000, false);
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);
}

/**
 * @tc.name: AstcEncoderTime_002
 * @tc.desc: Calculate the average time
 *         : BasedOnCPU / 64x64 / quality 100 / self-created images / 5000frames
 * @tc.type: Performance
 */
HWTEST_F(PluginTextureEncodeTest, AstcEncoderTime_002, TestSize.Level3)
{
    // test condition: width 64, height 64, block 4x4 , frames 5000, isBasedOnGpu: false
    AstcEncTestPara testPara = CreateAstcEncTestPara(64, 64, 4, 5000, false);
    testPara.privateProfile = HIGH_QUALITY_PROFILE;
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);
}

/**
 * @tc.name: AstcEncoderTime_003
 * @tc.desc: Calculate the average time
 *         : BasedOnCPU / 64x64 / quality 20 / Extern images / 5000frames
 * @tc.type: Performance
 */
HWTEST_F(PluginTextureEncodeTest, AstcEncoderTime_003, TestSize.Level3)
{
    // test condition: width 64, height 64, block 4x4 , frames 5000, isBasedOnGpu: false
    AstcEncTestPara testPara = CreateAstcEncTestPara(64, 64, 4, 5000, false);
    testPara.isSelfCreatePixMap = false;
    ASSERT_LE(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_FILE_NOT_FIND);
}

/**
 * @tc.name: AstcEncoderTime_004
 * @tc.desc: Calculate the average time
 *         : BasedOnCPU / 64x64 / quality 100 / Extern images / 5000frames
 * @tc.type: Performance
 */
HWTEST_F(PluginTextureEncodeTest, AstcEncoderTime_004, TestSize.Level3)
{
    // test condition: width 64, height 64, block 4x4 , frames 5000, isBasedOnGpu: false
    AstcEncTestPara testPara = CreateAstcEncTestPara(64, 64, 4, 5000, false);
    testPara.isSelfCreatePixMap = false;
    testPara.privateProfile = HIGH_QUALITY_PROFILE;
    ASSERT_LE(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_FILE_NOT_FIND);
}

/**
 * @tc.name: AstcEncoderTime_005
 * @tc.desc: Calculate the average time
 *         : BasedOnGPU / 64x64 / self-created images / 5000frames
 * @tc.type: Performance
 */
HWTEST_F(PluginTextureEncodeTest, AstcEncoderTime_005, TestSize.Level3)
{
    // test condition: width 64, height 64, block 4x4 , frames 5000, isBasedOnGpu: true
    AstcEncTestPara testPara = CreateAstcEncTestPara(64, 64, 4, 5000, true);
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);
}

/**
 * @tc.name: AstcEncoderTime_006
 * @tc.desc: Calculate the average time
 *         : BasedOnGPU / 64x64 / Extern images / 5000frames
 * @tc.type: Performance
 */
HWTEST_F(PluginTextureEncodeTest, AstcEncoderTime_006, TestSize.Level3)
{
    // test condition: width 64, height 64, block 4x4 , frames 5000, isBasedOnGpu: true
    AstcEncTestPara testPara = CreateAstcEncTestPara(64, 64, 4, 5000, true);
    testPara.isSelfCreatePixMap = false;
    ASSERT_LE(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_FILE_NOT_FIND);
}

/**
 * @tc.name: AstcEncoderTime_007
 * @tc.desc: Calculate the average time
 *         : BasedOnGPU / different resolution / self-created images
 * @tc.type: Performance
 */
HWTEST_F(PluginTextureEncodeTest, AstcEncoderTime_007, TestSize.Level3)
{
    // test condition: width 64, height 64, block 4x4 , frames 5000, isBasedOnGpu: true
    AstcEncTestPara testPara = CreateAstcEncTestPara(64, 64, 4, 5000, true);
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(128, 128, 4, 5000, true); // 64x64 block 4x4 , frames 5000
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(256, 256, 4, 5000, true); // 256x256 block 4x4 , frames 5000
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(512, 512, 4, 5000, true); // 512x512 block 4x4 , frames 5000
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(1024, 1024, 4, 200, true); // 1024x1024 block 4x4 , frames 200
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(1920, 1080, 4, 100, true); // 1920x1080 block 4x4 , frames 100
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(2560, 1440, 4, 50, true); // 2560x1440 block 4x4 , frames 50
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(3840, 2160, 4, 20, true); // 3840x2160 block 4x4 , frames 20
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(8192, 8192, 4, 10, true); // 8192x8192 block 4x4 , frames 10
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);
}

/**
 * @tc.name: AstcEncoderTime_008
 * @tc.desc: Calculate the average time
 *         : BasedOnCPU / different resolution / self-created images
 * @tc.type: Performance
 */
HWTEST_F(PluginTextureEncodeTest, AstcEncoderTime_008, TestSize.Level3)
{
    // test condition: width 64, height 64, block 4x4 , frames 5000, isBasedOnGpu: true
    AstcEncTestPara testPara = CreateAstcEncTestPara(64, 64, 4, 5000, false);
    testPara.isSelfCreatePixMap = true;
    testPara.privateProfile = HIGH_SPEED_PROFILE;
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(128, 128, 4, 5000, false); // 64x64 block 4x4 , frames 5000
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(256, 256, 4, 5000, false); // 256x256 block 4x4 , frames 5000
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(512, 512, 4, 5000, false); // 512x512 block 4x4 , frames 5000
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(1024, 1024, 4, 200, false); // 1024x1024 block 4x4 , frames 200
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(1920, 1080, 4, 100, false); // 1920x1080 block 4x4 , frames 100
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(2560, 1440, 4, 50, false); // 2560x1440 block 4x4 , frames 50
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(3840, 2160, 4, 20, false); // 3840x2160 block 4x4 , frames 20
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);

    testPara = CreateAstcEncTestPara(8192, 8192, 4, 10, false); // 8192x8192 block 4x4 , frames 10
    ASSERT_EQ(TestCaseMultiFrameEnc(testPara), TestEncRet::ERR_OK);
}

/**
 * @tc.name: AstcEncoderTime_009
 * @tc.desc: BoundCheck for new function
 * @tc.type: Performance
 */
HWTEST_F(PluginTextureEncodeTest, AstcEncoderTime_009, TestSize.Level3)
{
    TextureEncodeOptions param;
    ASSERT_EQ(AstcCodec::AstcSoftwareEncodeCore(param, nullptr, nullptr), false);

    uint8_t pixmapIn = 0;
    ASSERT_EQ(AstcCodec::AstcSoftwareEncodeCore(param, &pixmapIn, nullptr), false);
} // namespace Multimedia

}
} // namespace OHOS