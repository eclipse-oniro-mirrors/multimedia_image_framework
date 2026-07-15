/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <string>
#include <memory>
#include "securec.h"
#include "tiff_encoder.h"
#include "image_packer.h"
#include "pixel_map.h"
#include "buffer_packer_stream.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::ImagePlugin;

namespace OHOS {
namespace ImagePlugin {

// Test image file paths for file-based encoding tests
namespace {
    const std::string IMAGE_TIFF_RGB888_PATH = "/data/local/tmp/image/1920x1080_RGB888_none.dat";
    const std::string IMAGE_TIFF_Y8_PATH = "/data/local/tmp/image/1920x1080_Y8_none.dat";
    const std::string IMAGE_TIFF_Y1_PATH = "/data/local/tmp/image/1920x1080_Y1_none.dat";
}

// Standard test dimensions
static constexpr uint32_t TEST_WIDTH = 100;
static constexpr uint32_t TEST_HEIGHT = 100;

// File-based test image dimensions
static constexpr uint32_t FILE_TEST_WIDTH = 1920;
static constexpr uint32_t FILE_TEST_HEIGHT = 1080;
static constexpr uint32_t Y8_BYTES_PER_PIXEL = 1;
static constexpr uint32_t RGB888_BYTES_PER_PIXEL = 3;

// Buffer sizes
static constexpr size_t SMALL_BUFFER_SIZE = 1024 * 1024;        // 1MB

// Default TIFF parameters (using tiffPackingOption)
static constexpr int DEFAULT_TIFF_ORIENTATION = 1;  // ORIENTATION_TOPLEFT
static constexpr float DEFAULT_TIFF_X_RESOLUTION = 300.0f;
static constexpr float DEFAULT_TIFF_Y_RESOLUTION = 300.0f;
static constexpr int DEFAULT_TIFF_RESOLUTION_UNIT = 2;  // INCH

// Color and pixel constants
static constexpr uint32_t MIN_TIFF_HEADER_SIZE = 4;
static constexpr size_t TIFF_HEADER_ELEMENT_SIZE = 1;  // Size of each header element in bytes

// TIFF magic numbers
static constexpr uint8_t TIFF_LITTLE_ENDIAN_I = 'I';
static constexpr uint8_t TIFF_LITTLE_ENDIAN_M = 'M';
static constexpr uint8_t TIFF_MAGIC_NUMBER_1 = 0x2A;
static constexpr uint8_t TIFF_MAGIC_NUMBER_2 = 0x00;

static void SetDefaultPlPackingOptionsForTiff(OHOS::ImagePlugin::PlPackingOptionsForTiff &opt)
{
    opt.orientation = DEFAULT_TIFF_ORIENTATION;
    opt.xResolution = DEFAULT_TIFF_X_RESOLUTION;
    opt.yResolution = DEFAULT_TIFF_Y_RESOLUTION;
    opt.resolutionUnit = DEFAULT_TIFF_RESOLUTION_UNIT;
}

static void SetDefaultPackingOptionsForTiff(OHOS::Media::PackingOptionsForTiff &opt)
{
    opt.orientation = DEFAULT_TIFF_ORIENTATION;
    opt.xResolution = DEFAULT_TIFF_X_RESOLUTION;
    opt.yResolution = DEFAULT_TIFF_Y_RESOLUTION;
    opt.resolutionUnit = DEFAULT_TIFF_RESOLUTION_UNIT;
}

static void SetDefaultTiffPackOption(OHOS::Media::PackOption &opt)
{
    opt.tiffPackingOption.orientation = DEFAULT_TIFF_ORIENTATION;
    opt.tiffPackingOption.xResolution = DEFAULT_TIFF_X_RESOLUTION;
    opt.tiffPackingOption.yResolution = DEFAULT_TIFF_Y_RESOLUTION;
    opt.tiffPackingOption.resolutionUnit = DEFAULT_TIFF_RESOLUTION_UNIT;
}

class TiffEncoderTest : public testing::Test {
public:
    TiffEncoderTest() {}
    ~TiffEncoderTest() {}

    bool GetFormatInfoFromPath(const std::string &path, PixelFormat &format, uint32_t &rowBytes, uint64_t &dataSize)
    {
        if (path.find("Y8") != std::string::npos) {
            format = PixelFormat::Y8;
            rowBytes = FILE_TEST_WIDTH * Y8_BYTES_PER_PIXEL;
        } else if (path.find("RGB888") != std::string::npos) {
            format = PixelFormat::RGB_888;
            rowBytes = FILE_TEST_WIDTH * RGB888_BYTES_PER_PIXEL;
        } else {
            GTEST_LOG_(ERROR) << "Unsupported format for PixelMap: " << path;
            return false;
        }
        dataSize = static_cast<uint64_t>(rowBytes) * FILE_TEST_HEIGHT;
        return true;
    }

    std::vector<uint8_t> ReadFileData(const std::string &path, uint64_t dataSize, uint32_t &errorCode)
    {
        FILE* file = fopen(path.c_str(), "rb");
        if (!file) {
            GTEST_LOG_(ERROR) << "Failed to open file: " << path;
            errorCode = Media::ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
            return {};
        }

        std::vector<uint8_t> fileData(dataSize);
        size_t bytesRead = fread(fileData.data(), 1, dataSize, file);
        if (fclose(file) == EOF || bytesRead != dataSize) {
            GTEST_LOG_(ERROR) << "Failed to read complete file: " << path;
            errorCode = Media::ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
            return {};
        }

        return fileData;
    }

    std::shared_ptr<Media::PixelMap> CreatePixelMapWithData(PixelFormat format,
        const std::vector<uint8_t> &fileData, uint32_t rowBytes, uint32_t &errorCode)
    {
        Media::InitializationOptions initOpts;
        initOpts.size.width = FILE_TEST_WIDTH;
        initOpts.size.height = FILE_TEST_HEIGHT;
        initOpts.pixelFormat = format;
        initOpts.srcPixelFormat = format;
        initOpts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
        initOpts.editable = true;

        auto pixelMap = Media::PixelMap::Create(initOpts);
        if (!pixelMap) {
            GTEST_LOG_(ERROR) << "Failed to create PixelMap";
            errorCode = Media::ERR_IMAGE_PIXELMAP_CREATE_FAILED;
            return nullptr;
        }

        void* dstPixels = pixelMap->GetWritablePixels();
        if (!dstPixels) {
            GTEST_LOG_(ERROR) << "Failed to get writable pixels";
            errorCode = Media::ERR_IMAGE_PIXELMAP_CREATE_FAILED;
            return nullptr;
        }

        for (uint32_t y = 0; y < FILE_TEST_HEIGHT; y++) {
            uint8_t* dstRow = static_cast<uint8_t*>(dstPixels) + y * pixelMap->GetRowBytes();
            memcpy_s(dstRow, pixelMap->GetRowBytes(), fileData.data() + y * rowBytes, rowBytes);
        }

        errorCode = Media::SUCCESS;
        return pixelMap;
    }

    std::shared_ptr<Media::PixelMap> LoadPixelMapFromFile(const std::string &path, uint32_t &errorCode)
    {
        PixelFormat format;
        uint32_t rowBytes;
        uint64_t dataSize;

        if (!GetFormatInfoFromPath(path, format, rowBytes, dataSize)) {
            errorCode = Media::ERR_IMAGE_DECODE_ABNORMAL;
            return nullptr;
        }

        auto fileData = ReadFileData(path, dataSize, errorCode);
        if (fileData.empty()) {
            return nullptr;
        }

        return CreatePixelMapWithData(format, fileData, rowBytes, errorCode);
    }

    struct Y1DataBuffer {
        std::unique_ptr<uint8_t[]> data;
        PixelBufferInfo bufferInfo;

        bool IsValid() const
        {
            return data != nullptr && bufferInfo.data != nullptr;
        }
    };

    Y1DataBuffer LoadY1DataFromFile(const std::string &path, uint32_t &errorCode)
    {
        const uint32_t width = 1920;
        const uint32_t height = 1080;
        const uint32_t rowBytes = 240;
        const uint64_t dataSize = 259200;

        FILE* file = fopen(path.c_str(), "rb");
        if (!file) {
            GTEST_LOG_(ERROR) << "Failed to open file: " << path;
            errorCode = Media::ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
            return {nullptr, {}};
        }

        auto data = std::make_unique<uint8_t[]>(dataSize);

        size_t bytesRead = fread(data.get(), 1, dataSize, file);
        if (fclose(file) == EOF) {
            return {nullptr, {}};
        }
        if (bytesRead != dataSize) {
            GTEST_LOG_(ERROR) << "Failed to read complete file: " << path;
            errorCode = Media::ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
            return {nullptr, {}};
        }

        PixelBufferInfo bufferInfo;
        bufferInfo.width = width;
        bufferInfo.height = height;
        bufferInfo.bytesPerRow = rowBytes;
        bufferInfo.dataSize = dataSize;
        bufferInfo.data = data.get();

        errorCode = Media::SUCCESS;
        return {std::move(data), bufferInfo};
    }

    bool IsValidTiffHeader(uint8_t *data, size_t size)
    {
        if (size < MIN_TIFF_HEADER_SIZE || data == nullptr) {
            return false;
        }
        bool isLittleEndian = (data[0] == TIFF_LITTLE_ENDIAN_I && data[1] == TIFF_LITTLE_ENDIAN_I &&
                               data[2] == TIFF_MAGIC_NUMBER_1 && data[3] == TIFF_MAGIC_NUMBER_2);
        bool isBigEndian = (data[0] == TIFF_LITTLE_ENDIAN_M && data[1] == TIFF_LITTLE_ENDIAN_M &&
                            data[2] == TIFF_MAGIC_NUMBER_2 && data[3] == TIFF_MAGIC_NUMBER_1);
        return isLittleEndian || isBigEndian;
    }

    // Helper to encode PixelMap to TIFF and verify
    bool EncodePixelMapToTiffAndVerify(std::shared_ptr<Media::PixelMap> pixelMap, size_t bufferSize)
    {
        if (!pixelMap) {
            GTEST_LOG_(ERROR) << "PixelMap is null";
            return false;
        }

        auto outputData = std::make_unique<uint8_t[]>(bufferSize);
        auto stream = std::make_shared<BufferPackerStream>(outputData.get(), bufferSize);
        auto tiffEncoder = std::make_shared<TiffEncoder>();
        PlEncodeOptions opts;
        opts.format = "image/tiff";

        SetDefaultPlPackingOptionsForTiff(opts.tiffPackingOption);

        uint32_t ret = tiffEncoder->StartEncode(*stream.get(), opts);
        if (ret != SUCCESS) {
            GTEST_LOG_(ERROR) << "StartEncode failed, error: " << ret;
            return false;
        }
        ret = tiffEncoder->AddImage(*pixelMap.get());
        if (ret != SUCCESS) {
            GTEST_LOG_(ERROR) << "AddImage failed, error: " << ret;
            return false;
        }
        ret = tiffEncoder->FinalizeEncode();
        if (ret != SUCCESS) {
            GTEST_LOG_(ERROR) << "FinalizeEncode failed, error: " << ret;
            return false;
        }
        return IsValidTiffHeader(outputData.get(), bufferSize);
    }
};

/**
 * @tc.name: EncodeRGB888FileTest
 * @tc.desc: Test encoding RGB888 format to TIFF using TiffEncoder with file-based input
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, EncodeRGB888FileTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto pixelMap = LoadPixelMapFromFile(IMAGE_TIFF_RGB888_PATH, errorCode);
    ASSERT_NE(pixelMap, nullptr) << "Failed to load RGB888 image from " << IMAGE_TIFF_RGB888_PATH;
    ASSERT_EQ(errorCode, Media::SUCCESS);

    size_t bufferSize = pixelMap->GetWidth() * pixelMap->GetHeight() * 3 + 1024 * 1024;
    EXPECT_TRUE(EncodePixelMapToTiffAndVerify(pixelMap, bufferSize));
}

/**
 * @tc.name: EncodeY8FileTest
 * @tc.desc: Test encoding Y8 format to TIFF using TiffEncoder with file-based input
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, EncodeY8FileTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto pixelMap = LoadPixelMapFromFile(IMAGE_TIFF_Y8_PATH, errorCode);
    ASSERT_NE(pixelMap, nullptr) << "Failed to load Y8 image from " << IMAGE_TIFF_Y8_PATH;
    ASSERT_EQ(errorCode, Media::SUCCESS);

    size_t bufferSize = pixelMap->GetWidth() * pixelMap->GetHeight() * 2 + 1024 * 1024;
    EXPECT_TRUE(EncodePixelMapToTiffAndVerify(pixelMap, bufferSize));
}

/**
 * @tc.name: EncodeEmptyImageTest
 * @tc.desc: Test encoding empty image to TIFF (should fail with ERR_IMAGE_INVALID_PARAMETER)
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, EncodeEmptyImageTest, TestSize.Level3)
{
    auto tiffEncoder = std::make_shared<TiffEncoder>();
    auto outputData = std::make_unique<uint8_t[]>(SMALL_BUFFER_SIZE);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), SMALL_BUFFER_SIZE);
    PlEncodeOptions opts;
    opts.format = "image/tiff";
    SetDefaultPlPackingOptionsForTiff(opts.tiffPackingOption);
    uint32_t ret = tiffEncoder->StartEncode(*stream.get(), opts);
    EXPECT_EQ(ret, SUCCESS);
    ret = tiffEncoder->FinalizeEncode();
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: EncodeY1WithTiffEncoderTest
 * @tc.desc: Test PixelMap::Create with Y1 format (should fail as Y1 is not supported)
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, EncodeY1WithTiffEncoderTest, TestSize.Level3)
{
    Media::InitializationOptions initOpts;
    initOpts.size.width = 100;
    initOpts.size.height = 100;
    initOpts.pixelFormat = PixelFormat::Y1;
    initOpts.srcPixelFormat = PixelFormat::Y1;
    initOpts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    initOpts.editable = true;

    auto pixelMap = Media::PixelMap::Create(initOpts);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: EncodeOptionalTiffParamsTest
 * @tc.desc: Test encoding TIFF with optional parameters (default, compression only, all fields)
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, EncodeOptionalTiffParamsTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto pixelMap = LoadPixelMapFromFile(IMAGE_TIFF_RGB888_PATH, errorCode);
    ASSERT_NE(pixelMap, nullptr) << "Failed to load RGB888 image";
    ASSERT_EQ(errorCode, Media::SUCCESS);

    // Calculate buffer size based on image dimensions (same as EncodeRGB888FileTest)
    size_t bufferSize = pixelMap->GetWidth() * pixelMap->GetHeight() * 3 + 1024 * 1024;  // image size + 1MB

    auto tiffEncoder = std::make_shared<TiffEncoder>();
    auto outputData = std::make_unique<uint8_t[]>(bufferSize);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), bufferSize);

    // Test without setting any tiffPackingOption (all fields default to 0/-1)
    PlEncodeOptions opts;
    opts.format = "image/tiff";
    uint32_t ret = tiffEncoder->StartEncode(*stream.get(), opts);
    EXPECT_EQ(ret, SUCCESS);
    ret = tiffEncoder->AddImage(*pixelMap.get());
    EXPECT_EQ(ret, SUCCESS);
    ret = tiffEncoder->FinalizeEncode();
    EXPECT_EQ(ret, SUCCESS);

    // Test with only compression specified
    auto stream2 = std::make_shared<BufferPackerStream>(outputData.get(), bufferSize);
    PlEncodeOptions opts2;
    opts2.format = "image/tiff";
    opts2.tiffPackingOption.compression = 5;  // LZW
    ret = tiffEncoder->StartEncode(*stream2.get(), opts2);
    EXPECT_EQ(ret, SUCCESS);
    ret = tiffEncoder->AddImage(*pixelMap.get());
    EXPECT_EQ(ret, SUCCESS);
    ret = tiffEncoder->FinalizeEncode();
    EXPECT_EQ(ret, SUCCESS);

    // Test with all fields specified
    auto stream3 = std::make_shared<BufferPackerStream>(outputData.get(), bufferSize);
    PlEncodeOptions opts3;
    opts3.format = "image/tiff";
    SetDefaultPlPackingOptionsForTiff(opts3.tiffPackingOption);
    ret = tiffEncoder->StartEncode(*stream3.get(), opts3);
    EXPECT_EQ(ret, SUCCESS);
    ret = tiffEncoder->AddImage(*pixelMap.get());
    EXPECT_EQ(ret, SUCCESS);
    ret = tiffEncoder->FinalizeEncode();
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: EncoderReuseTest
 * @tc.desc: Test reusing TiffEncoder for multiple encoding operations
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, EncoderReuseTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto pixelMap = LoadPixelMapFromFile(IMAGE_TIFF_RGB888_PATH, errorCode);
    ASSERT_NE(pixelMap, nullptr) << "Failed to load RGB888 image";
    ASSERT_EQ(errorCode, Media::SUCCESS);

    // Calculate buffer size based on image dimensions (same as EncodeRGB888FileTest)
    size_t bufferSize = pixelMap->GetWidth() * pixelMap->GetHeight() * 3 + 1024 * 1024;  // image size + 1MB

    auto tiffEncoder = std::make_shared<TiffEncoder>();

    for (int i = 0; i < 3; i++) {
        auto outputData = std::make_unique<uint8_t[]>(bufferSize);
        auto stream = std::make_shared<BufferPackerStream>(outputData.get(), bufferSize);
        PlEncodeOptions opts;
        opts.format = "image/tiff";
        SetDefaultPlPackingOptionsForTiff(opts.tiffPackingOption);
        uint32_t ret = tiffEncoder->StartEncode(*stream.get(), opts);
        EXPECT_EQ(ret, SUCCESS);
        ret = tiffEncoder->AddImage(*pixelMap.get());
        EXPECT_EQ(ret, SUCCESS);
        ret = tiffEncoder->FinalizeEncode();
        EXPECT_EQ(ret, SUCCESS);
    }
}

// ========== ImagePacker TIFF Encoding Tests ==========

/**
 * @tc.name: ImagePackerTiffEncodeRGB888Test
 * @tc.desc: Test encoding RGB_888 format to TIFF using ImagePacker with file-based input
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, ImagePackerTiffEncodeRGB888Test, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto pixelMap = LoadPixelMapFromFile(IMAGE_TIFF_RGB888_PATH, errorCode);
    ASSERT_NE(pixelMap, nullptr) << "Failed to load RGB888 image";
    ASSERT_EQ(errorCode, Media::SUCCESS);

    // Calculate buffer size based on image dimensions
    size_t bufferSize = pixelMap->GetWidth() * pixelMap->GetHeight() * 3 + 1024 * 1024;  // image size + 1MB
    auto outputData = std::make_unique<uint8_t[]>(bufferSize);

    OHOS::Media::PackOption opts;
    opts.format = "image/tiff";
    SetDefaultTiffPackOption(opts);

    OHOS::Media::ImagePacker packer;
    uint32_t ret = packer.StartPacking(outputData.get(), bufferSize, opts);
    ASSERT_EQ(ret, OHOS::Media::SUCCESS);

    ret = packer.AddImage(*pixelMap.get());
    ASSERT_EQ(ret, OHOS::Media::SUCCESS);

    ret = packer.FinalizePacking();
    ASSERT_EQ(ret, OHOS::Media::SUCCESS);

    EXPECT_TRUE(IsValidTiffHeader(outputData.get(), bufferSize));
}

/**
 * @tc.name: ImagePackerTiffEncodeY8Test
 * @tc.desc: Test encoding Y8 format to TIFF using ImagePacker with file-based input
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, ImagePackerTiffEncodeY8Test, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto pixelMap = LoadPixelMapFromFile(IMAGE_TIFF_Y8_PATH, errorCode);
    ASSERT_NE(pixelMap, nullptr) << "Failed to load Y8 image";
    ASSERT_EQ(errorCode, Media::SUCCESS);

    auto outputData = std::make_unique<uint8_t[]>(SMALL_BUFFER_SIZE);

    OHOS::Media::PackOption opts;
    opts.format = "image/tiff";
    SetDefaultTiffPackOption(opts);

    OHOS::Media::ImagePacker packer;
    uint32_t ret = packer.StartPacking(outputData.get(), SMALL_BUFFER_SIZE, opts);
    ASSERT_EQ(ret, OHOS::Media::SUCCESS);

    ret = packer.AddImage(*pixelMap.get());
    ASSERT_EQ(ret, OHOS::Media::SUCCESS);

    ret = packer.FinalizePacking();
    ASSERT_EQ(ret, OHOS::Media::SUCCESS);

    EXPECT_TRUE(IsValidTiffHeader(outputData.get(), SMALL_BUFFER_SIZE));
}

/**
 * @tc.name: ImagePackerTiffEncodeWithDefaultOptionsTest
 * @tc.desc: Test TIFF encoding with default tiffPackingOptions using file-based input
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, ImagePackerTiffEncodeWithDefaultOptionsTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto pixelMap = LoadPixelMapFromFile(IMAGE_TIFF_RGB888_PATH, errorCode);
    ASSERT_NE(pixelMap, nullptr) << "Failed to load RGB888 image";
    ASSERT_EQ(errorCode, Media::SUCCESS);

    // Calculate buffer size based on image dimensions
    size_t bufferSize = pixelMap->GetWidth() * pixelMap->GetHeight() * 3 + 1024 * 1024;  // image size + 1MB
    auto outputData = std::make_unique<uint8_t[]>(bufferSize);

    OHOS::Media::PackOption opts;
    opts.format = "image/tiff";

    OHOS::Media::ImagePacker packer;
    uint32_t ret = packer.StartPacking(outputData.get(), bufferSize, opts);
    ASSERT_EQ(ret, OHOS::Media::SUCCESS);

    ret = packer.AddImage(*pixelMap.get());
    ASSERT_EQ(ret, OHOS::Media::SUCCESS);

    ret = packer.FinalizePacking();
    ASSERT_EQ(ret, OHOS::Media::SUCCESS);

    EXPECT_TRUE(IsValidTiffHeader(outputData.get(), bufferSize));
}

/**
 * @tc.name: ImagePackerTiffEncodeWithCustomOptionsTest
 * @tc.desc: Test TIFF encoding with custom tiffPackingOptions using file-based input
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, ImagePackerTiffEncodeWithCustomOptionsTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto pixelMap = LoadPixelMapFromFile(IMAGE_TIFF_RGB888_PATH, errorCode);
    ASSERT_NE(pixelMap, nullptr) << "Failed to load RGB888 image";
    ASSERT_EQ(errorCode, Media::SUCCESS);

    // Calculate buffer size based on image dimensions
    size_t bufferSize = pixelMap->GetWidth() * pixelMap->GetHeight() * 3 + 1024 * 1024;  // image size + 1MB
    auto outputData = std::make_unique<uint8_t[]>(bufferSize);

    OHOS::Media::PackOption opts;
    opts.format = "image/tiff";
    opts.tiffPackingOption.orientation = 1;
    opts.tiffPackingOption.xResolution = 300.0f;
    opts.tiffPackingOption.yResolution = 300.0f;
    opts.tiffPackingOption.resolutionUnit = 2;

    OHOS::Media::ImagePacker packer;
    uint32_t ret = packer.StartPacking(outputData.get(), bufferSize, opts);
    ASSERT_EQ(ret, OHOS::Media::SUCCESS);

    ret = packer.AddImage(*pixelMap.get());
    ASSERT_EQ(ret, OHOS::Media::SUCCESS);

    ret = packer.FinalizePacking();
    ASSERT_EQ(ret, OHOS::Media::SUCCESS);

    EXPECT_TRUE(IsValidTiffHeader(outputData.get(), bufferSize));
}

/**
 * @tc.name: ImagePackerTiffEncodeWithCustomOptionsTest
 * @tc.desc: Test encoding Y1 file from disk using PackBinaryImageToTiffData
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, EncodeY1FileTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto y1Buffer = LoadY1DataFromFile(IMAGE_TIFF_Y1_PATH, errorCode);
    ASSERT_TRUE(y1Buffer.IsValid()) << "Failed to load Y1 data from " << IMAGE_TIFF_Y1_PATH;
    ASSERT_EQ(errorCode, Media::SUCCESS);
    PixelBufferInfo& bufferInfo = y1Buffer.bufferInfo;

    auto outputData = std::make_unique<uint8_t[]>(SMALL_BUFFER_SIZE);
    uint32_t outputSize = SMALL_BUFFER_SIZE;

    OHOS::Media::PackingOptionsForTiff opts;
    SetDefaultPackingOptionsForTiff(opts);

    OHOS::Media::ImagePacker packer;
    uint32_t ret = packer.PackBinaryImageToTiffData(bufferInfo, opts, outputData.get(), outputSize);

    EXPECT_EQ(ret, OHOS::Media::SUCCESS);
    EXPECT_GT(outputSize, 0u);
    EXPECT_TRUE(IsValidTiffHeader(outputData.get(), outputSize));
}

/**
 * @tc.name: PackBinaryImageToTiffDataNullTest
 * @tc.desc: Test PackBinaryImageToTiffData with null buffer
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, PackBinaryImageToTiffDataNullTest, TestSize.Level3)
{
    PixelBufferInfo bufferInfo;
    bufferInfo.data = nullptr;
    bufferInfo.dataSize = 0;
    bufferInfo.width = TEST_WIDTH;
    bufferInfo.height = TEST_HEIGHT;

    auto outputData = std::make_unique<uint8_t[]>(SMALL_BUFFER_SIZE);
    uint32_t outputSize = SMALL_BUFFER_SIZE;

    OHOS::Media::PackingOptionsForTiff tiffOpts;
    OHOS::Media::ImagePacker packer;

    uint32_t ret = packer.PackBinaryImageToTiffData(bufferInfo, tiffOpts, outputData.get(), outputSize);
    EXPECT_EQ(ret, OHOS::Media::ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: PackBinaryImageToTiffDataZeroSizeTest
 * @tc.desc: Test PackBinaryImageToTiffData with zero dimensions
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, PackBinaryImageToTiffDataZeroSizeTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto y1Buffer = LoadY1DataFromFile(IMAGE_TIFF_Y1_PATH, errorCode);
    ASSERT_TRUE(y1Buffer.IsValid()) << "Failed to load Y1 data from " << IMAGE_TIFF_Y1_PATH;
    PixelBufferInfo& bufferInfo = y1Buffer.bufferInfo;

    // Set width to 0 to test zero dimension handling
    bufferInfo.width = 0;

    auto outputData = std::make_unique<uint8_t[]>(SMALL_BUFFER_SIZE);
    uint32_t outputSize = SMALL_BUFFER_SIZE;

    OHOS::Media::PackingOptionsForTiff tiffOpts;
    OHOS::Media::ImagePacker packer;

    uint32_t ret = packer.PackBinaryImageToTiffData(bufferInfo, tiffOpts, outputData.get(), outputSize);
    EXPECT_EQ(ret, OHOS::Media::ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: PackBinaryImageToTiffDataShortBytesPerRowTest
 * @tc.desc: Test PackBinaryImageToTiffData rejects bytesPerRow smaller than Y1 scanline bytes
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, PackBinaryImageToTiffDataShortBytesPerRowTest, TestSize.Level3)
{
    uint8_t inputData[] = {0xFF};
    PixelBufferInfo bufferInfo;
    bufferInfo.data = inputData;
    bufferInfo.dataSize = sizeof(inputData);
    bufferInfo.width = 16;
    bufferInfo.height = 1;
    bufferInfo.bytesPerRow = 1;

    auto outputData = std::make_unique<uint8_t[]>(SMALL_BUFFER_SIZE);
    uint32_t outputSize = SMALL_BUFFER_SIZE;

    OHOS::Media::PackingOptionsForTiff tiffOpts;
    OHOS::Media::ImagePacker packer;

    uint32_t ret = packer.PackBinaryImageToTiffData(bufferInfo, tiffOpts, outputData.get(), outputSize);
    EXPECT_EQ(ret, OHOS::Media::ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: PackBinaryImageToTiffDataNoMetadataTest
 * @tc.desc: Test PackBinaryImageToTiffData without optional metadata using file-based Y1 data
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, PackBinaryImageToTiffDataNoMetadataTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto y1Buffer = LoadY1DataFromFile(IMAGE_TIFF_Y1_PATH, errorCode);
    ASSERT_TRUE(y1Buffer.IsValid()) << "Failed to load Y1 data from " << IMAGE_TIFF_Y1_PATH;
    PixelBufferInfo& bufferInfo = y1Buffer.bufferInfo;

    auto outputData = std::make_unique<uint8_t[]>(SMALL_BUFFER_SIZE);
    uint32_t outputSize = SMALL_BUFFER_SIZE;

    // Use PackingOptionsForTiff with default compression (will use G4)
    OHOS::Media::PackingOptionsForTiff tiffOpts;
    OHOS::Media::ImagePacker packer;

    uint32_t ret = packer.PackBinaryImageToTiffData(bufferInfo, tiffOpts, outputData.get(), outputSize);
    EXPECT_EQ(ret, OHOS::Media::SUCCESS);
    EXPECT_GT(outputSize, 0u);
    EXPECT_TRUE(IsValidTiffHeader(outputData.get(), outputSize));
}

/**
 * @tc.name: PackBinaryImageToTiffDataInvalidCompressionNoneTest
 * @tc.desc: Test PackBinaryImageToTiffData with invalid COMPRESSION_NONE using file-based Y1 data
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, PackBinaryImageToTiffDataInvalidCompressionNoneTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto y1Buffer = LoadY1DataFromFile(IMAGE_TIFF_Y1_PATH, errorCode);
    ASSERT_TRUE(y1Buffer.IsValid()) << "Failed to load Y1 data from " << IMAGE_TIFF_Y1_PATH;
    PixelBufferInfo& bufferInfo = y1Buffer.bufferInfo;

    auto outputData = std::make_unique<uint8_t[]>(SMALL_BUFFER_SIZE);
    uint32_t outputSize = SMALL_BUFFER_SIZE;
    OHOS::Media::PackingOptionsForTiff tiffOpts;
    tiffOpts.compression = COMPRESSION_NONE;  // Invalid: must be -1, 3, or 4
    OHOS::Media::ImagePacker packer;

    uint32_t ret = packer.PackBinaryImageToTiffData(bufferInfo, tiffOpts, outputData.get(), outputSize);
    EXPECT_EQ(ret, OHOS::Media::ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: PackBinaryImageToTiffDataInvalidCompressionLzwTest
 * @tc.desc: Test PackBinaryImageToTiffData with invalid COMPRESSION_LZW using file-based Y1 data
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, PackBinaryImageToTiffDataInvalidCompressionLzwTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto y1Buffer = LoadY1DataFromFile(IMAGE_TIFF_Y1_PATH, errorCode);
    ASSERT_TRUE(y1Buffer.IsValid()) << "Failed to load Y1 data from " << IMAGE_TIFF_Y1_PATH;
    PixelBufferInfo& bufferInfo = y1Buffer.bufferInfo;

    auto outputData = std::make_unique<uint8_t[]>(SMALL_BUFFER_SIZE);
    uint32_t outputSize = SMALL_BUFFER_SIZE;
    OHOS::Media::PackingOptionsForTiff tiffOpts;
    tiffOpts.compression = COMPRESSION_LZW;  // Invalid for Y1: must be -1, 3, or 4
    OHOS::Media::ImagePacker packer;

    uint32_t ret = packer.PackBinaryImageToTiffData(bufferInfo, tiffOpts, outputData.get(), outputSize);
    EXPECT_EQ(ret, OHOS::Media::ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: PackBinaryImageToTiffDataCompressionCcittfax3Test
 * @tc.desc: Test PackBinaryImageToTiffData with COMPRESSION_CCITTFAX3 using file-based Y1 data
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, PackBinaryImageToTiffDataCompressionCcittfax3Test, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto y1Buffer = LoadY1DataFromFile(IMAGE_TIFF_Y1_PATH, errorCode);
    ASSERT_TRUE(y1Buffer.IsValid()) << "Failed to load Y1 data from " << IMAGE_TIFF_Y1_PATH;
    PixelBufferInfo& bufferInfo = y1Buffer.bufferInfo;

    auto outputData = std::make_unique<uint8_t[]>(SMALL_BUFFER_SIZE);
    uint32_t outputSize = SMALL_BUFFER_SIZE;
    OHOS::Media::PackingOptionsForTiff tiffOpts;
    tiffOpts.compression = COMPRESSION_CCITTFAX3;
    OHOS::Media::ImagePacker packer;

    uint32_t ret = packer.PackBinaryImageToTiffData(bufferInfo, tiffOpts, outputData.get(), outputSize);
    EXPECT_EQ(ret, OHOS::Media::SUCCESS);
    EXPECT_TRUE(IsValidTiffHeader(outputData.get(), outputSize));
}

/**
 * @tc.name: PackBinaryImageToTiffDataCompressionCcittfax4Test
 * @tc.desc: Test PackBinaryImageToTiffData with COMPRESSION_CCITTFAX4 using file-based Y1 data
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, PackBinaryImageToTiffDataCompressionCcittfax4Test, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto y1Buffer = LoadY1DataFromFile(IMAGE_TIFF_Y1_PATH, errorCode);
    ASSERT_TRUE(y1Buffer.IsValid()) << "Failed to load Y1 data from " << IMAGE_TIFF_Y1_PATH;
    PixelBufferInfo& bufferInfo = y1Buffer.bufferInfo;

    auto outputData = std::make_unique<uint8_t[]>(SMALL_BUFFER_SIZE);
    uint32_t outputSize = SMALL_BUFFER_SIZE;
    OHOS::Media::PackingOptionsForTiff tiffOpts;
    tiffOpts.compression = COMPRESSION_CCITTFAX4;
    OHOS::Media::ImagePacker packer;

    uint32_t ret = packer.PackBinaryImageToTiffData(bufferInfo, tiffOpts, outputData.get(), outputSize);
    EXPECT_EQ(ret, OHOS::Media::SUCCESS);
    EXPECT_TRUE(IsValidTiffHeader(outputData.get(), outputSize));
}

/**
 * @tc.name: PackBinaryImageToTiffDataDefaultCompressionTest
 * @tc.desc: Test PackBinaryImageToTiffData with default compression (-1) using file-based Y1 data
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, PackBinaryImageToTiffDataDefaultCompressionTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto y1Buffer = LoadY1DataFromFile(IMAGE_TIFF_Y1_PATH, errorCode);
    ASSERT_TRUE(y1Buffer.IsValid()) << "Failed to load Y1 data from " << IMAGE_TIFF_Y1_PATH;
    PixelBufferInfo& bufferInfo = y1Buffer.bufferInfo;

    auto outputData = std::make_unique<uint8_t[]>(SMALL_BUFFER_SIZE);
    uint32_t outputSize = SMALL_BUFFER_SIZE;
    OHOS::Media::PackingOptionsForTiff tiffOpts;
    tiffOpts.compression = -1;  // Not specified: will default to G4
    OHOS::Media::ImagePacker packer;

    uint32_t ret = packer.PackBinaryImageToTiffData(bufferInfo, tiffOpts, outputData.get(), outputSize);
    EXPECT_EQ(ret, OHOS::Media::SUCCESS);
    EXPECT_TRUE(IsValidTiffHeader(outputData.get(), outputSize));
}

/**
 * @tc.name: PackBinaryImageToTiffFileTest
 * @tc.desc: Test PackBinaryImageToTiffFile using file-based Y1 data
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, PackBinaryImageToTiffFileTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto y1Buffer = LoadY1DataFromFile(IMAGE_TIFF_Y1_PATH, errorCode);
    ASSERT_TRUE(y1Buffer.IsValid()) << "Failed to load Y1 data from " << IMAGE_TIFF_Y1_PATH;
    PixelBufferInfo& bufferInfo = y1Buffer.bufferInfo;

    // Create temporary file
    const char* tempFile = "/data/local/tmp/image/test_y1_output.tiff";
    int fd = open(tempFile, O_CREAT | O_RDWR | O_TRUNC, 0644);
    ASSERT_NE(fd, -1) << "Failed to create temp file";

    OHOS::Media::PackingOptionsForTiff tiffOpts;
    SetDefaultPackingOptionsForTiff(tiffOpts);
    OHOS::Media::ImagePacker packer;

    uint32_t ret = packer.PackBinaryImageToTiffFile(bufferInfo, fd, tiffOpts);
    close(fd);
    EXPECT_EQ(ret, OHOS::Media::SUCCESS);

    // Verify file exists and has valid TIFF header
    FILE* file = fopen(tempFile, "rb");
    ASSERT_NE(file, nullptr) << "Failed to open output file";
    uint8_t header[MIN_TIFF_HEADER_SIZE];
    size_t bytesRead = fread(header, TIFF_HEADER_ELEMENT_SIZE, MIN_TIFF_HEADER_SIZE, file);
    fclose(file);

    EXPECT_EQ(bytesRead, static_cast<size_t>(MIN_TIFF_HEADER_SIZE));
    EXPECT_TRUE(IsValidTiffHeader(header, MIN_TIFF_HEADER_SIZE));

    // Clean up
    unlink(tempFile);
}

/**
 * @tc.name: ImagePackerTiffOptionsWithJpegFormatTest
 * @tc.desc: Test that setting tiffPackingOptions with JPEG format fails encoding
 * @tc.type: FUNC
 */
HWTEST_F(TiffEncoderTest, ImagePackerTiffOptionsWithJpegFormatTest, TestSize.Level3)
{
    uint32_t errorCode = 0;
    auto pixelMap = LoadPixelMapFromFile(IMAGE_TIFF_Y8_PATH, errorCode);
    ASSERT_NE(pixelMap, nullptr) << "Failed to load RGB888 image";
    ASSERT_EQ(errorCode, Media::SUCCESS);

    size_t bufferSize = pixelMap->GetWidth() * pixelMap->GetHeight() * 3 + 1024 * 1024;
    auto outputData = std::make_unique<uint8_t[]>(bufferSize);

    OHOS::Media::PackOption opts;
    opts.format = "image/jpeg";
    opts.tiffPackingOption.orientation = 1;
    opts.tiffPackingOption.xResolution = 300.0f;
    opts.tiffPackingOption.yResolution = 300.0f;
    opts.tiffPackingOption.resolutionUnit = 2;

    OHOS::Media::ImagePacker packer;
    uint32_t ret = packer.StartPacking(outputData.get(), bufferSize, opts);
    EXPECT_EQ(ret, OHOS::Media::SUCCESS);
    ret = packer.AddImage(*pixelMap.get());
    EXPECT_EQ(ret, OHOS::Media::ERR_IMAGE_INVALID_PARAMETER);
}
} // namespace ImagePlugin
} // namespace OHOS
