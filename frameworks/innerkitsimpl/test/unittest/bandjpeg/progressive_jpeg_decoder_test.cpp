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

/**
 * Unit tests for the progressive JPEG fast path.
 *
 * The fast path decodes through libfast_image.so. libfast_image.so is dlopen'ed by
 * FASTManager, so the tests inject stub entry points into the singleton instead of
 * relying on the real library being present with a given ABI. This covers:
 *
 *   1. Entry selection: the resolved fast::image::bandjpeg entry points are called, and a
 *      missing entry degrades to the software decode path (ERR_IMAGE_DATA_UNSUPPORT).
 *   2. Result mapping: IMAGE_ErrorCode::SUCCESS/SUCCESS_PARTIAL mean success, every other
 *      value means "fall back to software decode".
 *   3. Argument marshalling: dimensions, strides and the pixel format translation
 *      (PixelFormat -> RGBFormat/YUVFormat) passed to the native entry point.
 *   4. Region decode (DecodeImageRegion) error code mapping.
 *   5. Pure geometry/plan helpers (region scale selection, output size rounding,
 *      RGB/YUV decode plan gating, byte count and row stride).
 *   6. GetJpegInputData stream handling for buffer, copy, oversize and error paths.
 *   7. IsProgressiveJpeg detection on real progressive and baseline JPEG resources.
 *
 * Only the current ABI is exercised: the legacy FastErrCode exports are being retired, so
 * these tests do not pin the fallback behaviour. The dlsym() names themselves are not
 * asserted either: FASTManager resolves them from the real libfast_image.so on device.
 */

#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include <dlfcn.h>

#include <gtest/gtest.h>

#include "include/codec/SkCodec.h"
#include "include/codec/SkEncodedImageFormat.h"
#include "include/core/SkData.h"
#include "include/core/SkImageInfo.h"

// FASTManager keeps the resolved entry points and the initialized flag private;
// the tests inject stubs into the singleton, so they need access to those fields.
#define private public
#include "bandjpeg/fast_manager.h"
#undef private

#include "bandjpeg/progressive_jpeg_decoder.h"
#include "jpeg_yuv_decoder/jpeg_decoder_yuv.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace ImagePlugin {
namespace {
constexpr char IMAGE_INPUT_PATH[] = "/data/local/tmp/image/";
// 2160x3840, progressive, long side above the bandjpeg fast path threshold (1080).
constexpr char PROGRESSIVE_JPEG_FILE[] = "progressivejpg.jpg";
// 800x500, baseline, long side below the bandjpeg fast path threshold.
constexpr char BASELINE_JPEG_FILE[] = "800-500.jpg";
// 3072x4096, baseline, long side above the bandjpeg fast path threshold.
constexpr char LARGE_BASELINE_JPEG_FILE[] = "jpeg_no_thumbnail.jpg";
constexpr char PNG_FILE[] = "test.png";
constexpr uint64_t MAX_JPEG_BUFFER_SIZE = 100ULL * 1024ULL * 1024ULL;
constexpr uint32_t RGB_BYTES_PER_PIXEL = 3;
constexpr uint32_t COLOR_BYTES_PER_PIXEL = 4;
constexpr uint32_t YUV_BYTES_PER_PIXEL_NUMERATOR = 3;
constexpr uint32_t YUV_BYTES_PER_PIXEL_DENOMINATOR = 2;
constexpr size_t JPEG_INPUT_BUFFER_SIZE = 16;

// progressivejpg.jpg geometry and the scaled sizes derived from it.
constexpr uint32_t PROGRESSIVE_IMAGE_WIDTH = 2160;
constexpr uint32_t PROGRESSIVE_IMAGE_HEIGHT = 3840;
// Output size denominators used to request a half, quarter or eighth size decode.
constexpr int32_t SCALE_HALF = 2;
constexpr int32_t SCALE_QUARTER = 4;
constexpr int32_t SCALE_EIGHTH = 8;

// Small frame used by the fast path entry tests.
constexpr uint32_t SMALL_IMAGE_WIDTH = 4;
constexpr uint32_t SMALL_IMAGE_HEIGHT = 4;
constexpr uint32_t SMALL_IMAGE_BYTES = SMALL_IMAGE_WIDTH * SMALL_IMAGE_HEIGHT * COLOR_BYTES_PER_PIXEL;
constexpr uint32_t SMALL_IMAGE_STRIDE = SMALL_IMAGE_WIDTH * COLOR_BYTES_PER_PIXEL;
constexpr uint32_t SMALL_IMAGE_CHROMA_WIDTH = (SMALL_IMAGE_WIDTH + 1) / 2;
constexpr size_t SMALL_IMAGE_UV_OFFSET = static_cast<size_t>(SMALL_IMAGE_WIDTH) * SMALL_IMAGE_HEIGHT;
constexpr size_t SMALL_IMAGE_UV_STRIDE = static_cast<size_t>(SMALL_IMAGE_CHROMA_WIDTH) * 2;

// Odd sized NV21 frame, its chroma planes round up to whole samples.
constexpr uint32_t ODD_YUV_WIDTH = 5;
constexpr uint32_t ODD_YUV_HEIGHT = 3;
constexpr uint32_t ODD_YUV_CHROMA_WIDTH = (ODD_YUV_WIDTH + 1) / 2;
constexpr uint32_t ODD_YUV_CHROMA_HEIGHT = (ODD_YUV_HEIGHT + 1) / 2;
constexpr size_t ODD_YUV_UV_STRIDE = static_cast<size_t>(ODD_YUV_CHROMA_WIDTH) * 2;
constexpr size_t ODD_YUV_UV_OFFSET = static_cast<size_t>(ODD_YUV_WIDTH) * ODD_YUV_HEIGHT;

// Frame used to check the argument marshalling of the RGB entry.
constexpr uint32_t ARG_IMAGE_WIDTH = 8;
constexpr uint32_t ARG_IMAGE_HEIGHT = 6;
constexpr uint32_t ARG_IMAGE_BYTES = ARG_IMAGE_WIDTH * ARG_IMAGE_HEIGHT * COLOR_BYTES_PER_PIXEL;
constexpr uint32_t ARG_IMAGE_STRIDE = ARG_IMAGE_WIDTH * COLOR_BYTES_PER_PIXEL;
constexpr uint8_t ARG_FILL_BYTE = 0xAB;

// Geometry passed through DecodeRegion.
constexpr uint32_t REGION_X = 10;
constexpr uint32_t REGION_Y = 20;
constexpr uint32_t REGION_WIDTH = 30;
constexpr uint32_t REGION_HEIGHT = 40;
constexpr size_t REGION_STRIDE = 120;
constexpr uint32_t MAPPING_REGION_SIZE = 16;
constexpr size_t MAPPING_REGION_STRIDE = 64;
constexpr uint32_t UNAVAILABLE_REGION_SIZE = 8;

// Odd source used to check the round-up behaviour of the full image region output.
constexpr uint32_t ODD_SOURCE_WIDTH = 1001;
constexpr uint32_t ODD_SOURCE_HEIGHT = 801;
constexpr uint32_t ODD_DESIRED_WIDTH = 125;
constexpr uint32_t ODD_DESIRED_HEIGHT = 100;
constexpr uint32_t ODD_OUTPUT_WIDTH = 126;   // ceil(1001 / 8)
constexpr uint32_t ODD_OUTPUT_HEIGHT = 101;  // ceil(801 / 8)

// Sub-region used to check that an unscaled crop keeps the region geometry.
constexpr uint32_t SUBREGION_SOURCE_WIDTH = 1000;
constexpr uint32_t SUBREGION_SOURCE_HEIGHT = 1000;
constexpr uint32_t SUBREGION_X = 100;
constexpr uint32_t SUBREGION_Y = 200;
constexpr uint32_t SUBREGION_WIDTH = 300;
constexpr uint32_t SUBREGION_HEIGHT = 200;

// Sub-region used to check that a scaled crop truncates and never collapses to zero.
constexpr uint32_t FLOOR_SOURCE_SIZE = 200;
constexpr uint32_t FLOOR_REGION_WIDTH = 7;
constexpr uint32_t FLOOR_REGION_HEIGHT = 5;

// Valid geometry that the invalid geometry tests derive from.
constexpr uint32_t GEOMETRY_SOURCE_WIDTH = 1000;
constexpr uint32_t GEOMETRY_SOURCE_HEIGHT = 800;
constexpr uint32_t GEOMETRY_DESIRED_WIDTH = 500;
constexpr uint32_t GEOMETRY_DESIRED_HEIGHT = 400;

// Caller owned storage of the rejected BuildRgbRegionParams call.
constexpr uint32_t SENTINEL_REGION_X = 7;
constexpr uint32_t SENTINEL_REGION_Y = 9;
constexpr uint32_t SENTINEL_DST_WIDTH = 11;
constexpr uint32_t SENTINEL_DST_HEIGHT = 13;
constexpr size_t SENTINEL_STRIDE = 32;
constexpr size_t STORAGE_BYTES = 64;

// Stream fixtures of the GetJpegInputData tests.
constexpr uint8_t BUFFER_FILL_BYTE = 0x11;
constexpr uint8_t COPY_FILL_BYTE = 0x5A;
constexpr size_t COPY_STREAM_BYTES = 8;

// Frame used by the byte count and row stride tests.
constexpr uint32_t BYTE_COUNT_WIDTH = 100;
constexpr uint32_t BYTE_COUNT_HEIGHT = 50;

struct RgbEntryArgs {
    const uint8_t *buffer = nullptr;
    size_t size = 0;
    uint8_t *dst = nullptr;
    uint32_t width = 0;
    uint32_t height = 0;
    size_t stride = 0;
    fast::image::RGBFormat format = fast::image::RGBFormat::RGBA8888;
};

struct YuvEntryArgs {
    const uint8_t *buffer = nullptr;
    size_t size = 0;
    uint8_t *dstY = nullptr;
    uint8_t *dstUV = nullptr;
    uint32_t width = 0;
    uint32_t height = 0;
    size_t yStride = 0;
    size_t uvStride = 0;
    fast::image::YUVFormat format = fast::image::YUVFormat::NV12;
};

// Records what the progressive JPEG fast path forwards to the native entry points.
struct FastEntryStub {
    RgbEntryArgs rgb;
    YuvEntryArgs yuv;
    fast::image::bandjpeg::RegionDecodeParams region;
    uint32_t rgbCalls = 0;
    uint32_t yuvCalls = 0;
    uint32_t regionCalls = 0;
    fast::image::IMAGE_ErrorCode rgbResult = fast::image::IMAGE_ErrorCode::SUCCESS;
    fast::image::IMAGE_ErrorCode yuvResult = fast::image::IMAGE_ErrorCode::SUCCESS;
    fast::image::IMAGE_ErrorCode regionResult = fast::image::IMAGE_ErrorCode::SUCCESS;
};

FastEntryStub g_stub;

fast::image::IMAGE_ErrorCode StubDecodeImage(const uint8_t *buffer, size_t size, uint8_t *dst, uint32_t width,
    uint32_t height, size_t stride, fast::image::RGBFormat format)
{
    ++g_stub.rgbCalls;
    g_stub.rgb.buffer = buffer;
    g_stub.rgb.size = size;
    g_stub.rgb.dst = dst;
    g_stub.rgb.width = width;
    g_stub.rgb.height = height;
    g_stub.rgb.stride = stride;
    g_stub.rgb.format = format;
    return g_stub.rgbResult;
}

fast::image::IMAGE_ErrorCode StubDecodeImageYuv(const uint8_t *buffer, size_t size, uint8_t *dstY, uint8_t *dstUV,
    uint32_t width, uint32_t height, size_t yStride, size_t uvStride, fast::image::YUVFormat format)
{
    ++g_stub.yuvCalls;
    g_stub.yuv.buffer = buffer;
    g_stub.yuv.size = size;
    g_stub.yuv.dstY = dstY;
    g_stub.yuv.dstUV = dstUV;
    g_stub.yuv.width = width;
    g_stub.yuv.height = height;
    g_stub.yuv.yStride = yStride;
    g_stub.yuv.uvStride = uvStride;
    g_stub.yuv.format = format;
    return g_stub.yuvResult;
}

fast::image::IMAGE_ErrorCode StubDecodeImageRegion(const fast::image::bandjpeg::RegionDecodeParams &params)
{
    ++g_stub.regionCalls;
    g_stub.region = params;
    return g_stub.regionResult;
}

std::unique_ptr<SkCodec> MakeCodec(const char *fileName)
{
    const std::string path = std::string(IMAGE_INPUT_PATH) + fileName;
    auto data = SkData::MakeFromFileName(path.c_str());
    if (data == nullptr) {
        return nullptr;
    }
    return SkCodec::MakeFromData(data);
}

SkImageInfo MakeRgbaImageInfo(uint32_t width, uint32_t height)
{
    return SkImageInfo::Make(static_cast<int32_t>(width), static_cast<int32_t>(height), kRGBA_8888_SkColorType,
        kOpaque_SkAlphaType);
}

Size MakeSize(uint32_t width, uint32_t height)
{
    return { static_cast<int32_t>(width), static_cast<int32_t>(height) };
}

// Geometry of a region decode request; a zero desired size asks for the native full size.
struct RegionRequest {
    uint32_t sourceWidth = 0;
    uint32_t sourceHeight = 0;
    uint32_t regionX = 0;
    uint32_t regionY = 0;
    uint32_t regionWidth = 0;
    uint32_t regionHeight = 0;
    uint32_t desiredWidth = 0;
    uint32_t desiredHeight = 0;
};

ProgressiveJpegDecoder::RgbRegionOptions MakeRegionOptions(const RegionRequest &request)
{
    ProgressiveJpegDecoder::RgbRegionOptions options;
    options.sourceWidth = static_cast<int32_t>(request.sourceWidth);
    options.sourceHeight = static_cast<int32_t>(request.sourceHeight);
    options.regionX = static_cast<int32_t>(request.regionX);
    options.regionY = static_cast<int32_t>(request.regionY);
    options.regionWidth = static_cast<int32_t>(request.regionWidth);
    options.regionHeight = static_cast<int32_t>(request.regionHeight);
    options.desiredWidth = static_cast<int32_t>(request.desiredWidth);
    options.desiredHeight = static_cast<int32_t>(request.desiredHeight);
    return options;
}

ProgressiveJpegDecoder::RgbDecodePlan MakeRgbPlan(uint32_t width, uint32_t height,
    PixelFormat format = PixelFormat::RGBA_8888)
{
    ProgressiveJpegDecoder::RgbDecodePlan plan;
    plan.dstInfo = MakeRgbaImageInfo(width, height);
    plan.pixelFormat = format;
    plan.isRgb888Output = format == PixelFormat::RGB_888;
    plan.byteCount = ProgressiveJpegDecoder::GetRgbOutputByteCount(plan.dstInfo, plan.isRgb888Output);
    return plan;
}

ProgressiveJpegDecoder::RgbDecodeOptions MakeRgbDecodeOptions(SkCodec *codec, const SkImageInfo &dstInfo)
{
    ProgressiveJpegDecoder::RgbDecodeOptions options;
    options.codec = codec;
    options.srcInfo = codec->getInfo();
    options.dstInfo = dstInfo;
    options.pixelFormat = PixelFormat::RGBA_8888;
    options.allocatorType = AllocatorType::DEFAULT;
    options.ifSourceCompleted = true;
    return options;
}

ProgressiveJpegDecoder::YuvDecodeOptions MakeYuvDecodeOptions(SkCodec *codec, const Size &desiredSize)
{
    ProgressiveJpegDecoder::YuvDecodeOptions options;
    options.codec = codec;
    options.sourceSize = { codec->getInfo().width(), codec->getInfo().height() };
    options.desiredSize = desiredSize;
    options.pixelFormat = PixelFormat::NV12;
    options.ifSourceCompleted = true;
    return options;
}

void ExpectInvalidRegionOptions(const ProgressiveJpegDecoder::RgbRegionOptions &options)
{
    fast::image::bandjpeg::RegionDecodeParams params;
    EXPECT_FALSE(ProgressiveJpegDecoder::BuildRgbRegionParams(options, params));
}

ProgressiveJpegDecoder::JpegInputData MakeJpegInputData(uint8_t *buffer, uint32_t size)
{
    ProgressiveJpegDecoder::JpegInputData jpegData;
    jpegData.buffer = buffer;
    jpegData.bufferSize = size;
    return jpegData;
}

std::vector<uint8_t> MakeYuvBuffer(uint32_t width, uint32_t height)
{
    const uint64_t size = static_cast<uint64_t>(width) * height * YUV_BYTES_PER_PIXEL_NUMERATOR /
        YUV_BYTES_PER_PIXEL_DENOMINATOR;
    return std::vector<uint8_t>(static_cast<size_t>(size), 0);
}

void ContextFreeStub(void *, void *, uint32_t)
{
}

class MockInputDataStream : public InputDataStream {
public:
    bool Read(uint32_t, DataStreamBuffer &) override
    {
        return true;
    }

    bool Read(uint32_t, uint8_t *, uint32_t, uint32_t &) override
    {
        return true;
    }

    bool Peek(uint32_t, DataStreamBuffer &) override
    {
        return true;
    }

    bool Peek(uint32_t, uint8_t *, uint32_t, uint32_t &) override
    {
        return true;
    }

    uint32_t Tell() override
    {
        return 0;
    }

    bool Seek(uint32_t) override
    {
        return true;
    }

    uint32_t GetStreamType() override
    {
        return streamType_;
    }

    uint8_t *GetDataPtr() override
    {
        return dataPtr_;
    }

    size_t GetStreamSize() override
    {
        return streamSize_;
    }

    void SetStreamType(uint32_t streamType)
    {
        streamType_ = streamType;
    }

    void SetDataPtr(uint8_t *dataPtr)
    {
        dataPtr_ = dataPtr;
    }

    void SetStreamSize(size_t streamSize)
    {
        streamSize_ = streamSize;
    }

private:
    uint32_t streamType_ = BUFFER_SOURCE_TYPE;
    uint8_t *dataPtr_ = nullptr;
    size_t streamSize_ = 0;
};

class ProgressiveJpegDecoderTest : public testing::Test {
public:
    void SetUp() override
    {
        FASTManager &manager = FASTManager::GetInstance();
        savedIsInitialized_ = manager.isInitialized_;
        savedDecodeImage_ = manager.DecodeImage;
        savedDecodeImageYuv_ = manager.DecodeImageYUV;
        savedDecodeImageLegacy_ = manager.DecodeImageLegacy;
        savedDecodeImageYuvLegacy_ = manager.DecodeImageYUVLegacy;
        savedDecodeImageRegion_ = manager.DecodeImageRegion;
        savedColorSpaceConvert_ = manager.ColorSpaceConvert;
        ResetFastManager();
    }

    void TearDown() override
    {
        FASTManager &manager = FASTManager::GetInstance();
        manager.isInitialized_ = savedIsInitialized_;
        manager.DecodeImage = savedDecodeImage_;
        manager.DecodeImageYUV = savedDecodeImageYuv_;
        manager.DecodeImageLegacy = savedDecodeImageLegacy_;
        manager.DecodeImageYUVLegacy = savedDecodeImageYuvLegacy_;
        manager.DecodeImageRegion = savedDecodeImageRegion_;
        manager.ColorSpaceConvert = savedColorSpaceConvert_;
        g_stub = FastEntryStub();
    }

protected:
    static FASTManager &Manager()
    {
        return FASTManager::GetInstance();
    }

    // Clears every entry point so a test only sees what it installs itself.
    static void ResetFastManager()
    {
        FASTManager &manager = Manager();
        manager.isInitialized_ = false;
        manager.DecodeImage = nullptr;
        manager.DecodeImageYUV = nullptr;
        // The legacy FastErrCode exports are being retired; clearing them keeps every test
        // on one deterministic dispatch path instead of whatever the device library exports.
        manager.DecodeImageLegacy = nullptr;
        manager.DecodeImageYUVLegacy = nullptr;
        manager.DecodeImageRegion = nullptr;
        manager.ColorSpaceConvert = nullptr;
        g_stub = FastEntryStub();
    }

    // Mimics an initialized manager: entry points resolved and ready to call.
    static void EnableFastManager()
    {
        Manager().isInitialized_ = true;
    }

    static void InstallFastEntries()
    {
        Manager().DecodeImage = StubDecodeImage;
        Manager().DecodeImageYUV = StubDecodeImageYuv;
    }

private:
    bool savedIsInitialized_ = false;
    fast::image::IMAGE_ErrorCode (*savedDecodeImage_)(const uint8_t *, size_t, uint8_t *, uint32_t, uint32_t, size_t,
        fast::image::RGBFormat) = nullptr;
    fast::image::IMAGE_ErrorCode (*savedDecodeImageYuv_)(const uint8_t *, size_t, uint8_t *, uint8_t *, uint32_t,
        uint32_t, size_t, size_t, fast::image::YUVFormat) = nullptr;
    fast::image::FastErrCode (*savedDecodeImageLegacy_)(const uint8_t *, size_t, uint8_t *, uint32_t, uint32_t,
        size_t, fast::image::RGBFormat) = nullptr;
    fast::image::FastErrCode (*savedDecodeImageYuvLegacy_)(const uint8_t *, size_t, uint8_t *, uint8_t *, uint32_t,
        uint32_t, size_t, size_t, fast::image::YUVFormat) = nullptr;
    fast::image::IMAGE_ErrorCode (*savedDecodeImageRegion_)(
        const fast::image::bandjpeg::RegionDecodeParams &) = nullptr;
    fast::image::IMAGE_ErrorCode (*savedColorSpaceConvert_)(uint8_t *, uint32_t, fast::image::ColorInfo, uint8_t *,
        uint32_t, fast::image::ColorInfo, uint32_t, uint32_t) = nullptr;
};
} // namespace

/**
 * @tc.name: DecodeRgbEntryTest
 * @tc.desc: Test DecodeRgb calls the resolved bandjpeg RGB entry point and reports success.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeRgbEntryTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbEntryTest start";
    EnableFastManager();
    InstallFastEntries();

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, 0);
    std::vector<uint8_t> pixels(SMALL_IMAGE_BYTES, 0);
    const auto plan = MakeRgbPlan(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));

    EXPECT_EQ(ProgressiveJpegDecoder::DecodeRgb(jpegData, plan, pixels.data(), SMALL_IMAGE_STRIDE), SUCCESS);
    EXPECT_EQ(g_stub.rgbCalls, 1u);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbEntryTest end";
}

/**
 * @tc.name: DecodeRgbNoEntryTest
 * @tc.desc: Test DecodeRgb keeps the software decode fallback when the RGB entry is not resolved.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeRgbNoEntryTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbNoEntryTest start";
    EnableFastManager();

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, 0);
    std::vector<uint8_t> pixels(SMALL_IMAGE_BYTES, 0);
    const auto plan = MakeRgbPlan(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));

    EXPECT_EQ(ProgressiveJpegDecoder::DecodeRgb(jpegData, plan, pixels.data(), SMALL_IMAGE_STRIDE),
        ERR_IMAGE_DATA_UNSUPPORT);
    EXPECT_EQ(g_stub.rgbCalls, 0u);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbNoEntryTest end";
}

/**
 * @tc.name: DecodeRgbManagerNotInitializedTest
 * @tc.desc: Test DecodeRgb returns unsupported without calling the entry when FASTManager is not initialized.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeRgbManagerNotInitializedTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbManagerNotInitializedTest start";
    InstallFastEntries();

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, 0);
    std::vector<uint8_t> pixels(SMALL_IMAGE_BYTES, 0);
    const auto plan = MakeRgbPlan(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));

    EXPECT_EQ(ProgressiveJpegDecoder::DecodeRgb(jpegData, plan, pixels.data(), SMALL_IMAGE_STRIDE),
        ERR_IMAGE_DATA_UNSUPPORT);
    EXPECT_EQ(g_stub.rgbCalls, 0u);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbManagerNotInitializedTest end";
}

/**
 * @tc.name: DecodeRgbSuccessPartialTest
 * @tc.desc: Test DecodeRgb treats IMAGE_ErrorCode::SUCCESS_PARTIAL as a usable RGB result.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeRgbSuccessPartialTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbSuccessPartialTest start";
    EnableFastManager();
    InstallFastEntries();
    g_stub.rgbResult = fast::image::IMAGE_ErrorCode::SUCCESS_PARTIAL;

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, 0);
    std::vector<uint8_t> pixels(SMALL_IMAGE_BYTES, 0);
    const auto plan = MakeRgbPlan(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));

    EXPECT_EQ(ProgressiveJpegDecoder::DecodeRgb(jpegData, plan, pixels.data(), SMALL_IMAGE_STRIDE), SUCCESS);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbSuccessPartialTest end";
}

/**
 * @tc.name: DecodeRgbErrorMappingTest
 * @tc.desc: Test DecodeRgb maps every non-successful IMAGE_ErrorCode to the software decode fallback.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeRgbErrorMappingTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbErrorMappingTest start";
    EnableFastManager();
    InstallFastEntries();

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, 0);
    std::vector<uint8_t> pixels(SMALL_IMAGE_BYTES, 0);
    const auto plan = MakeRgbPlan(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));
    const std::vector<fast::image::IMAGE_ErrorCode> errorCodes = {
        fast::image::IMAGE_ErrorCode::ILLEGAL_INPUT,
        fast::image::IMAGE_ErrorCode::INVALID_PTR,
        fast::image::IMAGE_ErrorCode::UNSUPPORTED,
        fast::image::IMAGE_ErrorCode::DECODE_ERROR,
        fast::image::IMAGE_ErrorCode::OOM,
    };
    for (const auto &errorCode : errorCodes) {
        g_stub.rgbResult = errorCode;
        EXPECT_EQ(ProgressiveJpegDecoder::DecodeRgb(jpegData, plan, pixels.data(), SMALL_IMAGE_STRIDE),
            ERR_IMAGE_DATA_UNSUPPORT);
    }
    EXPECT_EQ(g_stub.rgbCalls, static_cast<uint32_t>(errorCodes.size()));
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbErrorMappingTest end";
}

/**
 * @tc.name: DecodeRgbInvalidInputTest
 * @tc.desc: Test DecodeRgb rejects an empty input buffer, an empty buffer size and a null destination.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeRgbInvalidInputTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbInvalidInputTest start";
    EnableFastManager();
    InstallFastEntries();

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, 0);
    std::vector<uint8_t> pixels(SMALL_IMAGE_BYTES, 0);
    const auto plan = MakeRgbPlan(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);

    const auto nullBuffer = MakeJpegInputData(nullptr, static_cast<uint32_t>(jpegBytes.size()));
    EXPECT_EQ(ProgressiveJpegDecoder::DecodeRgb(nullBuffer, plan, pixels.data(), SMALL_IMAGE_STRIDE),
        ERR_IMAGE_DATA_UNSUPPORT);

    const auto emptyBuffer = MakeJpegInputData(jpegBytes.data(), 0);
    EXPECT_EQ(ProgressiveJpegDecoder::DecodeRgb(emptyBuffer, plan, pixels.data(), SMALL_IMAGE_STRIDE),
        ERR_IMAGE_DATA_UNSUPPORT);

    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));
    EXPECT_EQ(ProgressiveJpegDecoder::DecodeRgb(jpegData, plan, nullptr, SMALL_IMAGE_STRIDE),
        ERR_IMAGE_DATA_UNSUPPORT);
    EXPECT_EQ(g_stub.rgbCalls, 0u);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbInvalidInputTest end";
}

/**
 * @tc.name: DecodeRgbArgumentForwardingTest
 * @tc.desc: Test DecodeRgb forwards the buffer, size, output buffer, dimensions and stride unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeRgbArgumentForwardingTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbArgumentForwardingTest start";
    EnableFastManager();
    InstallFastEntries();

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, ARG_FILL_BYTE);
    std::vector<uint8_t> pixels(ARG_IMAGE_BYTES, 0);
    const auto plan = MakeRgbPlan(ARG_IMAGE_WIDTH, ARG_IMAGE_HEIGHT);
    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));

    EXPECT_EQ(ProgressiveJpegDecoder::DecodeRgb(jpegData, plan, pixels.data(), ARG_IMAGE_STRIDE), SUCCESS);
    EXPECT_EQ(g_stub.rgb.buffer, jpegBytes.data());
    EXPECT_EQ(g_stub.rgb.size, jpegBytes.size());
    EXPECT_EQ(g_stub.rgb.dst, pixels.data());
    EXPECT_EQ(g_stub.rgb.width, ARG_IMAGE_WIDTH);
    EXPECT_EQ(g_stub.rgb.height, ARG_IMAGE_HEIGHT);
    EXPECT_EQ(g_stub.rgb.stride, ARG_IMAGE_STRIDE);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbArgumentForwardingTest end";
}

/**
 * @tc.name: DecodeRgbFormatMappingTest
 * @tc.desc: Test DecodeRgb maps every supported PixelFormat to the native RGBFormat, defaulting to RGBA8888.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeRgbFormatMappingTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbFormatMappingTest start";
    EnableFastManager();
    InstallFastEntries();

    struct FormatCase {
        PixelFormat pixelFormat;
        fast::image::RGBFormat rgbFormat;
    };
    const std::vector<FormatCase> cases = {
        { PixelFormat::RGB_888, fast::image::RGBFormat::RGB888 },
        { PixelFormat::RGBA_8888, fast::image::RGBFormat::RGBA8888 },
        { PixelFormat::BGRA_8888, fast::image::RGBFormat::BGRA8888 },
        { PixelFormat::RGB_565, fast::image::RGBFormat::RGB565 },
        { PixelFormat::UNKNOWN, fast::image::RGBFormat::RGBA8888 },
    };

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, 0);
    std::vector<uint8_t> pixels(SMALL_IMAGE_BYTES, 0);
    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));
    for (const auto &testCase : cases) {
        const auto plan = MakeRgbPlan(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT, testCase.pixelFormat);
        EXPECT_EQ(ProgressiveJpegDecoder::DecodeRgb(jpegData, plan, pixels.data(), SMALL_IMAGE_STRIDE), SUCCESS);
        EXPECT_EQ(static_cast<int32_t>(g_stub.rgb.format), static_cast<int32_t>(testCase.rgbFormat));
    }
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRgbFormatMappingTest end";
}

/**
 * @tc.name: DecodeYuvEntryTest
 * @tc.desc: Test DecodeYuv calls the resolved bandjpeg YUV entry and fills the NV12 destination geometry.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeYuvEntryTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeYuvEntryTest start";
    EnableFastManager();
    InstallFastEntries();

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, 0);
    std::vector<uint8_t> pixels = MakeYuvBuffer(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    DecodeContext context;
    context.info.pixelFormat = PixelFormat::NV12;
    context.pixelsBuffer.buffer = pixels.data();
    context.pixelsBuffer.bufferSize = static_cast<uint32_t>(pixels.size());
    ProgressiveJpegDecoder::YuvDecodePlan plan;
    plan.size = MakeSize(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));

    EXPECT_EQ(ProgressiveJpegDecoder::DecodeYuv(jpegData, plan, context), SUCCESS);
    EXPECT_EQ(g_stub.yuvCalls, 1u);
    EXPECT_EQ(g_stub.yuv.dstY, pixels.data());
    EXPECT_EQ(g_stub.yuv.dstUV, pixels.data() + SMALL_IMAGE_UV_OFFSET);
    EXPECT_EQ(g_stub.yuv.width, SMALL_IMAGE_WIDTH);
    EXPECT_EQ(g_stub.yuv.height, SMALL_IMAGE_HEIGHT);
    EXPECT_EQ(g_stub.yuv.yStride, SMALL_IMAGE_WIDTH);
    EXPECT_EQ(g_stub.yuv.uvStride, SMALL_IMAGE_UV_STRIDE);
    EXPECT_EQ(static_cast<int32_t>(g_stub.yuv.format), static_cast<int32_t>(fast::image::YUVFormat::NV12));
    EXPECT_EQ(context.outInfo.size.width, plan.size.width);
    EXPECT_EQ(context.outInfo.size.height, plan.size.height);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeYuvEntryTest end";
}

/**
 * @tc.name: DecodeYuvNoEntryTest
 * @tc.desc: Test DecodeYuv keeps the software decode fallback when no YUV entry is resolved.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeYuvNoEntryTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeYuvNoEntryTest start";
    EnableFastManager();

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, 0);
    std::vector<uint8_t> pixels = MakeYuvBuffer(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    DecodeContext context;
    context.info.pixelFormat = PixelFormat::NV12;
    context.pixelsBuffer.buffer = pixels.data();
    ProgressiveJpegDecoder::YuvDecodePlan plan;
    plan.size = MakeSize(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));

    EXPECT_EQ(ProgressiveJpegDecoder::DecodeYuv(jpegData, plan, context), ERR_IMAGE_DATA_UNSUPPORT);
    EXPECT_EQ(g_stub.yuvCalls, 0u);
    EXPECT_EQ(context.outInfo.size.width, 0);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeYuvNoEntryTest end";
}

/**
 * @tc.name: DecodeYuvSuccessPartialTest
 * @tc.desc: Test DecodeYuv treats IMAGE_ErrorCode::SUCCESS_PARTIAL as a usable YUV result.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeYuvSuccessPartialTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeYuvSuccessPartialTest start";
    EnableFastManager();
    InstallFastEntries();
    g_stub.yuvResult = fast::image::IMAGE_ErrorCode::SUCCESS_PARTIAL;

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, 0);
    std::vector<uint8_t> pixels = MakeYuvBuffer(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    DecodeContext context;
    context.info.pixelFormat = PixelFormat::NV12;
    context.pixelsBuffer.buffer = pixels.data();
    ProgressiveJpegDecoder::YuvDecodePlan plan;
    plan.size = MakeSize(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));

    EXPECT_EQ(ProgressiveJpegDecoder::DecodeYuv(jpegData, plan, context), SUCCESS);
    EXPECT_EQ(context.outInfo.size.width, plan.size.width);
    EXPECT_EQ(context.outInfo.size.height, plan.size.height);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeYuvSuccessPartialTest end";
}

/**
 * @tc.name: DecodeYuvErrorMappingTest
 * @tc.desc: Test DecodeYuv maps every non-successful IMAGE_ErrorCode to the fallback and keeps outInfo empty.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeYuvErrorMappingTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeYuvErrorMappingTest start";
    EnableFastManager();
    InstallFastEntries();

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, 0);
    std::vector<uint8_t> pixels = MakeYuvBuffer(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    DecodeContext context;
    context.info.pixelFormat = PixelFormat::NV12;
    context.pixelsBuffer.buffer = pixels.data();
    ProgressiveJpegDecoder::YuvDecodePlan plan;
    plan.size = MakeSize(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));
    const std::vector<fast::image::IMAGE_ErrorCode> errorCodes = {
        fast::image::IMAGE_ErrorCode::ILLEGAL_INPUT,
        fast::image::IMAGE_ErrorCode::INVALID_PTR,
        fast::image::IMAGE_ErrorCode::UNSUPPORTED,
        fast::image::IMAGE_ErrorCode::DECODE_ERROR,
        fast::image::IMAGE_ErrorCode::OOM,
    };
    for (const auto &errorCode : errorCodes) {
        g_stub.yuvResult = errorCode;
        EXPECT_EQ(ProgressiveJpegDecoder::DecodeYuv(jpegData, plan, context), ERR_IMAGE_DATA_UNSUPPORT);
        EXPECT_EQ(context.outInfo.size.width, 0);
        EXPECT_EQ(context.outInfo.size.height, 0);
    }
    EXPECT_EQ(g_stub.yuvCalls, static_cast<uint32_t>(errorCodes.size()));
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeYuvErrorMappingTest end";
}

/**
 * @tc.name: DecodeYuvNv21OddSizeTest
 * @tc.desc: Test DecodeYuv rounds an odd NV21 destination up to whole chroma samples.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeYuvNv21OddSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeYuvNv21OddSizeTest start";
    EnableFastManager();
    InstallFastEntries();

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, 0);
    std::vector<uint8_t> pixels = MakeYuvBuffer(ODD_YUV_WIDTH, ODD_YUV_HEIGHT);
    DecodeContext context;
    context.info.pixelFormat = PixelFormat::NV21;
    context.pixelsBuffer.buffer = pixels.data();
    ProgressiveJpegDecoder::YuvDecodePlan plan;
    plan.size = MakeSize(ODD_YUV_WIDTH, ODD_YUV_HEIGHT);
    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));

    EXPECT_EQ(ProgressiveJpegDecoder::DecodeYuv(jpegData, plan, context), SUCCESS);
    EXPECT_EQ(g_stub.yuv.dstY, pixels.data());
    EXPECT_EQ(g_stub.yuv.dstUV, pixels.data() + ODD_YUV_UV_OFFSET);
    EXPECT_EQ(g_stub.yuv.width, ODD_YUV_WIDTH);
    EXPECT_EQ(g_stub.yuv.height, ODD_YUV_HEIGHT);
    EXPECT_EQ(g_stub.yuv.yStride, ODD_YUV_WIDTH);
    EXPECT_EQ(g_stub.yuv.uvStride, ODD_YUV_UV_STRIDE);
    EXPECT_EQ(static_cast<int32_t>(g_stub.yuv.format), static_cast<int32_t>(fast::image::YUVFormat::NV21));
    EXPECT_EQ(context.yuvInfo.uvWidth, ODD_YUV_CHROMA_WIDTH);
    EXPECT_EQ(context.yuvInfo.uvHeight, ODD_YUV_CHROMA_HEIGHT);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeYuvNv21OddSizeTest end";
}

/**
 * @tc.name: DecodeYuvInvalidInputTest
 * @tc.desc: Test DecodeYuv rejects empty input, a missing destination buffer, an unsupported format and an
 *           uninitialized manager before reaching the native entry.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeYuvInvalidInputTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeYuvInvalidInputTest start";
    EnableFastManager();
    InstallFastEntries();

    std::vector<uint8_t> jpegBytes(JPEG_INPUT_BUFFER_SIZE, 0);
    std::vector<uint8_t> pixels = MakeYuvBuffer(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);
    ProgressiveJpegDecoder::YuvDecodePlan plan;
    plan.size = MakeSize(SMALL_IMAGE_WIDTH, SMALL_IMAGE_HEIGHT);

    DecodeContext validContext;
    validContext.info.pixelFormat = PixelFormat::NV12;
    validContext.pixelsBuffer.buffer = pixels.data();
    EXPECT_EQ(ProgressiveJpegDecoder::DecodeYuv(MakeJpegInputData(jpegBytes.data(), 0), plan, validContext),
        ERR_IMAGE_DATA_UNSUPPORT);

    const auto jpegData = MakeJpegInputData(jpegBytes.data(), static_cast<uint32_t>(jpegBytes.size()));
    EXPECT_EQ(ProgressiveJpegDecoder::DecodeYuv(MakeJpegInputData(nullptr,
        static_cast<uint32_t>(jpegBytes.size())), plan, validContext), ERR_IMAGE_DATA_UNSUPPORT);

    DecodeContext emptyDestination;
    emptyDestination.info.pixelFormat = PixelFormat::NV12;
    EXPECT_EQ(ProgressiveJpegDecoder::DecodeYuv(jpegData, plan, emptyDestination), ERR_IMAGE_DATA_UNSUPPORT);

    DecodeContext rgbDestination;
    rgbDestination.info.pixelFormat = PixelFormat::RGBA_8888;
    rgbDestination.pixelsBuffer.buffer = pixels.data();
    EXPECT_EQ(ProgressiveJpegDecoder::DecodeYuv(jpegData, plan, rgbDestination), ERR_IMAGE_DATA_UNSUPPORT);

    Manager().isInitialized_ = false;
    EXPECT_EQ(ProgressiveJpegDecoder::DecodeYuv(jpegData, plan, validContext), ERR_IMAGE_DATA_UNSUPPORT);
    EXPECT_EQ(g_stub.yuvCalls, 0u);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeYuvInvalidInputTest end";
}

/**
 * @tc.name: DecodeRegionSuccessTest
 * @tc.desc: Test DecodeRegion forwards the region parameters and maps SUCCESS to SUCCESS.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeRegionSuccessTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRegionSuccessTest start";
    EnableFastManager();
    Manager().DecodeImageRegion = StubDecodeImageRegion;

    fast::image::bandjpeg::RegionDecodeParams params;
    params.regionX = REGION_X;
    params.regionY = REGION_Y;
    params.regionWidth = REGION_WIDTH;
    params.regionHeight = REGION_HEIGHT;
    params.scale = fast::image::bandjpeg::DecodeScale::HALF;
    params.dstWidth = REGION_WIDTH;
    params.dstHeight = REGION_HEIGHT;
    params.stride = REGION_STRIDE;

    EXPECT_EQ(ProgressiveJpegDecoder::DecodeRegion(params), SUCCESS);
    EXPECT_EQ(g_stub.regionCalls, 1u);
    EXPECT_EQ(g_stub.region.regionX, REGION_X);
    EXPECT_EQ(g_stub.region.regionY, REGION_Y);
    EXPECT_EQ(g_stub.region.regionWidth, REGION_WIDTH);
    EXPECT_EQ(g_stub.region.regionHeight, REGION_HEIGHT);
    EXPECT_EQ(static_cast<int32_t>(g_stub.region.scale),
        static_cast<int32_t>(fast::image::bandjpeg::DecodeScale::HALF));
    EXPECT_EQ(g_stub.region.dstWidth, REGION_WIDTH);
    EXPECT_EQ(g_stub.region.dstHeight, REGION_HEIGHT);
    EXPECT_EQ(g_stub.region.stride, REGION_STRIDE);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRegionSuccessTest end";
}

/**
 * @tc.name: DecodeRegionErrorMappingTest
 * @tc.desc: Test DecodeRegion maps every native IMAGE_ErrorCode to the matching framework error code.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeRegionErrorMappingTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRegionErrorMappingTest start";
    EnableFastManager();
    Manager().DecodeImageRegion = StubDecodeImageRegion;

    struct ErrorCase {
        fast::image::IMAGE_ErrorCode nativeCode;
        uint32_t frameworkCode;
    };
    const std::vector<ErrorCase> cases = {
        { fast::image::IMAGE_ErrorCode::INVALID_PTR, ERR_IMAGE_INVALID_PARAMETER },
        { fast::image::IMAGE_ErrorCode::ILLEGAL_INPUT, ERR_IMAGE_INVALID_PARAMETER },
        { fast::image::IMAGE_ErrorCode::UNSUPPORTED, ERR_IMAGE_DATA_UNSUPPORT },
        { fast::image::IMAGE_ErrorCode::SUCCESS_PARTIAL, ERR_IMAGE_DATA_UNSUPPORT },
        { fast::image::IMAGE_ErrorCode::OOM, ERR_IMAGE_MALLOC_ABNORMAL },
        { fast::image::IMAGE_ErrorCode::DECODE_ERROR, ERR_IMAGE_DECODE_FAILED },
    };

    fast::image::bandjpeg::RegionDecodeParams params;
    params.regionWidth = MAPPING_REGION_SIZE;
    params.regionHeight = MAPPING_REGION_SIZE;
    params.dstWidth = MAPPING_REGION_SIZE;
    params.dstHeight = MAPPING_REGION_SIZE;
    params.stride = MAPPING_REGION_STRIDE;
    for (const auto &testCase : cases) {
        g_stub.regionResult = testCase.nativeCode;
        EXPECT_EQ(ProgressiveJpegDecoder::DecodeRegion(params), testCase.frameworkCode);
    }
    EXPECT_EQ(g_stub.regionCalls, static_cast<uint32_t>(cases.size()));
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRegionErrorMappingTest end";
}

/**
 * @tc.name: DecodeRegionUnavailableTest
 * @tc.desc: Test DecodeRegion returns unsupported when the region symbol is missing or the manager is not ready.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, DecodeRegionUnavailableTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRegionUnavailableTest start";
    fast::image::bandjpeg::RegionDecodeParams params;
    params.regionWidth = UNAVAILABLE_REGION_SIZE;
    params.regionHeight = UNAVAILABLE_REGION_SIZE;
    params.dstWidth = UNAVAILABLE_REGION_SIZE;
    params.dstHeight = UNAVAILABLE_REGION_SIZE;

    // Manager ready but DecodeImageRegion was not exported by the library.
    EnableFastManager();
    EXPECT_EQ(ProgressiveJpegDecoder::DecodeRegion(params), ERR_IMAGE_DATA_UNSUPPORT);

    // Symbol resolved but the manager is not initialized.
    Manager().DecodeImageRegion = StubDecodeImageRegion;
    Manager().isInitialized_ = false;
    EXPECT_EQ(ProgressiveJpegDecoder::DecodeRegion(params), ERR_IMAGE_DATA_UNSUPPORT);
    EXPECT_EQ(g_stub.regionCalls, 0u);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: DecodeRegionUnavailableTest end";
}
/**
 * @tc.name: BuildRgbRegionParamsFullImageTest
 * @tc.desc: Test BuildRgbRegionParams keeps the native FULL scale when no desired size is requested.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbRegionParamsFullImageTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsFullImageTest start";
    const auto options = MakeRegionOptions({ PROGRESSIVE_IMAGE_WIDTH, PROGRESSIVE_IMAGE_HEIGHT, 0, 0,
        PROGRESSIVE_IMAGE_WIDTH, PROGRESSIVE_IMAGE_HEIGHT });
    fast::image::bandjpeg::RegionDecodeParams params;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbRegionParams(options, params));
    EXPECT_EQ(params.regionX, 0u);
    EXPECT_EQ(params.regionY, 0u);
    EXPECT_EQ(params.regionWidth, PROGRESSIVE_IMAGE_WIDTH);
    EXPECT_EQ(params.regionHeight, PROGRESSIVE_IMAGE_HEIGHT);
    EXPECT_EQ(static_cast<int32_t>(params.scale), static_cast<int32_t>(fast::image::bandjpeg::DecodeScale::FULL));
    EXPECT_EQ(params.dstWidth, PROGRESSIVE_IMAGE_WIDTH);
    EXPECT_EQ(params.dstHeight, PROGRESSIVE_IMAGE_HEIGHT);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsFullImageTest end";
}

/**
 * @tc.name: BuildRgbRegionParamsHalfScaleTest
 * @tc.desc: Test BuildRgbRegionParams selects HALF when the desired size is half of the full image.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbRegionParamsHalfScaleTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsHalfScaleTest start";
    const auto options = MakeRegionOptions({ PROGRESSIVE_IMAGE_WIDTH, PROGRESSIVE_IMAGE_HEIGHT, 0, 0,
        PROGRESSIVE_IMAGE_WIDTH, PROGRESSIVE_IMAGE_HEIGHT, PROGRESSIVE_IMAGE_WIDTH / SCALE_HALF,
        PROGRESSIVE_IMAGE_HEIGHT / SCALE_HALF });
    fast::image::bandjpeg::RegionDecodeParams params;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbRegionParams(options, params));
    EXPECT_EQ(static_cast<int32_t>(params.scale), static_cast<int32_t>(fast::image::bandjpeg::DecodeScale::HALF));
    EXPECT_EQ(params.dstWidth, PROGRESSIVE_IMAGE_WIDTH / SCALE_HALF);
    EXPECT_EQ(params.dstHeight, PROGRESSIVE_IMAGE_HEIGHT / SCALE_HALF);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsHalfScaleTest end";
}

/**
 * @tc.name: BuildRgbRegionParamsQuarterScaleTest
 * @tc.desc: Test BuildRgbRegionParams selects QUARTER when the desired size is a quarter of the full image.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbRegionParamsQuarterScaleTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsQuarterScaleTest start";
    const auto options = MakeRegionOptions({ PROGRESSIVE_IMAGE_WIDTH, PROGRESSIVE_IMAGE_HEIGHT, 0, 0,
        PROGRESSIVE_IMAGE_WIDTH, PROGRESSIVE_IMAGE_HEIGHT, PROGRESSIVE_IMAGE_WIDTH / SCALE_QUARTER,
        PROGRESSIVE_IMAGE_HEIGHT / SCALE_QUARTER });
    fast::image::bandjpeg::RegionDecodeParams params;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbRegionParams(options, params));
    EXPECT_EQ(static_cast<int32_t>(params.scale), static_cast<int32_t>(fast::image::bandjpeg::DecodeScale::QUARTER));
    EXPECT_EQ(params.dstWidth, PROGRESSIVE_IMAGE_WIDTH / SCALE_QUARTER);
    EXPECT_EQ(params.dstHeight, PROGRESSIVE_IMAGE_HEIGHT / SCALE_QUARTER);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsQuarterScaleTest end";
}

/**
 * @tc.name: BuildRgbRegionParamsEighthScaleTest
 * @tc.desc: Test BuildRgbRegionParams selects EIGHTH when the desired size is an eighth of the full image.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbRegionParamsEighthScaleTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsEighthScaleTest start";
    const auto options = MakeRegionOptions({ PROGRESSIVE_IMAGE_WIDTH, PROGRESSIVE_IMAGE_HEIGHT, 0, 0,
        PROGRESSIVE_IMAGE_WIDTH, PROGRESSIVE_IMAGE_HEIGHT, PROGRESSIVE_IMAGE_WIDTH / SCALE_EIGHTH,
        PROGRESSIVE_IMAGE_HEIGHT / SCALE_EIGHTH });
    fast::image::bandjpeg::RegionDecodeParams params;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbRegionParams(options, params));
    EXPECT_EQ(static_cast<int32_t>(params.scale), static_cast<int32_t>(fast::image::bandjpeg::DecodeScale::EIGHTH));
    EXPECT_EQ(params.dstWidth, PROGRESSIVE_IMAGE_WIDTH / SCALE_EIGHTH);
    EXPECT_EQ(params.dstHeight, PROGRESSIVE_IMAGE_HEIGHT / SCALE_EIGHTH);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsEighthScaleTest end";
}

/**
 * @tc.name: BuildRgbRegionParamsScaleThresholdTest
 * @tc.desc: Test BuildRgbRegionParams scale thresholds are inclusive: an exact eighth keeps EIGHTH, one pixel
 *           more needs QUARTER.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbRegionParamsScaleThresholdTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsScaleThresholdTest start";
    fast::image::bandjpeg::RegionDecodeParams onThreshold;
    const auto exactEighth = MakeRegionOptions({ PROGRESSIVE_IMAGE_WIDTH, PROGRESSIVE_IMAGE_HEIGHT, 0, 0,
        PROGRESSIVE_IMAGE_WIDTH, PROGRESSIVE_IMAGE_HEIGHT, PROGRESSIVE_IMAGE_WIDTH / SCALE_EIGHTH,
        PROGRESSIVE_IMAGE_HEIGHT / SCALE_EIGHTH });
    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbRegionParams(exactEighth, onThreshold));
    EXPECT_EQ(static_cast<int32_t>(onThreshold.scale),
        static_cast<int32_t>(fast::image::bandjpeg::DecodeScale::EIGHTH));

    fast::image::bandjpeg::RegionDecodeParams aboveThreshold;
    const auto overEighth = MakeRegionOptions({ PROGRESSIVE_IMAGE_WIDTH, PROGRESSIVE_IMAGE_HEIGHT, 0, 0,
        PROGRESSIVE_IMAGE_WIDTH, PROGRESSIVE_IMAGE_HEIGHT, PROGRESSIVE_IMAGE_WIDTH / SCALE_EIGHTH + 1,
        PROGRESSIVE_IMAGE_HEIGHT / SCALE_EIGHTH });
    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbRegionParams(overEighth, aboveThreshold));
    // One pixel above an exact eighth drops to QUARTER, so the output is the native quarter size.
    EXPECT_EQ(static_cast<int32_t>(aboveThreshold.scale),
        static_cast<int32_t>(fast::image::bandjpeg::DecodeScale::QUARTER));
    EXPECT_EQ(aboveThreshold.dstWidth, PROGRESSIVE_IMAGE_WIDTH / SCALE_QUARTER);
    EXPECT_EQ(aboveThreshold.dstHeight, PROGRESSIVE_IMAGE_HEIGHT / SCALE_QUARTER);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsScaleThresholdTest end";
}

/**
 * @tc.name: BuildRgbRegionParamsCeilOutputTest
 * @tc.desc: Test BuildRgbRegionParams rounds a full image output size up instead of truncating.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbRegionParamsCeilOutputTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsCeilOutputTest start";
    const auto options = MakeRegionOptions({ ODD_SOURCE_WIDTH, ODD_SOURCE_HEIGHT, 0, 0, ODD_SOURCE_WIDTH,
        ODD_SOURCE_HEIGHT, ODD_DESIRED_WIDTH, ODD_DESIRED_HEIGHT });
    fast::image::bandjpeg::RegionDecodeParams params;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbRegionParams(options, params));
    EXPECT_EQ(static_cast<int32_t>(params.scale), static_cast<int32_t>(fast::image::bandjpeg::DecodeScale::EIGHTH));
    EXPECT_EQ(params.dstWidth, ODD_OUTPUT_WIDTH);
    EXPECT_EQ(params.dstHeight, ODD_OUTPUT_HEIGHT);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsCeilOutputTest end";
}

/**
 * @tc.name: BuildRgbRegionParamsSubRegionTest
 * @tc.desc: Test BuildRgbRegionParams keeps an unclipped sub-region and its FULL geometry keyed by region size.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbRegionParamsSubRegionTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsSubRegionTest start";
    const auto options = MakeRegionOptions({ SUBREGION_SOURCE_WIDTH, SUBREGION_SOURCE_HEIGHT, SUBREGION_X,
        SUBREGION_Y, SUBREGION_WIDTH, SUBREGION_HEIGHT });
    fast::image::bandjpeg::RegionDecodeParams params;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbRegionParams(options, params));
    EXPECT_EQ(params.regionX, SUBREGION_X);
    EXPECT_EQ(params.regionY, SUBREGION_Y);
    EXPECT_EQ(params.regionWidth, SUBREGION_WIDTH);
    EXPECT_EQ(params.regionHeight, SUBREGION_HEIGHT);
    EXPECT_EQ(static_cast<int32_t>(params.scale), static_cast<int32_t>(fast::image::bandjpeg::DecodeScale::FULL));
    EXPECT_EQ(params.dstWidth, SUBREGION_WIDTH);
    EXPECT_EQ(params.dstHeight, SUBREGION_HEIGHT);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsSubRegionTest end";
}

/**
 * @tc.name: BuildRgbRegionParamsSubRegionFloorTest
 * @tc.desc: Test BuildRgbRegionParams truncates a scaled sub-region and keeps at least one pixel per axis.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbRegionParamsSubRegionFloorTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsSubRegionFloorTest start";
    const auto options = MakeRegionOptions({ FLOOR_SOURCE_SIZE, FLOOR_SOURCE_SIZE, 0, 0, FLOOR_REGION_WIDTH,
        FLOOR_REGION_HEIGHT, 1, 1 });
    fast::image::bandjpeg::RegionDecodeParams params;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbRegionParams(options, params));
    EXPECT_EQ(static_cast<int32_t>(params.scale), static_cast<int32_t>(fast::image::bandjpeg::DecodeScale::QUARTER));
    // 7 / 4 = 1 and 5 / 4 = 1; a scaled crop never collapses to zero.
    EXPECT_EQ(params.dstWidth, 1u);
    EXPECT_EQ(params.dstHeight, 1u);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsSubRegionFloorTest end";
}

/**
 * @tc.name: BuildRgbRegionParamsInvalidSourceTest
 * @tc.desc: Test BuildRgbRegionParams rejects a zero source size and negative region offsets.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbRegionParamsInvalidSourceTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsInvalidSourceTest start";
    const auto valid = MakeRegionOptions({ GEOMETRY_SOURCE_WIDTH, GEOMETRY_SOURCE_HEIGHT, 0, 0, GEOMETRY_SOURCE_WIDTH,
        GEOMETRY_SOURCE_HEIGHT, GEOMETRY_DESIRED_WIDTH, GEOMETRY_DESIRED_HEIGHT });

    auto zeroSourceWidth = valid;
    zeroSourceWidth.sourceWidth = 0;
    ExpectInvalidRegionOptions(zeroSourceWidth);

    auto negativeSourceHeight = valid;
    negativeSourceHeight.sourceHeight = -1;
    ExpectInvalidRegionOptions(negativeSourceHeight);

    auto negativeRegionX = valid;
    negativeRegionX.regionX = -1;
    ExpectInvalidRegionOptions(negativeRegionX);

    auto negativeRegionY = valid;
    negativeRegionY.regionY = -1;
    ExpectInvalidRegionOptions(negativeRegionY);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsInvalidSourceTest end";
}

/**
 * @tc.name: BuildRgbRegionParamsInvalidRegionTest
 * @tc.desc: Test BuildRgbRegionParams rejects empty and out of bounds rectangles but accepts an edge touching one.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbRegionParamsInvalidRegionTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsInvalidRegionTest start";
    const auto valid = MakeRegionOptions({ GEOMETRY_SOURCE_WIDTH, GEOMETRY_SOURCE_HEIGHT, 0, 0, GEOMETRY_SOURCE_WIDTH,
        GEOMETRY_SOURCE_HEIGHT, GEOMETRY_DESIRED_WIDTH, GEOMETRY_DESIRED_HEIGHT });

    auto zeroRegionWidth = valid;
    zeroRegionWidth.regionWidth = 0;
    ExpectInvalidRegionOptions(zeroRegionWidth);

    auto zeroRegionHeight = valid;
    zeroRegionHeight.regionHeight = 0;
    ExpectInvalidRegionOptions(zeroRegionHeight);

    auto rightOverflow = valid;
    rightOverflow.regionWidth = GEOMETRY_SOURCE_WIDTH + 1;
    ExpectInvalidRegionOptions(rightOverflow);

    auto bottomOverflow = valid;
    bottomOverflow.regionHeight = GEOMETRY_SOURCE_HEIGHT + 1;
    ExpectInvalidRegionOptions(bottomOverflow);

    // A rectangle may touch the source edge exactly.
    const auto onEdge = MakeRegionOptions({ GEOMETRY_SOURCE_WIDTH, GEOMETRY_SOURCE_HEIGHT,
        GEOMETRY_SOURCE_WIDTH / SCALE_HALF, GEOMETRY_SOURCE_HEIGHT / SCALE_HALF, GEOMETRY_SOURCE_WIDTH / SCALE_HALF,
        GEOMETRY_SOURCE_HEIGHT / SCALE_HALF, GEOMETRY_DESIRED_WIDTH, GEOMETRY_DESIRED_HEIGHT });
    fast::image::bandjpeg::RegionDecodeParams params;
    EXPECT_TRUE(ProgressiveJpegDecoder::BuildRgbRegionParams(onEdge, params));
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsInvalidRegionTest end";
}

/**
 * @tc.name: BuildRgbRegionParamsInvalidDesiredTest
 * @tc.desc: Test BuildRgbRegionParams rejects a desired size with only one positive side.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbRegionParamsInvalidDesiredTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsInvalidDesiredTest start";
    const auto valid = MakeRegionOptions({ GEOMETRY_SOURCE_WIDTH, GEOMETRY_SOURCE_HEIGHT, 0, 0, GEOMETRY_SOURCE_WIDTH,
        GEOMETRY_SOURCE_HEIGHT, GEOMETRY_DESIRED_WIDTH, GEOMETRY_DESIRED_HEIGHT });

    auto desiredWidthOnly = valid;
    desiredWidthOnly.desiredHeight = 0;
    ExpectInvalidRegionOptions(desiredWidthOnly);

    auto desiredHeightOnly = valid;
    desiredHeightOnly.desiredWidth = 0;
    ExpectInvalidRegionOptions(desiredHeightOnly);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsInvalidDesiredTest end";
}

/**
 * @tc.name: BuildRgbRegionParamsOverflowTest
 * @tc.desc: Test BuildRgbRegionParams widens the edge check so INT32_MAX inputs cannot wrap.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbRegionParamsOverflowTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsOverflowTest start";
    const int32_t maxValue = std::numeric_limits<int32_t>::max();
    ProgressiveJpegDecoder::RgbRegionOptions options;
    options.sourceWidth = maxValue;
    options.sourceHeight = maxValue;
    options.regionX = maxValue;
    options.regionWidth = maxValue;
    options.regionHeight = 1;
    fast::image::bandjpeg::RegionDecodeParams params;

    EXPECT_FALSE(ProgressiveJpegDecoder::BuildRgbRegionParams(options, params));
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsOverflowTest end";
}

/**
 * @tc.name: BuildRgbRegionParamsKeepParamsTest
 * @tc.desc: Test BuildRgbRegionParams leaves the caller storage fields untouched when the geometry is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbRegionParamsKeepParamsTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsKeepParamsTest start";
    std::vector<uint8_t> storage(STORAGE_BYTES, 0);
    fast::image::bandjpeg::RegionDecodeParams params;
    params.regionX = SENTINEL_REGION_X;
    params.regionY = SENTINEL_REGION_Y;
    params.dstWidth = SENTINEL_DST_WIDTH;
    params.dstHeight = SENTINEL_DST_HEIGHT;
    params.dst = storage.data();
    params.stride = SENTINEL_STRIDE;
    params.capacityBytes = storage.size();
    params.scale = fast::image::bandjpeg::DecodeScale::HALF;

    auto invalid = MakeRegionOptions({ GEOMETRY_SOURCE_WIDTH, GEOMETRY_SOURCE_HEIGHT, 0, 0, GEOMETRY_SOURCE_WIDTH,
        GEOMETRY_SOURCE_HEIGHT, GEOMETRY_DESIRED_WIDTH, GEOMETRY_DESIRED_HEIGHT });
    invalid.regionWidth = GEOMETRY_SOURCE_WIDTH + 1;
    EXPECT_FALSE(ProgressiveJpegDecoder::BuildRgbRegionParams(invalid, params));
    EXPECT_EQ(params.regionX, SENTINEL_REGION_X);
    EXPECT_EQ(params.regionY, SENTINEL_REGION_Y);
    EXPECT_EQ(params.dstWidth, SENTINEL_DST_WIDTH);
    EXPECT_EQ(params.dstHeight, SENTINEL_DST_HEIGHT);
    EXPECT_EQ(static_cast<void *>(params.dst), static_cast<void *>(storage.data()));
    EXPECT_EQ(params.stride, SENTINEL_STRIDE);
    EXPECT_EQ(params.capacityBytes, storage.size());
    EXPECT_EQ(static_cast<int32_t>(params.scale),
        static_cast<int32_t>(fast::image::bandjpeg::DecodeScale::HALF));
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbRegionParamsKeepParamsTest end";
}

/**
 * @tc.name: BuildRgbDecodePlanNoCodecTest
 * @tc.desc: Test BuildRgbDecodePlan refuses to plan without a codec.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbDecodePlanNoCodecTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanNoCodecTest start";
    ProgressiveJpegDecoder::RgbDecodeOptions options;
    options.srcInfo = MakeRgbaImageInfo(PROGRESSIVE_IMAGE_WIDTH, PROGRESSIVE_IMAGE_HEIGHT);
    options.dstInfo = options.srcInfo;
    options.pixelFormat = PixelFormat::RGBA_8888;
    options.ifSourceCompleted = true;
    ProgressiveJpegDecoder::RgbDecodePlan plan;

    EXPECT_FALSE(ProgressiveJpegDecoder::BuildRgbDecodePlan(options, plan));
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanNoCodecTest end";
}

/**
 * @tc.name: BuildRgbDecodePlanRejectedOptionsTest
 * @tc.desc: Test BuildRgbDecodePlan rejects region decode, incomplete sources, explicit subsets and DMA RGB888.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbDecodePlanRejectedOptionsTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanRejectedOptionsTest start";
    auto codec = MakeCodec(PROGRESSIVE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "progressive jpeg resource unavailable: " << PROGRESSIVE_JPEG_FILE;
    }
    const SkImageInfo imageInfo = codec->getInfo();
    std::vector<ProgressiveJpegDecoder::RgbDecodeOptions> rejected;

    auto regionOptions = MakeRgbDecodeOptions(codec.get(), imageInfo);
    regionOptions.supportRegion = true;
    rejected.push_back(regionOptions);

    auto incompleteOptions = MakeRgbDecodeOptions(codec.get(), imageInfo);
    incompleteOptions.ifSourceCompleted = false;
    rejected.push_back(incompleteOptions);

    auto subsetOptions = MakeRgbDecodeOptions(codec.get(), imageInfo);
    subsetOptions.hasSubset = true;
    rejected.push_back(subsetOptions);

    auto reuseOptions = MakeRgbDecodeOptions(codec.get(), imageInfo);
    reuseOptions.hasReusePixelmap = true;
    rejected.push_back(reuseOptions);

    auto unknownFormatOptions = MakeRgbDecodeOptions(codec.get(), imageInfo);
    unknownFormatOptions.pixelFormat = PixelFormat::UNKNOWN;
    rejected.push_back(unknownFormatOptions);

    auto argbOptions = MakeRgbDecodeOptions(codec.get(), imageInfo);
    argbOptions.pixelFormat = PixelFormat::ARGB_8888;
    rejected.push_back(argbOptions);

    // Packed RGB888 straight into a DMA buffer is handled by the hardware path, not here.
    auto dmaRgb888Options = MakeRgbDecodeOptions(codec.get(), imageInfo);
    dmaRgb888Options.pixelFormat = PixelFormat::RGB_888;
    dmaRgb888Options.allocatorType = AllocatorType::DMA_ALLOC;
    rejected.push_back(dmaRgb888Options);

    for (const auto &options : rejected) {
        ProgressiveJpegDecoder::RgbDecodePlan plan;
        EXPECT_FALSE(ProgressiveJpegDecoder::BuildRgbDecodePlan(options, plan));
    }
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanRejectedOptionsTest end";
}

/**
 * @tc.name: BuildRgbDecodePlanEmptyInfoTest
 * @tc.desc: Test BuildRgbDecodePlan refuses an empty source or destination image info.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbDecodePlanEmptyInfoTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanEmptyInfoTest start";
    auto codec = MakeCodec(PROGRESSIVE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "progressive jpeg resource unavailable: " << PROGRESSIVE_JPEG_FILE;
    }
    const SkImageInfo imageInfo = codec->getInfo();

    auto emptyDstOptions = MakeRgbDecodeOptions(codec.get(), SkImageInfo());
    ProgressiveJpegDecoder::RgbDecodePlan emptyDstPlan;
    EXPECT_FALSE(ProgressiveJpegDecoder::BuildRgbDecodePlan(emptyDstOptions, emptyDstPlan));

    auto emptySrcOptions = MakeRgbDecodeOptions(codec.get(), imageInfo);
    emptySrcOptions.srcInfo = SkImageInfo();
    ProgressiveJpegDecoder::RgbDecodePlan emptySrcPlan;
    EXPECT_FALSE(ProgressiveJpegDecoder::BuildRgbDecodePlan(emptySrcOptions, emptySrcPlan));
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanEmptyInfoTest end";
}

/**
 * @tc.name: BuildRgbDecodePlanFullSizeTest
 * @tc.desc: Test BuildRgbDecodePlan keeps the destination size and byte count for a full-size decode.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbDecodePlanFullSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanFullSizeTest start";
    auto codec = MakeCodec(PROGRESSIVE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "progressive jpeg resource unavailable: " << PROGRESSIVE_JPEG_FILE;
    }
    const SkImageInfo imageInfo = codec->getInfo();
    const auto options = MakeRgbDecodeOptions(codec.get(), imageInfo);
    ProgressiveJpegDecoder::RgbDecodePlan plan;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbDecodePlan(options, plan));
    EXPECT_FALSE(plan.useDesiredSize);
    EXPECT_EQ(plan.dstInfo.width(), imageInfo.width());
    EXPECT_EQ(plan.dstInfo.height(), imageInfo.height());
    EXPECT_EQ(static_cast<int32_t>(plan.pixelFormat), static_cast<int32_t>(PixelFormat::RGBA_8888));
    EXPECT_FALSE(plan.isRgb888Output);
    EXPECT_EQ(plan.byteCount, imageInfo.computeMinByteSize());
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanFullSizeTest end";
}

/**
 * @tc.name: BuildRgbDecodePlanDesiredSizeTest
 * @tc.desc: Test BuildRgbDecodePlan adopts a smaller desired size and recomputes the byte count.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbDecodePlanDesiredSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanDesiredSizeTest start";
    auto codec = MakeCodec(PROGRESSIVE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "progressive jpeg resource unavailable: " << PROGRESSIVE_JPEG_FILE;
    }
    const SkImageInfo imageInfo = codec->getInfo();
    const SkImageInfo dstInfo = imageInfo.makeWH(imageInfo.width() / SCALE_HALF, imageInfo.height() / SCALE_HALF);
    auto options = MakeRgbDecodeOptions(codec.get(), dstInfo);
    options.desiredSize = { imageInfo.width() / SCALE_QUARTER, imageInfo.height() / SCALE_QUARTER };
    ProgressiveJpegDecoder::RgbDecodePlan plan;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbDecodePlan(options, plan));
    EXPECT_TRUE(plan.useDesiredSize);
    EXPECT_EQ(plan.dstInfo.width(), imageInfo.width() / SCALE_QUARTER);
    EXPECT_EQ(plan.dstInfo.height(), imageInfo.height() / SCALE_QUARTER);
    EXPECT_EQ(plan.byteCount, plan.dstInfo.computeMinByteSize());
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanDesiredSizeTest end";
}

/**
 * @tc.name: BuildRgbDecodePlanDesiredClampTest
 * @tc.desc: Test BuildRgbDecodePlan clamps an oversized desired size to the source size.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbDecodePlanDesiredClampTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanDesiredClampTest start";
    auto codec = MakeCodec(PROGRESSIVE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "progressive jpeg resource unavailable: " << PROGRESSIVE_JPEG_FILE;
    }
    const SkImageInfo imageInfo = codec->getInfo();
    auto options = MakeRgbDecodeOptions(codec.get(), imageInfo);
    options.desiredSize = { imageInfo.width() + 1, imageInfo.height() + 1 };
    ProgressiveJpegDecoder::RgbDecodePlan plan;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbDecodePlan(options, plan));
    EXPECT_FALSE(plan.useDesiredSize);
    EXPECT_EQ(plan.dstInfo.width(), imageInfo.width());
    EXPECT_EQ(plan.dstInfo.height(), imageInfo.height());
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanDesiredClampTest end";
}

/**
 * @tc.name: BuildRgbDecodePlanZeroDesiredSizeTest
 * @tc.desc: Test BuildRgbDecodePlan falls back to the source size when the desired size is not positive.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbDecodePlanZeroDesiredSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanZeroDesiredSizeTest start";
    auto codec = MakeCodec(PROGRESSIVE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "progressive jpeg resource unavailable: " << PROGRESSIVE_JPEG_FILE;
    }
    const SkImageInfo imageInfo = codec->getInfo();
    const SkImageInfo dstInfo = imageInfo.makeWH(imageInfo.width() / SCALE_HALF, imageInfo.height() / SCALE_HALF);
    auto options = MakeRgbDecodeOptions(codec.get(), dstInfo);
    options.desiredSize = { 0, -1 };
    ProgressiveJpegDecoder::RgbDecodePlan plan;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbDecodePlan(options, plan));
    EXPECT_TRUE(plan.useDesiredSize);
    EXPECT_EQ(plan.dstInfo.width(), imageInfo.width());
    EXPECT_EQ(plan.dstInfo.height(), imageInfo.height());
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanZeroDesiredSizeTest end";
}

/**
 * @tc.name: BuildRgbDecodePlanOutputBufferTest
 * @tc.desc: Test BuildRgbDecodePlan keeps the caller destination when an output buffer is already allocated.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbDecodePlanOutputBufferTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanOutputBufferTest start";
    auto codec = MakeCodec(PROGRESSIVE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "progressive jpeg resource unavailable: " << PROGRESSIVE_JPEG_FILE;
    }
    const SkImageInfo imageInfo = codec->getInfo();
    const SkImageInfo dstInfo = imageInfo.makeWH(imageInfo.width() / SCALE_HALF, imageInfo.height() / SCALE_HALF);
    auto options = MakeRgbDecodeOptions(codec.get(), dstInfo);
    options.desiredSize = { imageInfo.width() / SCALE_QUARTER, imageInfo.height() / SCALE_QUARTER };
    options.hasOutputBuffer = true;
    ProgressiveJpegDecoder::RgbDecodePlan plan;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbDecodePlan(options, plan));
    EXPECT_FALSE(plan.useDesiredSize);
    EXPECT_EQ(plan.dstInfo.width(), dstInfo.width());
    EXPECT_EQ(plan.dstInfo.height(), dstInfo.height());
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanOutputBufferTest end";
}

/**
 * @tc.name: BuildRgbDecodePlanRgb888Test
 * @tc.desc: Test BuildRgbDecodePlan reports a packed RGB888 output with three bytes per pixel.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbDecodePlanRgb888Test, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanRgb888Test start";
    auto codec = MakeCodec(PROGRESSIVE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "progressive jpeg resource unavailable: " << PROGRESSIVE_JPEG_FILE;
    }
    const SkImageInfo imageInfo = codec->getInfo();
    auto options = MakeRgbDecodeOptions(codec.get(), imageInfo);
    options.pixelFormat = PixelFormat::RGB_888;
    ProgressiveJpegDecoder::RgbDecodePlan plan;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildRgbDecodePlan(options, plan));
    EXPECT_TRUE(plan.isRgb888Output);
    EXPECT_EQ(static_cast<int32_t>(plan.pixelFormat), static_cast<int32_t>(PixelFormat::RGB_888));
    const uint64_t expectedBytes = static_cast<uint64_t>(imageInfo.width()) *
        static_cast<uint64_t>(imageInfo.height()) * RGB_BYTES_PER_PIXEL;
    EXPECT_EQ(plan.byteCount, expectedBytes);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanRgb888Test end";
}

/**
 * @tc.name: BuildRgbDecodePlanSmallImageTest
 * @tc.desc: Test BuildRgbDecodePlan keeps small JPEGs on the software path.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbDecodePlanSmallImageTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanSmallImageTest start";
    auto codec = MakeCodec(BASELINE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "jpeg resource unavailable: " << BASELINE_JPEG_FILE;
    }
    auto options = MakeRgbDecodeOptions(codec.get(), codec->getInfo());
    ProgressiveJpegDecoder::RgbDecodePlan plan;

    EXPECT_FALSE(ProgressiveJpegDecoder::BuildRgbDecodePlan(options, plan));
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanSmallImageTest end";
}

/**
 * @tc.name: BuildRgbDecodePlanBaselineImageTest
 * @tc.desc: Test BuildRgbDecodePlan keeps a large baseline JPEG on the software path.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildRgbDecodePlanBaselineImageTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanBaselineImageTest start";
    auto codec = MakeCodec(LARGE_BASELINE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "jpeg resource unavailable: " << LARGE_BASELINE_JPEG_FILE;
    }
    auto options = MakeRgbDecodeOptions(codec.get(), codec->getInfo());
    ProgressiveJpegDecoder::RgbDecodePlan plan;

    EXPECT_FALSE(ProgressiveJpegDecoder::BuildRgbDecodePlan(options, plan));
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildRgbDecodePlanBaselineImageTest end";
}
/**
 * @tc.name: BuildYuvDecodePlanRejectedOptionsTest
 * @tc.desc: Test BuildYuvDecodePlan rejects missing codecs, region decode, incomplete sources, subsets and RGB.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildYuvDecodePlanRejectedOptionsTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildYuvDecodePlanRejectedOptionsTest start";
    auto codec = MakeCodec(PROGRESSIVE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "progressive jpeg resource unavailable: " << PROGRESSIVE_JPEG_FILE;
    }
    std::vector<ProgressiveJpegDecoder::YuvDecodeOptions> rejected;

    auto noCodecOptions = MakeYuvDecodeOptions(codec.get(), { 0, 0 });
    noCodecOptions.codec = nullptr;
    rejected.push_back(noCodecOptions);

    auto regionOptions = MakeYuvDecodeOptions(codec.get(), { 0, 0 });
    regionOptions.supportRegion = true;
    rejected.push_back(regionOptions);

    auto incompleteOptions = MakeYuvDecodeOptions(codec.get(), { 0, 0 });
    incompleteOptions.ifSourceCompleted = false;
    rejected.push_back(incompleteOptions);

    auto subsetOptions = MakeYuvDecodeOptions(codec.get(), { 0, 0 });
    subsetOptions.hasSubset = true;
    rejected.push_back(subsetOptions);

    auto rgbOptions = MakeYuvDecodeOptions(codec.get(), { 0, 0 });
    rgbOptions.pixelFormat = PixelFormat::RGBA_8888;
    rejected.push_back(rgbOptions);

    for (const auto &options : rejected) {
        ProgressiveJpegDecoder::YuvDecodePlan plan;
        EXPECT_FALSE(ProgressiveJpegDecoder::BuildYuvDecodePlan(options, plan));
    }
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildYuvDecodePlanRejectedOptionsTest end";
}

/**
 * @tc.name: BuildYuvDecodePlanSourceSizeTest
 * @tc.desc: Test BuildYuvDecodePlan uses the full source size and its 4:2:0 buffer size when no size is requested.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildYuvDecodePlanSourceSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildYuvDecodePlanSourceSizeTest start";
    auto codec = MakeCodec(PROGRESSIVE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "progressive jpeg resource unavailable: " << PROGRESSIVE_JPEG_FILE;
    }
    const auto options = MakeYuvDecodeOptions(codec.get(), { 0, 0 });
    ProgressiveJpegDecoder::YuvDecodePlan plan;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildYuvDecodePlan(options, plan));
    EXPECT_EQ(plan.size.width, codec->getInfo().width());
    EXPECT_EQ(plan.size.height, codec->getInfo().height());
    const uint64_t expectedBytes = static_cast<uint64_t>(plan.size.width) * plan.size.height *
        YUV_BYTES_PER_PIXEL_NUMERATOR / YUV_BYTES_PER_PIXEL_DENOMINATOR;
    EXPECT_EQ(plan.bufferSize, expectedBytes);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildYuvDecodePlanSourceSizeTest end";
}

/**
 * @tc.name: BuildYuvDecodePlanDesiredSizeTest
 * @tc.desc: Test BuildYuvDecodePlan adopts a smaller desired size and sizes the YUV buffer for it.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildYuvDecodePlanDesiredSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildYuvDecodePlanDesiredSizeTest start";
    auto codec = MakeCodec(PROGRESSIVE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "progressive jpeg resource unavailable: " << PROGRESSIVE_JPEG_FILE;
    }
    const int32_t desiredWidth = codec->getInfo().width() / SCALE_QUARTER;
    const int32_t desiredHeight = codec->getInfo().height() / SCALE_QUARTER;
    const auto options = MakeYuvDecodeOptions(codec.get(), { desiredWidth, desiredHeight });
    ProgressiveJpegDecoder::YuvDecodePlan plan;

    ASSERT_TRUE(ProgressiveJpegDecoder::BuildYuvDecodePlan(options, plan));
    EXPECT_EQ(plan.size.width, desiredWidth);
    EXPECT_EQ(plan.size.height, desiredHeight);
    const uint64_t expectedBytes = static_cast<uint64_t>(desiredWidth) * desiredHeight *
        YUV_BYTES_PER_PIXEL_NUMERATOR / YUV_BYTES_PER_PIXEL_DENOMINATOR;
    EXPECT_EQ(plan.bufferSize, expectedBytes);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildYuvDecodePlanDesiredSizeTest end";
}

/**
 * @tc.name: BuildYuvDecodePlanInvalidSizeTest
 * @tc.desc: Test BuildYuvDecodePlan rejects a desired size larger than the source and an empty source size.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildYuvDecodePlanInvalidSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildYuvDecodePlanInvalidSizeTest start";
    auto codec = MakeCodec(PROGRESSIVE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "progressive jpeg resource unavailable: " << PROGRESSIVE_JPEG_FILE;
    }
    auto oversizedOptions = MakeYuvDecodeOptions(codec.get(),
        { codec->getInfo().width() + 1, codec->getInfo().height() });
    ProgressiveJpegDecoder::YuvDecodePlan oversizedPlan;
    EXPECT_FALSE(ProgressiveJpegDecoder::BuildYuvDecodePlan(oversizedOptions, oversizedPlan));

    auto emptySourceOptions = MakeYuvDecodeOptions(codec.get(), { 0, 0 });
    emptySourceOptions.sourceSize = { 0, 0 };
    ProgressiveJpegDecoder::YuvDecodePlan emptySourcePlan;
    EXPECT_FALSE(ProgressiveJpegDecoder::BuildYuvDecodePlan(emptySourceOptions, emptySourcePlan));
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildYuvDecodePlanInvalidSizeTest end";
}

/**
 * @tc.name: BuildYuvDecodePlanBaselineImageTest
 * @tc.desc: Test BuildYuvDecodePlan keeps a baseline JPEG on the software path.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, BuildYuvDecodePlanBaselineImageTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildYuvDecodePlanBaselineImageTest start";
    auto codec = MakeCodec(BASELINE_JPEG_FILE);
    if (codec == nullptr) {
        GTEST_SKIP() << "jpeg resource unavailable: " << BASELINE_JPEG_FILE;
    }
    const auto options = MakeYuvDecodeOptions(codec.get(), { 0, 0 });
    ProgressiveJpegDecoder::YuvDecodePlan plan;

    EXPECT_FALSE(ProgressiveJpegDecoder::BuildYuvDecodePlan(options, plan));
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: BuildYuvDecodePlanBaselineImageTest end";
}

/**
 * @tc.name: IsProgressiveJpegDetectionTest
 * @tc.desc: Test IsProgressiveJpeg reports the JPEG scan mode and refuses null and non-JPEG codecs.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, IsProgressiveJpegDetectionTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: IsProgressiveJpegDetectionTest start";
    EXPECT_FALSE(ProgressiveJpegDecoder::IsProgressiveJpeg(nullptr));

    auto progressiveCodec = MakeCodec(PROGRESSIVE_JPEG_FILE);
    if (progressiveCodec == nullptr) {
        GTEST_SKIP() << "progressive jpeg resource unavailable: " << PROGRESSIVE_JPEG_FILE;
    }
    EXPECT_TRUE(ProgressiveJpegDecoder::IsProgressiveJpeg(progressiveCodec.get()));

    auto baselineCodec = MakeCodec(LARGE_BASELINE_JPEG_FILE);
    if (baselineCodec != nullptr) {
        EXPECT_FALSE(ProgressiveJpegDecoder::IsProgressiveJpeg(baselineCodec.get()));
    }

    auto pngCodec = MakeCodec(PNG_FILE);
    if (pngCodec != nullptr) {
        EXPECT_EQ(static_cast<int32_t>(pngCodec->getEncodedFormat()),
            static_cast<int32_t>(SkEncodedImageFormat::kPNG));
        EXPECT_FALSE(ProgressiveJpegDecoder::IsProgressiveJpeg(pngCodec.get()));
    }
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: IsProgressiveJpegDetectionTest end";
}

/**
 * @tc.name: GetJpegInputDataNullStreamTest
 * @tc.desc: Test GetJpegInputData rejects a null stream.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, GetJpegInputDataNullStreamTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataNullStreamTest start";
    ProgressiveJpegDecoder::JpegInputData jpegData;
    auto readJpegData = [](uint8_t *, uint32_t) { return static_cast<uint32_t>(SUCCESS); };

    EXPECT_EQ(ProgressiveJpegDecoder::GetJpegInputData(nullptr, readJpegData, jpegData), ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataNullStreamTest end";
}

/**
 * @tc.name: GetJpegInputDataEmptyStreamTest
 * @tc.desc: Test GetJpegInputData rejects an empty stream.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, GetJpegInputDataEmptyStreamTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataEmptyStreamTest start";
    MockInputDataStream stream;
    ProgressiveJpegDecoder::JpegInputData jpegData;
    auto readJpegData = [](uint8_t *, uint32_t) { return static_cast<uint32_t>(SUCCESS); };

    EXPECT_EQ(ProgressiveJpegDecoder::GetJpegInputData(&stream, readJpegData, jpegData), ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataEmptyStreamTest end";
}

/**
 * @tc.name: GetJpegInputDataOversizeStreamTest
 * @tc.desc: Test GetJpegInputData rejects a stream above the 100MB JPEG limit before copying anything.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, GetJpegInputDataOversizeStreamTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataOversizeStreamTest start";
    MockInputDataStream stream;
    stream.SetStreamSize(static_cast<size_t>(MAX_JPEG_BUFFER_SIZE) + 1);
    ProgressiveJpegDecoder::JpegInputData jpegData;
    bool readCalled = false;
    auto readJpegData = [&readCalled](uint8_t *, uint32_t) {
        readCalled = true;
        return static_cast<uint32_t>(SUCCESS);
    };

    EXPECT_EQ(ProgressiveJpegDecoder::GetJpegInputData(&stream, readJpegData, jpegData), ERR_IMAGE_TOO_LARGE);
    EXPECT_FALSE(readCalled);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataOversizeStreamTest end";
}

/**
 * @tc.name: GetJpegInputDataBufferStreamTest
 * @tc.desc: Test GetJpegInputData reuses the stream buffer without copying or invoking the read callback.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, GetJpegInputDataBufferStreamTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataBufferStreamTest start";
    std::vector<uint8_t> streamBytes(JPEG_INPUT_BUFFER_SIZE, BUFFER_FILL_BYTE);
    MockInputDataStream stream;
    stream.SetStreamType(BUFFER_SOURCE_TYPE);
    stream.SetStreamSize(streamBytes.size());
    stream.SetDataPtr(streamBytes.data());
    ProgressiveJpegDecoder::JpegInputData jpegData;
    bool readCalled = false;
    auto readJpegData = [&readCalled](uint8_t *, uint32_t) {
        readCalled = true;
        return static_cast<uint32_t>(SUCCESS);
    };

    EXPECT_EQ(ProgressiveJpegDecoder::GetJpegInputData(&stream, readJpegData, jpegData), SUCCESS);
    EXPECT_EQ(jpegData.buffer, streamBytes.data());
    EXPECT_EQ(jpegData.bufferSize, streamBytes.size());
    EXPECT_EQ(jpegData.ownedBuffer, nullptr);
    EXPECT_FALSE(readCalled);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataBufferStreamTest end";
}

/**
 * @tc.name: GetJpegInputDataCopyStreamTest
 * @tc.desc: Test GetJpegInputData allocates and fills a private copy for a non-buffer stream.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, GetJpegInputDataCopyStreamTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataCopyStreamTest start";
    MockInputDataStream stream;
    stream.SetStreamType(INPUT_STREAM_TYPE);
    stream.SetStreamSize(COPY_STREAM_BYTES);
    ProgressiveJpegDecoder::JpegInputData jpegData;
    auto readJpegData = [](uint8_t *buffer, uint32_t size) {
        EXPECT_NE(buffer, nullptr);
        EXPECT_EQ(size, static_cast<uint32_t>(COPY_STREAM_BYTES));
        std::memset(buffer, COPY_FILL_BYTE, size);
        return static_cast<uint32_t>(SUCCESS);
    };

    EXPECT_EQ(ProgressiveJpegDecoder::GetJpegInputData(&stream, readJpegData, jpegData), SUCCESS);
    ASSERT_NE(jpegData.ownedBuffer, nullptr);
    EXPECT_EQ(jpegData.buffer, jpegData.ownedBuffer.get());
    EXPECT_EQ(jpegData.bufferSize, COPY_STREAM_BYTES);
    EXPECT_EQ(jpegData.buffer[0], COPY_FILL_BYTE);
    EXPECT_EQ(jpegData.buffer[COPY_STREAM_BYTES - 1], COPY_FILL_BYTE);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataCopyStreamTest end";
}

/**
 * @tc.name: GetJpegInputDataNullCallbackTest
 * @tc.desc: Test GetJpegInputData reports a missing read callback for a non-buffer stream.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, GetJpegInputDataNullCallbackTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataNullCallbackTest start";
    MockInputDataStream stream;
    stream.SetStreamType(INPUT_STREAM_TYPE);
    stream.SetStreamSize(JPEG_INPUT_BUFFER_SIZE);
    ProgressiveJpegDecoder::JpegInputData jpegData;
    ProgressiveJpegDecoder::ReadJpegDataFunc readJpegData;

    EXPECT_EQ(ProgressiveJpegDecoder::GetJpegInputData(&stream, readJpegData, jpegData),
        ERR_IMAGE_GET_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataNullCallbackTest end";
}

/**
 * @tc.name: GetJpegInputDataReadFailureTest
 * @tc.desc: Test GetJpegInputData propagates a failing read callback.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, GetJpegInputDataReadFailureTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataReadFailureTest start";
    MockInputDataStream stream;
    stream.SetStreamType(INPUT_STREAM_TYPE);
    stream.SetStreamSize(JPEG_INPUT_BUFFER_SIZE);
    ProgressiveJpegDecoder::JpegInputData jpegData;
    auto readJpegData = [](uint8_t *, uint32_t) {
        return static_cast<uint32_t>(ERR_IMAGE_GET_DATA_ABNORMAL);
    };

    EXPECT_EQ(ProgressiveJpegDecoder::GetJpegInputData(&stream, readJpegData, jpegData),
        ERR_IMAGE_GET_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetJpegInputDataReadFailureTest end";
}

/**
 * @tc.name: GetRgbOutputByteCountTest
 * @tc.desc: Test GetRgbOutputByteCount uses three bytes per pixel for packed RGB888 and the Skia stride otherwise.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, GetRgbOutputByteCountTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetRgbOutputByteCountTest start";
    const SkImageInfo imageInfo = MakeRgbaImageInfo(BYTE_COUNT_WIDTH, BYTE_COUNT_HEIGHT);

    const uint64_t rgb888Bytes = static_cast<uint64_t>(BYTE_COUNT_WIDTH) * BYTE_COUNT_HEIGHT * RGB_BYTES_PER_PIXEL;
    EXPECT_EQ(ProgressiveJpegDecoder::GetRgbOutputByteCount(imageInfo, true), rgb888Bytes);
    EXPECT_EQ(ProgressiveJpegDecoder::GetRgbOutputByteCount(imageInfo, false),
        static_cast<uint64_t>(imageInfo.computeMinByteSize()));
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetRgbOutputByteCountTest end";
}

/**
 * @tc.name: GetOutputRowStrideTest
 * @tc.desc: Test GetOutputRowStride returns the Skia row stride for heap buffers and reports a missing DMA buffer.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, GetOutputRowStrideTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetOutputRowStrideTest start";
    const SkImageInfo imageInfo = MakeRgbaImageInfo(BYTE_COUNT_WIDTH, BYTE_COUNT_HEIGHT);
    DecodeContext context;
    context.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    EXPECT_EQ(ProgressiveJpegDecoder::GetOutputRowStride(imageInfo, context, nullptr),
        static_cast<uint64_t>(imageInfo.minRowBytes64()));

#if !defined(CROSS_PLATFORM)
    // A DMA buffer without a SurfaceBuffer cannot provide a stride and must not be guessed.
    context.allocatorType = AllocatorType::DMA_ALLOC;
    context.pixelsBuffer.buffer = nullptr;
    EXPECT_EQ(ProgressiveJpegDecoder::GetOutputRowStride(imageInfo, context, nullptr), 0u);
#endif
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: GetOutputRowStrideTest end";
}

/**
 * @tc.name: ResetDecodeContextPixelsBufferTest
 * @tc.desc: Test ResetDecodeContextPixelsBuffer clears the release callback and the pixel buffer ownership.
 * @tc.type: FUNC
 */
HWTEST_F(ProgressiveJpegDecoderTest, ResetDecodeContextPixelsBufferTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: ResetDecodeContextPixelsBufferTest start";
    std::vector<uint8_t> pixels(STORAGE_BYTES, 0);
    DecodeContext context;
    context.freeFunc = ContextFreeStub;
    context.pixelsBuffer.buffer = pixels.data();
    context.pixelsBuffer.bufferSize = static_cast<uint32_t>(pixels.size());
    context.pixelsBuffer.context = pixels.data();

    ProgressiveJpegDecoder::ResetDecodeContextPixelsBuffer(context);
    EXPECT_EQ(context.freeFunc, nullptr);
    EXPECT_EQ(context.pixelsBuffer.buffer, nullptr);
    EXPECT_EQ(context.pixelsBuffer.bufferSize, 0u);
    EXPECT_EQ(context.pixelsBuffer.context, nullptr);
    GTEST_LOG_(INFO) << "ProgressiveJpegDecoderTest: ResetDecodeContextPixelsBufferTest end";
}
} // namespace ImagePlugin
} // namespace OHOS
