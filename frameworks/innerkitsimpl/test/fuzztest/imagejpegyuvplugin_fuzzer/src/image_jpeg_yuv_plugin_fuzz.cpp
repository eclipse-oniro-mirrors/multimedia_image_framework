/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <fuzzer/FuzzedDataProvider.h>
#include "image_jpeg_yuv_plugin_fuzz.h"

#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>

#include "buffer_source_stream.h"
#include "common_fuzztest_function.h"
#include "data_buf.h"
#include "jpeg_decoder_yuv.h"
#include "image_log.h"
#include "image_utils.h"
#include "surface_buffer.h"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
FuzzedDataProvider *FDP;

namespace {
    static constexpr uint32_t YUV_COMPONENT_INDEX_MODULE = 4;
    static constexpr uint32_t JPEG_YUV_FMT_MODULE = 4;
    static constexpr uint32_t YUVCOMPONENT_SIZE = 4;
    static constexpr uint32_t ALLOCATOR_TYPE_MODULE = 5;
    static constexpr uint32_t COLOR_SPACE_MODULE = 17;
    static constexpr uint32_t IMAGE_HDR_TYPE_MODULE = 8;
    static constexpr uint32_t ALPHA_TYPE_MODULE = 4;
    static constexpr uint32_t RESOLUTION_QUALITY_MODULE = 4;
    static constexpr uint32_t PIXEL_FORMAT_MODULE = 105;
    static constexpr uint32_t NUM_0 = 0;
    static constexpr uint32_t MAX_IMAGE_SIZE = 8192;

    std::vector<uint8_t> YUV_BUFFER;

    unsigned char g_mockPlanes[YUVCOMPONENT_SIZE] = { 0 };

    int MOCK_FUNC(const YuvPlaneInfo& src, const YuvPlaneInfo& dest)
    {
        (void)src;
        (void)dest;
        return FDP == nullptr ? 0 : FDP->ConsumeIntegral<int>();
    }
}

Size ConstructSize()
{
    return Size {
        .width = FDP->ConsumeIntegral<int32_t>(),
        .height = FDP->ConsumeIntegral<int32_t>() };
}

YUVDataInfo ConstructYUVDataInfo()
{
    return YUVDataInfo {
        .imageSize = ConstructSize(),
        .yWidth = FDP->ConsumeIntegral<uint32_t>(),
        .yHeight = FDP->ConsumeIntegral<uint32_t>(),
        .uvWidth = FDP->ConsumeIntegral<uint32_t>(),
        .uvHeight = FDP->ConsumeIntegral<uint32_t>(),
        .yStride = FDP->ConsumeIntegral<uint32_t>(),
        .uStride = FDP->ConsumeIntegral<uint32_t>(),
        .vStride = FDP->ConsumeIntegral<uint32_t>(),
        .uvStride = FDP->ConsumeIntegral<uint32_t>(),
        .yOffset = FDP->ConsumeIntegral<uint32_t>(),
        .uOffset = FDP->ConsumeIntegral<uint32_t>(),
        .vOffset = FDP->ConsumeIntegral<uint32_t>(),
        .uvOffset = FDP->ConsumeIntegral<uint32_t>() };
}

PlImageInfo ConstructPlImageInfo()
{
    return PlImageInfo {
        .size = ConstructSize(),
        .pixelFormat = static_cast<PixelFormat>(FDP->ConsumeIntegral<uint32_t>() % PIXEL_FORMAT_MODULE),
        .colorSpace = static_cast<ColorSpace>(FDP->ConsumeIntegral<uint32_t>() % COLOR_SPACE_MODULE),
        .alphaType = static_cast<AlphaType>(FDP->ConsumeIntegral<uint32_t>() % ALPHA_TYPE_MODULE),
        .yuvDataInfo = ConstructYUVDataInfo() };
}

DecodeContext ConstructDecodeContext()
{
    DecodeContext context{
        .info = ConstructPlImageInfo(),
        .pixelmapUniqueId_ = FDP->ConsumeIntegral<uint32_t>(),
        .ifSourceCompleted = FDP->ConsumeBool(),
        .pixelFormat = static_cast<PixelFormat>(FDP->ConsumeIntegral<uint32_t>() % PIXEL_FORMAT_MODULE),
        .photoDesiredPixelFormat = static_cast<PixelFormat>(FDP->ConsumeIntegral<uint32_t>() % PIXEL_FORMAT_MODULE),
        .colorSpace = static_cast<ColorSpace>(FDP->ConsumeIntegral<uint32_t>() % COLOR_SPACE_MODULE),
        .ifPartialOutput = FDP->ConsumeBool(),
        .allocatorType = static_cast<AllocatorType>(FDP->ConsumeIntegral<uint32_t>() % ALLOCATOR_TYPE_MODULE),
        .yuvInfo = ConstructYUVDataInfo(),
        .isHardDecode = FDP->ConsumeBool(),
        .hdrType = static_cast<ImageHdrType>(FDP->ConsumeIntegral<uint32_t>() % IMAGE_HDR_TYPE_MODULE),
        .resolutionQuality =
            static_cast<ResolutionQuality>(FDP->ConsumeIntegral<uint32_t>() % RESOLUTION_QUALITY_MODULE),
        .isAisr = FDP->ConsumeBool(),
        .isAppUseAllocator = FDP->ConsumeBool(),
        .isCreateWideGamutSdrPixelMap = FDP->ConsumeBool() };

    if (context.allocatorType == AllocatorType::DMA_ALLOC) {
        sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
        BufferRequestConfig requestConfig = {
            .width = context.info.size.width,
            .height = context.info.size.height,
            .strideAlignment = 0x8, // set 0x8 as default value to alloc SurfaceBufferImpl
            .format = GRAPHIC_PIXEL_FMT_RGBA_8888, // PixelFormat
            .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
            .timeout = 0,
            .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
            .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,
        };
        GSError ret = sb->Alloc(requestConfig);
        if (ret != GSERROR_OK) {
            return context;
        }
        void* nativeBuffer = sb.GetRefPtr();
        if (ImageUtils::SurfaceBuffer_Reference(nativeBuffer) != OHOS::GSERROR_OK) {
            return context;
        }
        context.pixelsBuffer.buffer = sb->GetVirAddr();
        context.pixelsBuffer.context = nativeBuffer;
        context.pixelsBuffer.bufferSize = sb->GetSize();
        context.allocatorType = AllocatorType::DMA_ALLOC;
        context.freeFunc = nullptr;
    }
    return context;
}

JpegDecoderYuvParameter ConstructJpegDecoderYuvParameter(const uint8_t *data, size_t size)
{
    uint8_t *yuvBuffer { nullptr };
    uint32_t yuvWidth = FDP->ConsumeIntegralInRange<uint32_t>(NUM_0, MAX_IMAGE_SIZE);
    uint32_t yuvHeight = FDP->ConsumeIntegralInRange<uint32_t>(NUM_0, MAX_IMAGE_SIZE);
    uint32_t yuvBufferSize = JpegDecoderYuv::GetYuvOutSize(yuvWidth, yuvHeight);
    if (yuvBufferSize != 0) {
        YUV_BUFFER = FDP->ConsumeBytes<uint8_t>(yuvBufferSize);
        yuvBuffer = YUV_BUFFER.data();
    }
    return JpegDecoderYuvParameter {
        .jpgwidth_ = 0,
        .jpgheight_ = 0,
        .jpegBuffer_ = data,
        .jpegBufferSize_ = size,
        .yuvBuffer_ = yuvBuffer,
        .yuvBufferSize_ = yuvBufferSize,
        .outfmt_ = static_cast<JpegYuvFmt>(FDP->ConsumeIntegralInRange<uint32_t>(1, JPEG_YUV_FMT_MODULE)),
        .outwidth_ = yuvWidth,
        .outheight_ = yuvHeight };
}

YuvPlaneInfo ConstructYuvPlaneInfo()
{
    YuvPlaneInfo yuvPlaneInfo;
    yuvPlaneInfo.imageWidth = FDP->ConsumeIntegral<uint32_t>();
    yuvPlaneInfo.imageHeight = FDP->ConsumeIntegral<uint32_t>();
    for (uint32_t i = 0; i < YUVCOMPONENT_SIZE; i++) {
        yuvPlaneInfo.planeWidth[i] = FDP->ConsumeIntegral<uint32_t>();
        yuvPlaneInfo.planeHeight[i] = FDP->ConsumeIntegral<uint32_t>();
        yuvPlaneInfo.strides[i] = FDP->ConsumeIntegral<uint32_t>();
        if (FDP->ConsumeBool()) {
            yuvPlaneInfo.planes[i] = &g_mockPlanes[i];
        } else {
            yuvPlaneInfo.planes[i] = nullptr;
        }
    }
    return yuvPlaneInfo;
}

ConverterPair ConstructConverterPair()
{
    ConverterPair converterPair;
    if (FDP->ConsumeBool()) {
        converterPair.to420Func = MOCK_FUNC;
    }
    if (FDP->ConsumeBool()) {
        converterPair.toNV21Func = MOCK_FUNC;
    }
    return converterPair;
}

void IsSupportedSubSampleFuzzTest(std::shared_ptr<JpegDecoderYuv> jpegDecoderYuv)
{
    if (!jpegDecoderYuv) {
        return;
    }
    jpegDecoderYuv->IsSupportedSubSample(FDP->ConsumeIntegral<int>());
}

void GetScaledSizeFuzzTest(std::shared_ptr<JpegDecoderYuv> jpegDecoderYuv)
{
    if (!jpegDecoderYuv) {
        return;
    }
    int32_t width = FDP->ConsumeIntegral<int32_t>();
    int32_t height = FDP->ConsumeIntegral<int32_t>();
    jpegDecoderYuv->GetScaledSize(
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>(),
        width,
        height);
}

void GetScaledFactorFuzzTest(std::shared_ptr<JpegDecoderYuv> jpegDecoderYuv)
{
    if (!jpegDecoderYuv) {
        return;
    }
    jpegDecoderYuv->GetScaledFactor(
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>());
}

void Get420OutPlaneSizeFuzzTest()
{
    JpegDecoderYuv::Get420OutPlaneSize(
        static_cast<YuvComponentIndex>(FDP->ConsumeIntegral<uint32_t>() % YUV_COMPONENT_INDEX_MODULE),
        FDP->ConsumeIntegral<int>(),
        FDP->ConsumeIntegral<int>());
}

void GetYuvOutSizeFuzzTest()
{
    JpegDecoderYuv::GetYuvOutSize(FDP->ConsumeIntegral<int>(), FDP->ConsumeIntegral<int>());
}

void GetJpegDecompressedYuvSizeFuzzTest()
{
    JpegDecoderYuv::GetJpegDecompressedYuvSize(
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<int>());
}

void InitYuvDataOutInfoTo420FuzzTest()
{
    YUVDataInfo yuvDataInfo;
    JpegDecoderYuv::InitYuvDataOutInfoTo420(
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>(),
        yuvDataInfo,
        static_cast<JpegYuvFmt>(FDP->ConsumeIntegralInRange<uint32_t>(1, JPEG_YUV_FMT_MODULE)));
}

void InitPlaneOutInfoTo420FuzzTest()
{
    YuvPlaneInfo yuvPlaneInfo = ConstructYuvPlaneInfo();
    JpegDecoderYuv::InitPlaneOutInfoTo420(
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>(),
        yuvPlaneInfo);
}

void InitPlaneOutInfoTo420NVFuzzTest()
{
    YuvPlaneInfo yuvPlaneInfo = ConstructYuvPlaneInfo();
    JpegDecoderYuv::InitPlaneOutInfoTo420NV(
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>(),
        yuvPlaneInfo);
}

void IsYU12YV12FormatFuzzTest()
{
    JpegDecoderYuv::IsYU12YV12Format(
        static_cast<JpegYuvFmt>(FDP->ConsumeIntegralInRange<uint32_t>(1, JPEG_YUV_FMT_MODULE)));
}

void DoDecodeFuzzTest(std::shared_ptr<JpegDecoderYuv> jpegDecoderYuv, const uint8_t *data, size_t size)
{
    if (!jpegDecoderYuv) {
        return;
    }
    DecodeContext context = ConstructDecodeContext();
    JpegDecoderYuvParameter jpegDecoderYuvParameter = ConstructJpegDecoderYuvParameter(data, size);
    jpegDecoderYuv->DoDecode(context, jpegDecoderYuvParameter);
}

void JpegDecoderYuvFuzzTest001(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    std::shared_ptr<JpegDecoderYuv> jpegDecoderYuv = std::make_shared<JpegDecoderYuv>();
    if (!jpegDecoderYuv) {
        return;
    }
    IsSupportedSubSampleFuzzTest(jpegDecoderYuv);
    GetScaledSizeFuzzTest(jpegDecoderYuv);
    GetScaledFactorFuzzTest(jpegDecoderYuv);
    Get420OutPlaneSizeFuzzTest();
    GetYuvOutSizeFuzzTest();
    GetJpegDecompressedYuvSizeFuzzTest();
    InitYuvDataOutInfoTo420FuzzTest();
    InitPlaneOutInfoTo420FuzzTest();
    InitPlaneOutInfoTo420NVFuzzTest();
    IsYU12YV12FormatFuzzTest();
    DoDecodeFuzzTest(jpegDecoderYuv, data, size);
}
}  // namespace Media
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    /* Run your code on data */
    OHOS::Media::JpegDecoderYuvFuzzTest001(data, size);
    return 0;
}
