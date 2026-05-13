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

#include "bandjpeg/progressive_jpeg_decoder.h"

#include <algorithm>

#include "bandjpeg/fast_manager.h"
#include "image_log.h"
#include "input_data_stream.h"
#include "jpeg_yuv_decoder/jpeg_decoder_yuv.h"
#include "media_errors.h"
#include "securec.h"
#include "src/codec/SkJpegCodec.h"
#include "src/codec/SkJpegDecoderMgr.h"
#if !defined(CROSS_PLATFORM)
#include "surface_buffer.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "ProgressiveJpegDecoder"

namespace {
constexpr static int32_t NUM_1 = 1;
constexpr static int32_t NUM_2 = 2;
constexpr static int32_t NUM_3 = 3;
constexpr static int32_t NUM_4 = 4;
constexpr static uint32_t DEFAULT_SAMPLE_SIZE = 1;
constexpr static int32_t BANDJPEG_V1_MIN_LONG_SIDE = 1080;
constexpr static int32_t BANDJPEG_V1_MAX_LONG_SIDE = 32768;  // 最大边长限制
constexpr static uint32_t MAX_JPEG_BUFFER_SIZE = 100 * 1024 * 1024;  // 最大 JPEG 缓冲区 100MB
}

namespace OHOS {
namespace ImagePlugin {
using namespace Media;

static bool IsProgressiveJpegCodec(SkCodec *codec)
{
    if (codec == nullptr || codec->getEncodedFormat() != SkEncodedImageFormat::kJPEG) {
        return false;
    }
    auto *jpegCodec = static_cast<SkJpegCodec *>(codec);
    if (jpegCodec->decoderMgr() == nullptr || jpegCodec->decoderMgr()->dinfo() == nullptr) {
        return false;
    }
    return jpegCodec->decoderMgr()->dinfo()->progressive_mode;
}

static bool IsLargeImage(const SkImageInfo &srcInfo)
{
    if (srcInfo.isEmpty()) {
        return false;
    }
    const int32_t width = srcInfo.width();
    const int32_t height = srcInfo.height();
    // 验证尺寸上限，防止超大图像导致 OOM
    if (width > BANDJPEG_V1_MAX_LONG_SIDE || height > BANDJPEG_V1_MAX_LONG_SIDE) {
        IMAGE_LOGE("Image size exceeds max limit: %{public}dx%{public}d", width, height);
        return false;
    }
    
    const int32_t longSide = std::max(width, height);
    return longSide >= BANDJPEG_V1_MIN_LONG_SIDE;
}

static bool IsRgbOutputFormatSupported(PixelFormat format)
{
    return format == PixelFormat::RGB_888 ||
        format == PixelFormat::RGBA_8888 ||
        format == PixelFormat::RGB_565 ||
        format == PixelFormat::BGRA_8888;
}

static bool IsYuvOutputFormatSupported(PixelFormat format)
{
    return format == PixelFormat::NV12 || format == PixelFormat::NV21;
}

static bool ResolveYuvDecodeSize(const Size &requestedSize, const Size &sourceSize, Size &decodeSize)
{
    if (sourceSize.width <= 0 || sourceSize.height <= 0) {
        return false;
    }
    if (requestedSize.width <= 0 || requestedSize.height <= 0) {
        decodeSize = sourceSize;
        return true;
    }
    if (requestedSize.width > sourceSize.width || requestedSize.height > sourceSize.height) {
        return false;
    }
    decodeSize = requestedSize;
    return true;
}

static bool ResolveRgbDecodeSize(const Size &requestedSize, const Size &sourceSize, Size &decodeSize)
{
    if (sourceSize.width <= 0 || sourceSize.height <= 0) {
        return false;
    }
    if (requestedSize.width <= 0 || requestedSize.height <= 0) {
        decodeSize = sourceSize;
        return true;
    }
    decodeSize.width = std::min(requestedSize.width, sourceSize.width);
    decodeSize.height = std::min(requestedSize.height, sourceSize.height);
    return decodeSize.width > 0 && decodeSize.height > 0;
}

static bool InitYuvDataInfo(DecodeContext &context, uint32_t width, uint32_t height)
{
    if (memset_s(&context.yuvInfo, sizeof(context.yuvInfo), 0, sizeof(context.yuvInfo)) != EOK) {
        IMAGE_LOGE("InitYuvDataInfo memset failed");
        return false;
    }
    context.yuvInfo.imageSize = { static_cast<int32_t>(width), static_cast<int32_t>(height) };
    context.yuvInfo.yWidth = width;
    context.yuvInfo.yHeight = height;
    context.yuvInfo.uvWidth = static_cast<uint32_t>((width + 1) / NUM_2);
    context.yuvInfo.uvHeight = static_cast<uint32_t>((height + 1) / NUM_2);
    context.yuvInfo.uStride = context.yuvInfo.uvWidth;
    context.yuvInfo.vStride = context.yuvInfo.uvWidth;
#if !defined(CROSS_PLATFORM)
    if (context.allocatorType == AllocatorType::DMA_ALLOC) {
        auto *surfaceBuffer = reinterpret_cast<SurfaceBuffer *>(context.pixelsBuffer.context);
        if (surfaceBuffer == nullptr) {
            IMAGE_LOGE("InitYuvDataInfo surfaceBuffer is nullptr");
            return false;
        }
        OH_NativeBuffer_Planes *planes = nullptr;
        GSError retVal = surfaceBuffer->GetPlanesInfo(reinterpret_cast<void**>(&planes));
        uint32_t uvIndex = (context.info.pixelFormat == PixelFormat::NV12) ? NUM_1 : NUM_2;
        if (retVal != OHOS::GSERROR_OK || planes == nullptr || planes->planeCount <= uvIndex) {
            IMAGE_LOGE("InitYuvDataInfo GetPlanesInfo failed, retVal:%{public}d planeCount:%{public}u",
                retVal, planes == nullptr ? 0 : planes->planeCount);
            return false;
        }
        context.yuvInfo.yStride = planes->planes[0].columnStride;
        context.yuvInfo.uvStride = planes->planes[uvIndex].columnStride;
        context.yuvInfo.yOffset = planes->planes[0].offset;
        context.yuvInfo.uvOffset = planes->planes[uvIndex].offset;
        return true;
    }
#endif
    context.yuvInfo.yStride = width;
    context.yuvInfo.uvStride = context.yuvInfo.uvWidth * NUM_2;
    context.yuvInfo.yOffset = 0;
    context.yuvInfo.uvOffset = context.yuvInfo.yStride * context.yuvInfo.yHeight;
    return true;
}

struct YuvDecodeDestination {
    uint8_t *dstY = nullptr;
    uint8_t *dstUV = nullptr;
    uint32_t width = 0;
    uint32_t height = 0;
    size_t yStride = 0;
    size_t uvStride = 0;
    fast::image::YUVFormat format = fast::image::YUVFormat::NV12;
};

static bool BuildYuvDestination(DecodeContext &context, const Size &size, YuvDecodeDestination &dstImage)
{
    if (context.pixelsBuffer.buffer == nullptr || !IsYuvOutputFormatSupported(context.info.pixelFormat)) {
        return false;
    }
    const uint32_t width = static_cast<uint32_t>(size.width);
    const uint32_t height = static_cast<uint32_t>(size.height);
    if (!InitYuvDataInfo(context, width, height)) {
        return false;
    }
    auto *base = static_cast<uint8_t *>(context.pixelsBuffer.buffer);
    dstImage.width = width;
    dstImage.height = height;
    dstImage.format = (context.info.pixelFormat == PixelFormat::NV12) ?
        fast::image::YUVFormat::NV12 : fast::image::YUVFormat::NV21;
    dstImage.dstY = base + context.yuvInfo.yOffset;
    dstImage.dstUV = base + context.yuvInfo.uvOffset;
    dstImage.yStride = context.yuvInfo.yStride;
    dstImage.uvStride = context.yuvInfo.uvStride;
    return true;
}

uint32_t ProgressiveJpegDecoder::GetJpegInputData(InputDataStream *stream, const ReadJpegDataFunc &readJpegData,
    JpegInputData &jpegData)
{
    CHECK_ERROR_RETURN_RET(stream == nullptr, ERR_IMAGE_SOURCE_DATA);
    jpegData.buffer = nullptr;
    jpegData.ownedBuffer.reset();
    
    uint64_t streamSize = stream->GetStreamSize();
    CHECK_ERROR_RETURN_RET_LOG(streamSize == 0, ERR_IMAGE_SOURCE_DATA, "jpegBufferSize 0");
    
    CHECK_ERROR_RETURN_RET_LOG(streamSize > MAX_JPEG_BUFFER_SIZE,
        ERR_IMAGE_TOO_LARGE, "jpegBufferSize %{public}llu exceeds max size", streamSize);
    
    CHECK_ERROR_RETURN_RET_LOG(streamSize > UINT32_MAX,
        ERR_IMAGE_TOO_LARGE, "jpegBufferSize %{public}llu exceeds uint32 max", streamSize);
    
    jpegData.bufferSize = static_cast<uint32_t>(streamSize);
    if (stream->GetStreamType() == ImagePlugin::BUFFER_SOURCE_TYPE) {
        jpegData.buffer = stream->GetDataPtr();
    }
    if (jpegData.buffer != nullptr) {
        return SUCCESS;
    }

    jpegData.ownedBuffer = std::make_unique<uint8_t[]>(jpegData.bufferSize);
    CHECK_ERROR_RETURN_RET_LOG(jpegData.ownedBuffer == nullptr, ERR_IMAGE_DECODE_ABNORMAL,
        "GetJpegInputData alloc input failed");
    jpegData.buffer = jpegData.ownedBuffer.get();
    CHECK_ERROR_RETURN_RET_LOG(!readJpegData, ERR_IMAGE_GET_DATA_ABNORMAL,
        "GetJpegInputData read callback is null");
    return readJpegData(jpegData.buffer, jpegData.bufferSize);
}

bool ProgressiveJpegDecoder::BuildRgbDecodePlan(const RgbDecodeOptions &options, RgbDecodePlan &plan)
{
    if (options.codec == nullptr || options.supportRegion || !options.ifSourceCompleted ||
        !IsRgbOutputFormatSupported(options.pixelFormat) ||
        options.hasSubset ||
        options.hasReusePixelmap) {
        return false;
    }
    if (options.pixelFormat == PixelFormat::RGB_888 && options.allocatorType == AllocatorType::DMA_ALLOC) {
        return false;
    }
    if (options.srcInfo.isEmpty() || options.dstInfo.isEmpty() ||
        options.codec->getEncodedFormat() != SkEncodedImageFormat::kJPEG ||
        options.dstInfo.refColorSpace().get() != options.srcInfo.refColorSpace().get()) {
        return false;
    }
    if (!IsLargeImage(options.srcInfo) || !IsProgressiveJpegCodec(options.codec)) {
        return false;
    }

    const Size sourceSize = {
        static_cast<int32_t>(options.srcInfo.width()), static_cast<int32_t>(options.srcInfo.height())
    };
    Size decodeSize = {
        static_cast<int32_t>(options.dstInfo.width()), static_cast<int32_t>(options.dstInfo.height())
    };
    if (!ResolveRgbDecodeSize(options.desiredSize, sourceSize, decodeSize)) {
        return false;
    }
    plan.useDesiredSize = !options.hasOutputBuffer &&
        (decodeSize.width != options.dstInfo.width() || decodeSize.height != options.dstInfo.height());
    plan.dstInfo = plan.useDesiredSize ? options.dstInfo.makeWH(decodeSize.width, decodeSize.height) :
        options.dstInfo;
    plan.pixelFormat = options.pixelFormat;
    plan.isRgb888Output = options.pixelFormat == PixelFormat::RGB_888;
    plan.byteCount = GetRgbOutputByteCount(plan.dstInfo, plan.isRgb888Output);
    return true;
}

uint32_t ProgressiveJpegDecoder::DecodeRgb(const JpegInputData &jpegData, const RgbDecodePlan &plan,
    uint8_t *dstPixels, size_t dstStride)
{
    CHECK_ERROR_RETURN_RET(jpegData.buffer == nullptr || jpegData.bufferSize == 0 || dstPixels == nullptr,
        ERR_IMAGE_DATA_UNSUPPORT);

    fast::image::RGBFormat colorFormat = fast::image::RGBFormat::RGBA8888;
    if (plan.pixelFormat == PixelFormat::RGB_888) {
        colorFormat = fast::image::RGBFormat::RGB888;
    } else if (plan.pixelFormat == PixelFormat::RGB_565) {
        colorFormat = fast::image::RGBFormat::RGB565;
    } else if (plan.pixelFormat == PixelFormat::BGRA_8888) {
        colorFormat = fast::image::RGBFormat::BGRA8888;
    }
    FASTManager& fastManager = FASTManager::GetInstance();
    if (!fastManager.IsInitialized()) {
        IMAGE_LOGE("FASTManager not initialized, fallback to software decode");
        return ERR_IMAGE_DATA_UNSUPPORT;
    }
    const fast::image::FastErrCode ret = fastManager.DecodeImage(jpegData.buffer, jpegData.bufferSize, dstPixels,
        static_cast<uint32_t>(plan.dstInfo.width()), static_cast<uint32_t>(plan.dstInfo.height()), dstStride,
        colorFormat);
    if (ret == fast::image::FastErrCode::OK) {
        IMAGE_LOGI("progressive jpeg decode success");
        return SUCCESS;
    }
    IMAGE_LOGE("progressive jpeg decode fallback, ret=%{public}d", static_cast<int32_t>(ret));
    return ERR_IMAGE_DATA_UNSUPPORT;
}

bool ProgressiveJpegDecoder::BuildYuvDecodePlan(const YuvDecodeOptions &options, YuvDecodePlan &plan)
{
#if !defined(CROSS_PLATFORM)
    if (options.codec == nullptr || options.supportRegion || !options.ifSourceCompleted ||
        options.hasSubset) {
        return false;
    }
    if (!IsYuvOutputFormatSupported(options.pixelFormat) ||
        options.codec->getEncodedFormat() != SkEncodedImageFormat::kJPEG) {
        return false;
    }
    if (!ResolveYuvDecodeSize(options.desiredSize, options.sourceSize, plan.size)) {
        return false;
    }
    if (!IsProgressiveJpegCodec(options.codec)) {
        return false;
    }
    plan.bufferSize = JpegDecoderYuv::GetYuvOutSize(static_cast<uint32_t>(plan.size.width),
        static_cast<uint32_t>(plan.size.height));
    return plan.bufferSize != 0;
#else
    return false;
#endif
}

uint32_t ProgressiveJpegDecoder::DecodeYuv(const JpegInputData &jpegData, const YuvDecodePlan &plan,
    DecodeContext &context)
{
    CHECK_ERROR_RETURN_RET(jpegData.buffer == nullptr || jpegData.bufferSize == 0, ERR_IMAGE_DATA_UNSUPPORT);
    YuvDecodeDestination dstImage = {};
    if (!BuildYuvDestination(context, plan.size, dstImage)) {
        IMAGE_LOGE("progressive jpeg yuv decode fallback, build destination failed");
        return ERR_IMAGE_DATA_UNSUPPORT;
    }
    FASTManager& fastManager = FASTManager::GetInstance();
    if (!fastManager.IsInitialized()) {
        IMAGE_LOGE("FASTManager not initialized, fallback to software decode");
        return ERR_IMAGE_DATA_UNSUPPORT;
    }
    const fast::image::FastErrCode ret = fastManager.DecodeImageYUV(jpegData.buffer, jpegData.bufferSize,
        dstImage.dstY, dstImage.dstUV, dstImage.width, dstImage.height, dstImage.yStride, dstImage.uvStride,
        dstImage.format);
    if (ret == fast::image::FastErrCode::OK) {
        context.outInfo.size = plan.size;
        IMAGE_LOGI("progressive jpeg yuv decode success");
        return SUCCESS;
    }
    IMAGE_LOGE("progressive jpeg yuv decode fallback, ret=%{public}d", static_cast<int32_t>(ret));
    return ERR_IMAGE_DATA_UNSUPPORT;
}

uint64_t ProgressiveJpegDecoder::GetRgbOutputByteCount(const SkImageInfo &imageInfo, bool isRgb888Format)
{
    if (isRgb888Format) {
        uint64_t width = static_cast<uint64_t>(imageInfo.width());
        uint64_t height = static_cast<uint64_t>(imageInfo.height());
        return width * height * NUM_3;
    }
    return imageInfo.computeMinByteSize();
}

uint64_t ProgressiveJpegDecoder::GetOutputRowStride(const SkImageInfo &imageInfo, const DecodeContext &context,
    const uint8_t *bufferForDecode)
{
    uint64_t rowStride = imageInfo.minRowBytes64();
#if !defined(CROSS_PLATFORM)
    if (bufferForDecode == static_cast<const uint8_t *>(context.pixelsBuffer.buffer) &&
        context.allocatorType == AllocatorType::DMA_ALLOC) {
        SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*> (context.pixelsBuffer.context);
        if (sbBuffer == nullptr) {
            IMAGE_LOGE("%{public}s: surface buffer is nullptr", __func__);
            return 0;
        }
        rowStride = static_cast<uint64_t>(sbBuffer->GetStride());
    }
#endif
    return rowStride;
}

void ProgressiveJpegDecoder::ResetDecodeContextPixelsBuffer(DecodeContext &context)
{
    context.freeFunc = nullptr;
    context.pixelsBuffer.buffer = nullptr;
    context.pixelsBuffer.bufferSize = 0;
    context.pixelsBuffer.context = nullptr;
}
} // namespace ImagePlugin
} // namespace OHOS
