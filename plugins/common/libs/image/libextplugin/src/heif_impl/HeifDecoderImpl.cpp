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

#include "HeifDecoderImpl.h"

#ifdef HEIF_HW_DECODE_ENABLE
#include "image_trace.h"
#include "image_utils.h"
#include "image_log.h"
#include "media_errors.h"

#include "hardware/heif_hw_decoder.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "libswscale/swscale.h"
#include "libavutil/imgutils.h"
#include "libavcodec/avcodec.h"
#ifdef __cplusplus
}
#endif

#include <cmath>
#include <sstream>

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "HeifDecoderImpl"

namespace OHOS {
namespace ImagePlugin {
using namespace Media;

const static int LUMA_10_BIT = 10;
const static int DEGREE_360 = 360;
const static int CHUNK_HEAD_OFFSET_1 = 1;
const static int CHUNK_HEAD_OFFSET_2 = 2;
const static int CHUNK_HEAD_OFFSET_3 = 3;
const static int CHUNK_HEAD_SHIFT_8 = 8;
const static int CHUNK_HEAD_SHIFT_16 = 16;
const static int CHUNK_HEAD_SHIFT_24 = 24;
const static int CHUNK_HEAD_SIZE = 4;
const static int PIXEL_OFFSET_0 = 0;
const static int PIXEL_OFFSET_1 = 1;
const static int PIXEL_OFFSET_2 = 2;
const static int PIXEL_OFFSET_3 = 3;
const static int PIXEL_SIZE_4 = 4;
const static int MAX_ALPHA = 255;

const static int GRID_NUM_2 = 2;
const static uint32_t PLANE_COUNT_TWO = 2;

struct PixelFormatConvertParam {
    uint8_t *data;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    OH_NativeBuffer_Planes *planesInfo;
    AVPixelFormat format;
};

static bool FillFrameInfoForPixelConvert(AVFrame *frame, PixelFormatConvertParam &param)
{
    if (param.format == AV_PIX_FMT_NV12 || param.format == AV_PIX_FMT_NV21 || param.format == AV_PIX_FMT_P010) {
        if (param.planesInfo == nullptr || param.planesInfo->planeCount < PLANE_COUNT_TWO) {
            IMAGE_LOGE("planesInfo is invalid for yuv buffer");
            return false;
        }
        const OH_NativeBuffer_Plane &planeY = param.planesInfo->planes[0];
        const OH_NativeBuffer_Plane &planeUV = param.planesInfo->planes[param.format == AV_PIX_FMT_NV21 ? 2 : 1];
        IMAGE_LOGI("planeY offset: %{public}llu, columnStride: %{public}u, rowStride: %{public}u,"
                   " planeUV offset: %{public}llu, columnStride: %{public}u, rowStride: %{public}u",
                   planeY.offset, planeY.columnStride, planeY.rowStride,
                   planeUV.offset, planeUV.columnStride, planeUV.rowStride);
        frame->data[0] = param.data + planeY.offset;
        frame->data[1] = param.data + planeUV.offset;
        frame->linesize[0] = static_cast<int>(planeY.columnStride);
        frame->linesize[1] = static_cast<int>(planeUV.columnStride);
    } else {
        IMAGE_LOGI("rgb stride: %{public}d", param.stride);
        frame->data[0] = param.data;
        frame->linesize[0] = static_cast<int>(param.stride);
    }
    return true;
}

static bool ConvertPixelFormat(PixelFormatConvertParam &srcParam, PixelFormatConvertParam &dstParam)
{
    ImageTrace trace("ConvertPixelFormat %d %d", srcParam.format, dstParam.format);
    IMAGE_LOGI("ConvertPixelFormat %{public}d %{public}d", srcParam.format, dstParam.format);
    bool res = false;
    AVFrame *srcFrame = av_frame_alloc();
    AVFrame *dstFrame = av_frame_alloc();
    SwsContext *ctx = sws_getContext(static_cast<int>(srcParam.width), static_cast<int>(srcParam.height),
                                     srcParam.format,
                                     static_cast<int>(dstParam.width), static_cast<int>(dstParam.height),
                                     dstParam.format,
                                     SWS_BICUBIC, nullptr, nullptr, nullptr);
    if (srcFrame != nullptr && dstFrame != nullptr && ctx != nullptr) {
        res = FillFrameInfoForPixelConvert(srcFrame, srcParam)
                && FillFrameInfoForPixelConvert(dstFrame, dstParam)
                && sws_scale(ctx, srcFrame->data, srcFrame->linesize, 0,
                             static_cast<int>(srcParam.height), dstFrame->data, dstFrame->linesize);
    }

    av_frame_free(&srcFrame);
    av_frame_free(&dstFrame);
    sws_freeContext(ctx);
    return res;
}

static AVPixelFormat GraphicPixFmt2AvPixFmtForYuv(GraphicPixelFormat pixelFormat)
{
    AVPixelFormat res = AV_PIX_FMT_NV12;
    switch (pixelFormat) {
        case GRAPHIC_PIXEL_FMT_YCBCR_420_SP:
            res = AV_PIX_FMT_NV12;
            break;
        case GRAPHIC_PIXEL_FMT_YCRCB_420_SP:
            res = AV_PIX_FMT_NV21;
            break;
        case GRAPHIC_PIXEL_FMT_YCBCR_P010:
            res = AV_PIX_FMT_P010;
            break;
        default:
            break;
    }
    return res;
}

static AVPixelFormat PixFmt2AvPixFmtForOutput(PixelFormat pixelFormat)
{
    AVPixelFormat res = AV_PIX_FMT_RGBA;
    switch (pixelFormat) {
        case PixelFormat::RGBA_8888:
            res = AV_PIX_FMT_RGBA;
            break;
        case PixelFormat::BGRA_8888:
            res = AV_PIX_FMT_BGRA;
            break;
        case PixelFormat::RGB_565:
            res = AV_PIX_FMT_RGB565;
            break;
        case PixelFormat::NV12:
            res = AV_PIX_FMT_NV12;
            break;
        case PixelFormat::NV21:
            res = AV_PIX_FMT_NV21;
            break;
        default:
            break;
    }
    return res;
}

static PixelFormat SkHeifColorFormat2PixelFormat(SkHeifColorFormat format)
{
    PixelFormat res = PixelFormat::UNKNOWN;
    switch (format) {
        case kHeifColorFormat_RGB565:
            res = PixelFormat::RGB_565;
            break;
        case kHeifColorFormat_RGBA_8888:
            res = PixelFormat::RGBA_8888;
            break;
        case kHeifColorFormat_BGRA_8888:
            res = PixelFormat::BGRA_8888;
            break;
        case kHeifColorFormat_NV12:
            res = PixelFormat::NV12;
            break;
        case kHeifColorFormat_NV21:
            res = PixelFormat::NV21;
            break;
        default:
            IMAGE_LOGE("Unsupported dst pixel format: %{public}d", format);
            break;
    }
    return res;
}

HeifDecoderImpl::HeifDecoderImpl()
    : outPixelFormat_(PixelFormat::RGBA_8888),
    dstMemory_(nullptr), dstRowStride_(0), dstHwBuffer_(nullptr),
    gainmapDstMemory_(nullptr), gainmapDstRowStride_(0) {}

HeifDecoderImpl::~HeifDecoderImpl()
{
    if (srcMemory_ != nullptr) {
        delete[] srcMemory_;
    }
}

bool HeifDecoderImpl::init(HeifStream *stream, HeifFrameInfo *frameInfo)
{
    ImageTrace trace("HeifDecoderImpl::init");
    if (stream == nullptr) {
        return false;
    }

    size_t fileLength = stream->getLength();
    if (srcMemory_ == nullptr) {
        if (fileLength == 0) {
            IMAGE_LOGE("file size is 0");
            return false;
        }
        srcMemory_ = new uint8_t[fileLength];
        if (srcMemory_ == nullptr) {
            return false;
        }
        stream->read(srcMemory_, fileLength);
    }

    heif_error err = HeifParser::MakeFromMemory(srcMemory_, fileLength, false, &parser_);
    if (parser_ == nullptr || err != heif_error_ok) {
        IMAGE_LOGE("make heif parser failed, err: %{public}d", err);
        return false;
    }
    primaryImage_ = parser_->GetPrimaryImage();
    if (primaryImage_ == nullptr) {
        IMAGE_LOGE("heif primary image is null");
        return false;
    }
    gainmapImage_ = parser_->GetGainmapImage();
    std::shared_ptr<HeifImage> tmapImage = parser_->GetTmapImage();
    if (tmapImage != nullptr) {
        InitFrameInfo(&tmapInfo_, tmapImage);
    }
    return Reinit(frameInfo);
}

bool HeifDecoderImpl::Reinit(HeifFrameInfo *frameInfo)
{
    InitFrameInfo(&imageInfo_, primaryImage_);
    InitGridInfo(primaryImage_, gridInfo_);
    if (gainmapImage_ != nullptr) {
        InitFrameInfo(&gainmapImageInfo_, gainmapImage_);
        InitGridInfo(gainmapImage_, gainmapGridInfo_);
    }
    if (frameInfo != nullptr) {
        *frameInfo = imageInfo_;
    }
    return true;
}

void HeifDecoderImpl::InitFrameInfo(HeifFrameInfo *info, const std::shared_ptr<HeifImage> &image)
{
    if (info == nullptr || image == nullptr) {
        IMAGE_LOGE("InitFrameInfo info or image is null");
        return;
    }
    info->mWidth = image->GetOriginalWidth();
    info->mHeight = image->GetOriginalHeight();
    info->mRotationAngle = (DEGREE_360 - image->GetRotateDegrees()) % DEGREE_360;
    info->mBytesPerPixel = static_cast<uint32_t>(ImageUtils::GetPixelBytes(outPixelFormat_));
    info->mDurationUs = 0;
    SetColorSpaceInfo(info, image);
    if (info->mIccData.empty() && !info->hasNclxColor && (parser_->GetItemType(image->GetItemId())== "grid")) {
        std::vector<std::shared_ptr<HeifImage>> tileImages;
        parser_->GetTileImages(image->GetItemId(), tileImages);
        if (!tileImages.empty()) {
            SetColorSpaceInfo(info, tileImages[0]);
        }
    }
}

void HeifDecoderImpl::SetColorSpaceInfo(HeifFrameInfo* info, const std::shared_ptr<HeifImage>& image)
{
    auto &iccProfile = image->GetRawColorProfile();
    size_t iccSize = iccProfile != nullptr ? iccProfile->GetData().size() : 0;
    if (iccSize > 0) {
        auto iccProfileData = iccProfile->GetData().data();
        info->mIccData.assign(iccProfileData, iccProfileData + iccSize);
    } else {
        info->mIccData.clear();
    }
    auto& nclx = image->GetNclxColorProfile();
    if (nclx != nullptr) {
        info->hasNclxColor = true;
        info->nclxColor.colorPrimaries = nclx->GetColorPrimaries();
        info->nclxColor.transferCharacteristics = nclx->GetTransferCharacteristics();
        info->nclxColor.matrixCoefficients = nclx->GetMatrixCoefficients();
        info->nclxColor.fullRangeFlag = nclx->GetFullRangeFlag();
    } else {
        info->hasNclxColor = false;
    }
}

void HeifDecoderImpl::InitGridInfo(const std::shared_ptr<HeifImage> &image, GridInfo &gridInfo)
{
    if (!image) {
        IMAGE_LOGE("InitGridInfo image is null");
        return;
    }
    gridInfo.displayWidth = image->GetOriginalWidth();
    gridInfo.displayHeight = image->GetOriginalHeight();
    GetTileSize(image, gridInfo);
    GetRowColNum(gridInfo);
}

void HeifDecoderImpl::GetTileSize(const std::shared_ptr<HeifImage> &image, GridInfo &gridInfo)
{
    if (!image) {
        IMAGE_LOGE("GetTileSize image is null");
        return;
    }

    std::string imageType = parser_->GetItemType(image->GetItemId());
    if (imageType == "hvc1") {
        gridInfo.tileWidth = image->GetOriginalWidth();
        gridInfo.tileHeight = image->GetOriginalHeight();
        return;
    }
    if (imageType == "iden") {
        std::shared_ptr<HeifImage> idenImage;
        parser_->GetIdenImage(image->GetItemId(), idenImage);
        if (idenImage != nullptr && idenImage != image) {
            GetTileSize(idenImage, gridInfo);
        }
        return;
    }
    if (imageType != "grid") {
        IMAGE_LOGE("GetTileSize unsupported image type: %{public}s", imageType.c_str());
        return;
    }
    std::vector<std::shared_ptr<HeifImage>> tileImages;
    parser_->GetTileImages(image->GetItemId(), tileImages);
    if (tileImages.empty() || tileImages[0] == nullptr) {
        IMAGE_LOGE("grid image has no tile image");
        return;
    }
    gridInfo.tileWidth = tileImages[0]->GetOriginalWidth();
    gridInfo.tileHeight = tileImages[0]->GetOriginalHeight();
}

void HeifDecoderImpl::GetRowColNum(GridInfo &gridInfo)
{
    if (gridInfo.tileWidth != 0) {
        gridInfo.cols = static_cast<size_t>(ceil((double)gridInfo.displayWidth / (double)gridInfo.tileWidth));
    }
    if (gridInfo.tileHeight != 0) {
        gridInfo.rows = static_cast<size_t>(ceil((double)gridInfo.displayHeight / (double)gridInfo.tileHeight));
    }
}

GraphicPixelFormat HeifDecoderImpl::GetInPixelFormat(const std::shared_ptr<HeifImage> &image)
{
    return (image != nullptr && image->GetLumaBitNum() == LUMA_10_BIT) ?
            GRAPHIC_PIXEL_FMT_YCBCR_P010 : GRAPHIC_PIXEL_FMT_YCBCR_420_SP;
}

bool HeifDecoderImpl::getSequenceInfo(HeifFrameInfo *frameInfo, size_t *frameCount)
{
    // unimplemented
    return false;
}

bool HeifDecoderImpl::setOutputColor(SkHeifColorFormat heifColor)
{
    outPixelFormat_ = SkHeifColorFormat2PixelFormat(heifColor);
    imageInfo_.mBytesPerPixel = static_cast<uint32_t>(ImageUtils::GetPixelBytes(outPixelFormat_));
    return outPixelFormat_ != PixelFormat::UNKNOWN;
}

bool HeifDecoderImpl::decode(HeifFrameInfo *frameInfo)
{
    ImageTrace trace("HeifDecoderImpl::decode");

    sptr<SurfaceBuffer> hwBuffer;
    std::shared_ptr<HeifHardwareDecoder> hwDecoder = std::make_shared<HeifHardwareDecoder>();
    if (hwDecoder == nullptr) {
        IMAGE_LOGE("decode make HeifHardwareDecoder failed");
        return false;
    }

    bool decodeRes = DecodeImage(hwDecoder, primaryImage_, gridInfo_, &hwBuffer, true);
    if (!decodeRes) {
        return false;
    }

    bool convertRes = IsDirectYUVDecode() ||
            ConvertHwBufferPixelFormat(hwBuffer, gridInfo_, dstMemory_, dstRowStride_);
    if (!convertRes) {
        return false;
    }
    ApplyAlphaImage(primaryImage_, dstMemory_, dstRowStride_);
    return true;
}

bool HeifDecoderImpl::decodeGainmap()
{
    ImageTrace trace("HeifDecoderImpl::decodeGainmap");
    sptr<SurfaceBuffer> hwBuffer;
    std::shared_ptr<HeifHardwareDecoder> hwDecoder = std::make_shared<HeifHardwareDecoder>();
    if (hwDecoder == nullptr) {
        IMAGE_LOGE("decodeGainmap make HeifHardwareDecoder failed");
        return false;
    }

    bool decodeRes = DecodeImage(hwDecoder, gainmapImage_, gainmapGridInfo_, &hwBuffer, false);
    if (!decodeRes) {
        return false;
    }

    bool convertRes = IsDirectYUVDecode() ||
            ConvertHwBufferPixelFormat(hwBuffer, gainmapGridInfo_, gainmapDstMemory_, gainmapDstRowStride_);
    if (!convertRes) {
        return false;
    }
    return true;
}

bool HeifDecoderImpl::DecodeImage(std::shared_ptr<HeifHardwareDecoder> &hwDecoder,
                                  std::shared_ptr<HeifImage> &image, GridInfo &gridInfo,
                                  sptr<SurfaceBuffer> *outBuffer, bool isPrimary)
{
    if (outPixelFormat_ == PixelFormat::UNKNOWN) {
        IMAGE_LOGE("unknown pixel type: %{public}d", outPixelFormat_);
        return false;
    }

    if (hwDecoder == nullptr || image == nullptr || outBuffer == nullptr) {
        return false;
    }

    std::string imageType = parser_->GetItemType(image->GetItemId());
    if (imageType == "iden") {
        return DecodeIdenImage(hwDecoder, image, gridInfo, outBuffer, isPrimary);
    }

    GraphicPixelFormat inPixelFormat = GetInPixelFormat(image);
    sptr<SurfaceBuffer> hwBuffer =
            isPrimary && IsDirectYUVDecode() ? sptr<SurfaceBuffer>(dstHwBuffer_) :
            hwDecoder->AllocateOutputBuffer(gridInfo.displayWidth, gridInfo.displayHeight, inPixelFormat);
    if (IsDirectYUVDecode()) {
        inPixelFormat = static_cast<GraphicPixelFormat>(hwBuffer->GetFormat());
    }
    if (hwBuffer == nullptr) {
        IMAGE_LOGE("decode AllocateOutputBuffer return null");
        return false;
    }

    bool res = false;
    IMAGE_LOGI("HeifDecoderImpl::DecodeImage width: %{public}d, height: %{public}d,"
               " imageType: %{public}s, inPixelFormat: %{public}d",
               gridInfo.displayWidth, gridInfo.displayHeight, imageType.c_str(), inPixelFormat);
    if (imageType == "grid") {
        gridInfo.enableGrid = true;
        res = DecodeGrids(hwDecoder, image, gridInfo, hwBuffer);
    } else if (imageType == "hvc1") {
        gridInfo.enableGrid = false;
        res = DecodeSingleImage(hwDecoder, image, gridInfo, hwBuffer);
    }
    if (!res) {
        return false;
    }
    *outBuffer = hwBuffer;
    return true;
}

bool HeifDecoderImpl::DecodeGrids(std::shared_ptr<HeifHardwareDecoder> &hwDecoder, std::shared_ptr<HeifImage> &image,
                                  GridInfo &gridInfo, sptr<SurfaceBuffer> &hwBuffer)
{
    std::vector<std::shared_ptr<HeifImage>> tileImages;
    parser_->GetTileImages(image->GetItemId(), tileImages);
    if (tileImages.empty()) {
        IMAGE_LOGE("grid image has no tile image");
        return false;
    }
    size_t numGrid = tileImages.size();
    std::vector<std::vector<uint8_t>> inputs(numGrid + 1);

    for (size_t index = 0; index < numGrid; ++index) {
        std::shared_ptr<HeifImage> &tileImage = tileImages[index];
        if (index == 0) {
            // get hvcc header
            parser_->GetItemData(tileImage->GetItemId(), &inputs[index], heif_only_header);
            ProcessChunkHead(inputs[index].data(), inputs[index].size());
        }
        parser_->GetItemData(tileImage->GetItemId(), &inputs[index + 1], heif_no_header);
        ProcessChunkHead(inputs[index + 1].data(), inputs[index + 1].size());
    }

    uint32_t err = hwDecoder->DoDecode(gridInfo, inputs, hwBuffer);
    if (err != SUCCESS) {
        IMAGE_LOGE("heif hw decoder return error: %{public}d, width: %{public}d, height: %{public}d,"
                   " imageType: grid, inPixelFormat: %{public}d, colNum: %{public}d, rowNum: %{public}d,"
                   " tileWidth: %{public}d, tileHeight: %{public}d, hvccLen: %{public}zu",
                   err, gridInfo.displayWidth, gridInfo.displayHeight,
                   hwBuffer->GetFormat(), gridInfo.cols, gridInfo.rows,
                   gridInfo.tileWidth, gridInfo.tileHeight, inputs[0].size());
        SetHardwareDecodeErrMsg(gridInfo.tileWidth, gridInfo.tileHeight);
        return false;
    }
    return true;
}

bool HeifDecoderImpl::DecodeIdenImage(std::shared_ptr<HeifHardwareDecoder> &hwDecoder,
                                      std::shared_ptr<HeifImage> &image, GridInfo &gridInfo,
                                      sptr<SurfaceBuffer> *outBuffer, bool isPrimary)
{
    if (!image) {
        return false;
    }
    std::shared_ptr<HeifImage> idenImage;
    parser_->GetIdenImage(image->GetItemId(), idenImage);
    if (idenImage == nullptr || idenImage == image) {
        IMAGE_LOGE("invalid iden image");
        return false;
    }
    return DecodeImage(hwDecoder, idenImage, gridInfo, outBuffer, isPrimary);
}

bool HeifDecoderImpl::DecodeSingleImage(std::shared_ptr<HeifHardwareDecoder> &hwDecoder,
                                        std::shared_ptr<HeifImage> &image,
                                        GridInfo &gridInfo, sptr<SurfaceBuffer> &hwBuffer)
{
    if (image == nullptr) {
        IMAGE_LOGI("HeifDecoderImpl::DecodeSingleImage image is nullptr");
        return false;
    }
    std::vector<std::vector<uint8_t>> inputs(GRID_NUM_2);

    parser_->GetItemData(image->GetItemId(), &inputs[0], heif_only_header);
    ProcessChunkHead(inputs[0].data(), inputs[0].size());

    parser_->GetItemData(image->GetItemId(), &inputs[1], heif_no_header);
    ProcessChunkHead(inputs[1].data(), inputs[1].size());

    uint32_t err = hwDecoder->DoDecode(gridInfo, inputs, hwBuffer);
    if (err != SUCCESS) {
        IMAGE_LOGE("heif hw decoder return error: %{public}d, width: %{public}d, height: %{public}d,"
                   " imageType: hvc1, inPixelFormat: %{public}d, colNum: %{public}d, rowNum: %{public}d,"
                   " tileWidth: %{public}d, tileHeight: %{public}d, hvccLen: %{public}zu, dataLen: %{public}zu",
                   err, gridInfo.displayWidth, gridInfo.displayHeight,
                   hwBuffer->GetFormat(), gridInfo.cols, gridInfo.rows,
                   gridInfo.tileWidth, gridInfo.tileHeight, inputs[0].size(), inputs[1].size());
        SetHardwareDecodeErrMsg(gridInfo.tileWidth, gridInfo.tileHeight);
        return false;
    }
    return true;
}

static bool IsEmptyBuffer(uint8_t *buffer, uint32_t width, uint32_t height, uint32_t bpp, uint32_t rowStride)
{
    if (buffer == nullptr) {
        return true;
    }
    uint8_t *bufferRowStart = buffer;
    uint32_t rowBytes = width * bpp;
    for (uint32_t row = 0; row < height; ++row) {
        for (uint32_t col = 0; col < rowBytes; ++col) {
            if (bufferRowStart[col] != 0) {
                return false;
            }
        }
        bufferRowStart += rowStride;
    }
    return true;
}

bool HeifDecoderImpl::ApplyAlphaImage(std::shared_ptr<HeifImage> &masterImage, uint8_t *dstMemory, size_t dstRowStride)
{
    // check alpha image is available
    if (masterImage == nullptr || IsDirectYUVDecode()) {
        return false;
    }
    std::shared_ptr<HeifImage> alphaImage = masterImage->GetAlphaImage();
    if (alphaImage == nullptr || alphaImage == masterImage) {
        return false;
    }
    if (alphaImage->GetOriginalWidth() != masterImage->GetOriginalWidth() ||
        alphaImage->GetOriginalHeight() != masterImage->GetOriginalHeight() ||
        alphaImage->GetLumaBitNum() == LUMA_10_BIT ||
        (outPixelFormat_ != PixelFormat::RGBA_8888 && outPixelFormat_ != PixelFormat::BGRA_8888)) {
        return false;
    }

    // decode alpha image
    ImageTrace trace("HeifDecoderImpl::ApplyAlphaImage");
    GridInfo alphaGridInfo;
    sptr<SurfaceBuffer> hwBuffer;
    InitGridInfo(alphaImage, alphaGridInfo);
    std::shared_ptr<HeifHardwareDecoder> hwDecoder = std::make_shared<HeifHardwareDecoder>();
    if (hwDecoder == nullptr) {
        IMAGE_LOGE("ApplyAlphaImage make HeifHardwareDecoder failed");
        return false;
    }
    bool decodeRes = DecodeImage(hwDecoder, alphaImage, alphaGridInfo, &hwBuffer, false);
    if (!decodeRes) {
        IMAGE_LOGE("decode alpha image failed");
        return false;
    }

    // merge alpha channel
    uint8_t *alphaRowStart = static_cast<uint8_t*>(hwBuffer->GetVirAddr());
    uint8_t *dstRowStart = dstMemory;
    uint32_t width = masterImage->GetOriginalWidth();
    uint32_t height = masterImage->GetOriginalHeight();
    if (IsEmptyBuffer(reinterpret_cast<uint8_t*>(hwBuffer->GetVirAddr()), width, height, 1, hwBuffer->GetStride())) {
        return false;
    }

    for (uint32_t row = 0; row < height; ++row) {
        uint8_t *dstPixel = dstRowStart;
        for (uint32_t col = 0; col < width; ++col) {
            uint32_t alphaVal = static_cast<uint32_t>(alphaRowStart[col]);
            dstPixel[PIXEL_OFFSET_0] = static_cast<uint8_t>(alphaVal * dstPixel[PIXEL_OFFSET_0] / MAX_ALPHA);
            dstPixel[PIXEL_OFFSET_1] = static_cast<uint8_t>(alphaVal * dstPixel[PIXEL_OFFSET_1] / MAX_ALPHA);
            dstPixel[PIXEL_OFFSET_2] = static_cast<uint8_t>(alphaVal * dstPixel[PIXEL_OFFSET_2] / MAX_ALPHA);
            dstPixel[PIXEL_OFFSET_3] = static_cast<uint8_t>(alphaVal);
            dstPixel += PIXEL_SIZE_4;
        }
        alphaRowStart += hwBuffer->GetStride();
        dstRowStart += dstRowStride;
    }
    return true;
}

bool HeifDecoderImpl::ConvertHwBufferPixelFormat(sptr<SurfaceBuffer> &hwBuffer, GridInfo &gridInfo,
                                                 uint8_t *dstMemory, size_t dstRowStride)
{
    OH_NativeBuffer_Planes *srcBufferPlanesInfo = nullptr;
    hwBuffer->GetPlanesInfo((void **)&srcBufferPlanesInfo);
    if (srcBufferPlanesInfo == nullptr) {
        IMAGE_LOGE("find to get src buffer planes info");
        return false;
    }

    OH_NativeBuffer_Planes *dstBufferPlanesInfo = nullptr;
    if (dstHwBuffer_ != nullptr) {
        dstHwBuffer_->GetPlanesInfo((void **)&dstBufferPlanesInfo);
        if (dstBufferPlanesInfo == nullptr) {
            IMAGE_LOGE("fail to get dst buffer planes info");
            return false;
        }
    }

    PixelFormatConvertParam srcParam = {static_cast<uint8_t *>(hwBuffer->GetVirAddr()),
                                        gridInfo.displayWidth, gridInfo.displayHeight,
                                        static_cast<uint32_t>(hwBuffer->GetStride()),
                                        srcBufferPlanesInfo,
                                        GraphicPixFmt2AvPixFmtForYuv(
                                            static_cast<GraphicPixelFormat>(hwBuffer->GetFormat()))};
    PixelFormatConvertParam dstParam = {dstMemory, gridInfo.displayWidth, gridInfo.displayHeight,
                                        static_cast<uint32_t>(dstRowStride),
                                        dstBufferPlanesInfo,
                                        PixFmt2AvPixFmtForOutput(outPixelFormat_)};
    return ConvertPixelFormat(srcParam, dstParam);
}

bool HeifDecoderImpl::ProcessChunkHead(uint8_t *data, size_t len)
{
    if (len < CHUNK_HEAD_SIZE) {
        return false;
    }
    size_t index = 0;
    while (index < len - CHUNK_HEAD_SIZE) {
        size_t chunkLen = (data[index] << CHUNK_HEAD_SHIFT_24)
                | (data[index + CHUNK_HEAD_OFFSET_1] << CHUNK_HEAD_SHIFT_16)
                | (data[index + CHUNK_HEAD_OFFSET_2] << CHUNK_HEAD_SHIFT_8)
                | (data[index + CHUNK_HEAD_OFFSET_3]);
        data[index] = 0;
        data[index + CHUNK_HEAD_OFFSET_1] = 0;
        data[index + CHUNK_HEAD_OFFSET_2] = 0;
        data[index + CHUNK_HEAD_OFFSET_3] = 1;
        index += (chunkLen + CHUNK_HEAD_SIZE);
    }
    return true;
}

bool HeifDecoderImpl::IsDirectYUVDecode()
{
    return dstHwBuffer_ != nullptr && primaryImage_->GetLumaBitNum() != LUMA_10_BIT;
}

bool HeifDecoderImpl::decodeSequence(int frameIndex, HeifFrameInfo *frameInfo)
{
    // unimplemented
    return false;
}

void HeifDecoderImpl::setDstBuffer(uint8_t *dstBuffer, size_t rowStride, void *context)
{
    if (dstMemory_ == nullptr) {
        dstMemory_ = dstBuffer;
        dstRowStride_ = rowStride;
    }
    dstHwBuffer_ = reinterpret_cast<SurfaceBuffer*>(context);
}

void HeifDecoderImpl::setGainmapDstBuffer(uint8_t* dstBuffer, size_t rowStride)
{
    if (gainmapDstMemory_ == nullptr) {
        gainmapDstMemory_ = dstBuffer;
        gainmapDstRowStride_ = rowStride;
    }
}

bool HeifDecoderImpl::getScanline(uint8_t *dst)
{
    // no need to implement
    return true;
}

size_t HeifDecoderImpl::skipScanlines(int count)
{
    // no need to implement
    return true;
}

bool HeifDecoderImpl::getImageInfo(HeifFrameInfo *frameInfo)
{
    if (frameInfo != nullptr) {
        *frameInfo = imageInfo_;
    }
    return true;
}

bool HeifDecoderImpl::getGainmapInfo(HeifFrameInfo* frameInfo)
{
    if (frameInfo != nullptr) {
        *frameInfo = gainmapImageInfo_;
    }
    return true;
}

bool HeifDecoderImpl::getTmapInfo(HeifFrameInfo* frameInfo)
{
    if (frameInfo != nullptr) {
        *frameInfo = tmapInfo_;
    }
    return true;
}

HeifImageHdrType HeifDecoderImpl::getHdrType()
{
    std::vector<uint8_t> uwaInfo = primaryImage_->GetUWAInfo();
    if (primaryImage_->GetLumaBitNum() == LUMA_10_BIT) {
        return uwaInfo.empty() ? HeifImageHdrType::UNKNOWN : HeifImageHdrType::VIVID_SINGLE;
    }
    if (gainmapImage_ != nullptr) {
        return uwaInfo.empty() ? HeifImageHdrType::ISO_DUAL : HeifImageHdrType::VIVID_DUAL;
    }
    return HeifImageHdrType::UNKNOWN;
}

void HeifDecoderImpl::getVividMetadata(std::vector<uint8_t>& uwaInfo, std::vector<uint8_t>& displayInfo,
    std::vector<uint8_t>& lightInfo)
{
    uwaInfo = primaryImage_->GetUWAInfo();
    displayInfo = primaryImage_->GetDisplayInfo();
    lightInfo = primaryImage_->GetLightInfo();
}

void HeifDecoderImpl::getISOMetadata(std::vector<uint8_t>& isoMetadata)
{
    isoMetadata = primaryImage_->GetISOMetadata();
}

void HeifDecoderImpl::getErrMsg(std::string& errMsg)
{
    errMsg = errMsg_;
}

void HeifDecoderImpl::SetHardwareDecodeErrMsg(const uint32_t width, const uint32_t height)
{
    std::stringstream sstream;
    sstream << "HEIF Hardware Decode Failed, Width: ";
    sstream << width;
    sstream << ", Height: ";
    sstream << height;
    errMsg_ = sstream.str();
}
} // namespace ImagePlugin
} // namespace OHOS
#endif

HeifDecoder* CreateHeifDecoderImpl()
{
#ifdef HEIF_HW_DECODE_ENABLE
    return new OHOS::ImagePlugin::HeifDecoderImpl();
#else
    return nullptr;
#endif
}
