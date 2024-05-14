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
#include "image_trace.h"
#include "image_utils.h"
#include "image_log.h"
#include "media_errors.h"

#ifdef HEIF_HW_DECODE_ENABLE
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

#ifdef HEIF_HW_DECODE_ENABLE
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
        IMAGE_LOGI("planeY offset: %{public}ld, columnStride: %{public}d, rowStride: %{public}d,"
                   " planeUV offset: %{public}ld, columnStride: %{public}d, rowStride: %{public}d",
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
#endif

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
    : inPixelFormat_(GRAPHIC_PIXEL_FMT_YCBCR_420_SP), outPixelFormat_(PixelFormat::RGBA_8888),
    tileWidth_(0), tileHeight_(0), colNum_(0), rowNum_(0),
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
    if (primaryImage_->GetLumaBitNum() == LUMA_10_BIT) {
        IMAGE_LOGI("heif image is in 10 bit");
        inPixelFormat_ = GRAPHIC_PIXEL_FMT_YCBCR_P010;
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
    GetTileSize(primaryImage_, tileWidth_, tileHeight_);
#ifdef HEIF_HW_DECODE_ENABLE
    if (gainmapImage_ != nullptr) {
        InitFrameInfo(&gainmapImageInfo_, gainmapImage_);
        GetTileSize(gainmapImage_, gainmapGridInfo_.tileWidth, gainmapGridInfo_.tileHeight);
        gainmapGridInfo_.displayWidth = gainmapImageInfo_.mWidth;
        gainmapGridInfo_.displayHeight = gainmapImageInfo_.mHeight;
    }
#endif
    SetRowColNum();
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

void HeifDecoderImpl::GetTileSize(const std::shared_ptr<HeifImage> &image, uint32_t &tileWidth, uint32_t &tileHeight)
{
    if (!image) {
        IMAGE_LOGE("GetTileSize image is null");
        return;
    }

    std::string imageType = parser_->GetItemType(image->GetItemId());
    if (imageType == "hvc1") {
        tileWidth = image->GetOriginalWidth();
        tileHeight = image->GetOriginalHeight();
        return;
    }
    if (imageType != "grid") {
        IMAGE_LOGE("GetTileSize unsupported image type: %{public}s", imageType.c_str());
        return;
    }
    std::vector<std::shared_ptr<HeifImage>> tileImages;
    parser_->GetTileImages(image->GetItemId(), tileImages);
    if (tileImages.empty()) {
        IMAGE_LOGE("grid image has no tile image");
        return;
    }
    tileWidth = tileImages[0]->GetOriginalWidth();
    tileHeight = tileImages[0]->GetOriginalHeight();
}

void HeifDecoderImpl::SetRowColNum()
{
    if (tileWidth_ != 0) {
        colNum_ = static_cast<size_t>(ceil((double)imageInfo_.mWidth / (double)tileWidth_));
    }
    if (tileHeight_ != 0) {
        rowNum_ = static_cast<size_t>(ceil((double)imageInfo_.mHeight / (double)tileHeight_));
    }
#ifdef HEIF_HW_DECODE_ENABLE
    if (gainmapImage_ != nullptr) {
        if (gainmapGridInfo_.tileWidth != 0) {
            gainmapGridInfo_.cols =
                static_cast<size_t>(ceil((double)gainmapImageInfo_.mWidth / (double)gainmapGridInfo_.tileWidth));
        }
        if (gainmapGridInfo_.tileHeight != 0) {
            gainmapGridInfo_.rows =
                static_cast<size_t>(ceil((double)gainmapImageInfo_.mHeight / (double)gainmapGridInfo_.tileHeight));
        }
    }
#endif
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
#ifdef HEIF_HW_DECODE_ENABLE
    ImageTrace trace("HeifDecoderImpl::decode");

    if (outPixelFormat_ == PixelFormat::UNKNOWN) {
        IMAGE_LOGE("unknown pixel type: %{public}d", outPixelFormat_);
        return false;
    }

    if (!primaryImage_) {
        return false;
    }

    if (hwDecoder_ == nullptr) {
        hwDecoder_ = std::make_shared<HeifHardwareDecoder>();
        if (hwDecoder_ == nullptr) {
            IMAGE_LOGE("decode make HeifHardwareDecoder failed");
            return false;
        }
    }

    sptr<SurfaceBuffer> hwBuffer
        = IsDirectYUVDecode() ? sptr<SurfaceBuffer>(dstHwBuffer_) :
                hwDecoder_->AllocateOutputBuffer(imageInfo_.mWidth, imageInfo_.mHeight, inPixelFormat_);
    if (IsDirectYUVDecode()) {
        inPixelFormat_ = static_cast<GraphicPixelFormat>(hwBuffer->GetFormat());
    }
    if (hwBuffer == nullptr) {
        IMAGE_LOGE("decode AllocateOutputBuffer return null");
        return false;
    }

    std::string imageType = parser_->GetItemType(primaryImage_->GetItemId());
    bool res = false;
    IMAGE_LOGI("HeifDecoderImpl::decode width: %{public}d, height: %{public}d,"
               " imageType: %{public}s, inPixelFormat: %{public}d",
               imageInfo_.mWidth, imageInfo_.mHeight, imageType.c_str(), inPixelFormat_);
    if (imageType == "grid") {
        res = DecodeGrids(hwBuffer);
    } else if (imageType == "hvc1") {
        res = DecodeSingleImage(primaryImage_, hwBuffer);
    }
    return res;
#else
    return false;
#endif
}

bool HeifDecoderImpl::decodeGainmap()
{
#ifdef HEIF_HW_DECODE_ENABLE
    ImageTrace trace("HeifDecoderImpl::decodeGainmap");

    if (outPixelFormat_ == PixelFormat::UNKNOWN) {
        IMAGE_LOGE("unknown pixel type: %{public}d", outPixelFormat_);
        return false;
    }

    if (!gainmapImage_) {
        return false;
    }

    if (hwGainmapDecoder_ == nullptr) {
        hwGainmapDecoder_ = std::make_shared<HeifHardwareDecoder>();
        if (hwGainmapDecoder_ == nullptr) {
            IMAGE_LOGE("decode make HeifHardwareDecoder failed");
            return false;
        }
    }
    sptr<SurfaceBuffer> hwBuffer
        = hwGainmapDecoder_->AllocateOutputBuffer(gainmapImageInfo_.mWidth, gainmapImageInfo_.mHeight, inPixelFormat_);
    if (IsDirectYUVDecode()) {
        inPixelFormat_ = static_cast<GraphicPixelFormat>(hwBuffer->GetFormat());
    }
    if (hwBuffer == nullptr) {
        IMAGE_LOGE("decode AllocateOutputBuffer return null");
        return false;
    }

    std::string imageType = parser_->GetItemType(gainmapImage_->GetItemId());
    bool res = false;
    IMAGE_LOGI("HeifDecoderImpl::decodeGainmap width: %{public}d, height: %{public}d,"
               " imageType: %{public}s, inPixelFormat: %{public}d",
               gainmapImageInfo_.mWidth, gainmapImageInfo_.mHeight, imageType.c_str(), inPixelFormat_);
    if (imageType == "grid") {
        gainmapGridInfo_.enableGrid = true;
        res = DecodeGrids(hwBuffer, true);
    } else if (imageType == "hvc1") {
        gainmapGridInfo_.enableGrid = false;
        res = DecodeSingleImage(gainmapImage_, hwBuffer, true);
    }
    return res;
#else
    return false;
#endif
}


bool HeifDecoderImpl::DecodeGrids(sptr<SurfaceBuffer> &hwBuffer, bool isGainmap)
{
#ifdef HEIF_HW_DECODE_ENABLE
    std::vector<std::shared_ptr<HeifImage>> tileImages;
    std::shared_ptr<HeifImage> decodeImage = isGainmap ? gainmapImage_ : primaryImage_;
    parser_->GetTileImages(decodeImage->GetItemId(), tileImages);
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

    GridInfo gridInfo = {imageInfo_.mWidth, imageInfo_.mHeight, true, colNum_, rowNum_, tileWidth_, tileHeight_};
    if (isGainmap) {
        gridInfo = gainmapGridInfo_;
    }
    uint32_t err;
    if (isGainmap) {
        err = hwGainmapDecoder_->DoDecode(gridInfo, inputs, hwBuffer);
    } else {
        err = hwDecoder_->DoDecode(gridInfo, inputs, hwBuffer);
    }
    if (err != SUCCESS) {
        IMAGE_LOGE("heif hw decoder return error: %{public}d, width: %{public}d, height: %{public}d,"
                   " imageType: grid, inPixelFormat: %{public}d, colNum: %{public}d, rowNum: %{public}d,"
                   " tileWidth: %{public}d, tileHeight: %{public}d, hvccLen: %{public}zu",
                   err, gridInfo.displayWidth, gridInfo.displayHeight, inPixelFormat_, gridInfo.cols, gridInfo.rows,
                   gridInfo.tileWidth, gridInfo.tileHeight, inputs[0].size());
        SetHardwareDecodeErrMsg(gridInfo.tileWidth, gridInfo.tileHeight);
        return false;
    }
    return IsDirectYUVDecode() || ConvertHwBufferPixelFormat(hwBuffer, isGainmap);
#else
    return false;
#endif
}

bool HeifDecoderImpl::DecodeSingleImage(std::shared_ptr<HeifImage> &image, sptr<SurfaceBuffer> &hwBuffer,
    bool isGainmap)
{
#ifdef HEIF_HW_DECODE_ENABLE
    if (image == nullptr) {
        IMAGE_LOGI("HeifDecoderImpl::DecodeSingleImage image is nullptr");
        return false;
    }
    std::vector<std::vector<uint8_t>> inputs(GRID_NUM_2);

    parser_->GetItemData(image->GetItemId(), &inputs[0], heif_only_header);
    ProcessChunkHead(inputs[0].data(), inputs[0].size());

    parser_->GetItemData(image->GetItemId(), &inputs[1], heif_no_header);
    ProcessChunkHead(inputs[1].data(), inputs[1].size());

    GridInfo gridInfo = {imageInfo_.mWidth, imageInfo_.mHeight, false, colNum_, rowNum_, tileWidth_, tileHeight_};
    if (isGainmap) {
        gridInfo = gainmapGridInfo_;
    }
    uint32_t err;
    if (isGainmap) {
        err = hwGainmapDecoder_->DoDecode(gridInfo, inputs, hwBuffer);
    } else {
        err = hwDecoder_->DoDecode(gridInfo, inputs, hwBuffer);
    }
    if (err != SUCCESS) {
        IMAGE_LOGE("heif hw decoder return error: %{public}d, width: %{public}d, height: %{public}d,"
                   " imageType: hvc1, inPixelFormat: %{public}d, colNum: %{public}d, rowNum: %{public}d,"
                   " tileWidth: %{public}d, tileHeight: %{public}d, hvccLen: %{public}zu, dataLen: %{public}zu",
                   err, gridInfo.displayWidth, gridInfo.displayHeight, inPixelFormat_, gridInfo.cols, gridInfo.rows,
                   gridInfo.tileWidth, gridInfo.tileHeight, inputs[0].size(), inputs[1].size());
        SetHardwareDecodeErrMsg(gridInfo.tileWidth, gridInfo.tileHeight);
        return false;
    }
    return IsDirectYUVDecode() || ConvertHwBufferPixelFormat(hwBuffer, isGainmap);
#else
    return false;
#endif
}

bool HeifDecoderImpl::ConvertHwBufferPixelFormat(sptr<SurfaceBuffer> &hwBuffer, bool isGainmap)
{
#ifdef HEIF_HW_DECODE_ENABLE
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

    HeifFrameInfo info = imageInfo_;
    uint8_t* dst = dstMemory_;
    size_t rowStride = dstRowStride_;
    if (isGainmap) {
        info = gainmapImageInfo_;
        dst = gainmapDstMemory_;
        rowStride = gainmapDstRowStride_;
    }
    PixelFormatConvertParam srcParam = {static_cast<uint8_t *>(hwBuffer->GetVirAddr()),
                                        info.mWidth, info.mHeight,
                                        static_cast<uint32_t>(hwBuffer->GetStride()),
                                        srcBufferPlanesInfo,
                                        GraphicPixFmt2AvPixFmtForYuv(inPixelFormat_)};
    PixelFormatConvertParam dstParam = {dst, info.mWidth, info.mHeight,
                                        static_cast<uint32_t>(rowStride),
                                        dstBufferPlanesInfo,
                                        PixFmt2AvPixFmtForOutput(outPixelFormat_)};
    return ConvertPixelFormat(srcParam, dstParam);
#else
    return false;
#endif
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

HeifDecoder* CreateHeifDecoderImpl()
{
#ifdef HEIF_HW_DECODE_ENABLE
    return new OHOS::ImagePlugin::HeifDecoderImpl();
#else
    return nullptr;
#endif
}
