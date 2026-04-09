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

#include "AvifDecoderImpl.h"

#include <cmath>
#include <dlfcn.h>
#include <sys/timerfd.h>
#include <sys/mman.h>
#include <sstream>
#include <limits>
#include "image_func_timer.h"
#include "image_system_properties.h"
#include "image_trace.h"
#include "image_utils.h"
#include "image_log.h"
#include "media_errors.h"
#include "securec.h"

#include "SkImageInfo.h"

#if !defined(CROSS_PLATFORM)
#include <sys/ioctl.h>
#include <linux/dma-buf.h>
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "AvifDecoderImpl"

namespace OHOS {
namespace ImagePlugin {
using namespace Media;

static constexpr int DEGREE_360 = 360;
static constexpr uint32_t MONO_BYTES = 1;
static constexpr uint32_t YUV420_BYTES = 2;
static constexpr uint32_t YUV444_BYTES = 3;
static constexpr uint32_t MAX_STREAM_LEN = 300 * 1024 * 1024;

#ifdef AVIF_DECODE_ENABLE
static constexpr int BITS_8 = 8;
static constexpr int BITS_10 = 10;
static constexpr uint32_t Y_PLANE_INDEX = 0;
static constexpr uint32_t U_PLANE_INDEX = 1;
static constexpr uint32_t V_PLANE_INDEX = 2;
static constexpr uint32_t Y_STRIDE_INDEX = 0;
static constexpr uint32_t U_STRIDE_INDEX = 1;
static constexpr uint32_t V_STRIDE_INDEX = 1;
static constexpr uint32_t MIN_GROUP_NUM = 1;
static constexpr uint32_t GROUP_DIVIDE_NUM = 2;
// To ensure synchronous calls
static constexpr int DEFAULT_THREAD_NUM = 1;
static constexpr uint32_t PRIMARY_IMAGE_INDEX = std::numeric_limits<uint32_t>::max();
static constexpr uint32_t DAV1D_SIZE_ALIGNMENT = 128;
static constexpr uint32_t MAX_IMAGE_SIZE = 20000;

static void Dav1dFreeCallback(const uint8_t* buf, void* cookie)
{
    // This data is owned by the decoder; nothing to free here
    (void)buf;
    (void)cookie;
}

static AVPixelFormat PixelFormatToAVPixelFormat(PixelFormat pixelFormat)
{
    const auto &formatMap = PixelConvertAdapter::FFMPEG_PIXEL_FORMAT_MAP;
    auto iter = formatMap.find(pixelFormat);
    return (iter != formatMap.end()) ? iter->second : AVPixelFormat::AV_PIX_FMT_NONE;
}

static AVPixelFormat Dav1dPictureToAVPixelFormat(const Dav1dPicture &pic)
{
    AVPixelFormat avFormat = AVPixelFormat::AV_PIX_FMT_NONE;
    if (pic.p.layout == Dav1dPixelLayout::DAV1D_PIXEL_LAYOUT_I420) {
        if (pic.p.bpc == BITS_8) {
            avFormat = AVPixelFormat::AV_PIX_FMT_YUV420P;
        } else if (pic.p.bpc == BITS_10) {
            avFormat = AVPixelFormat::AV_PIX_FMT_YUV420P10LE;
        }
    }
    return avFormat;
}

static AVPixelFormat HeifPixelFormatToAVPixelFormat(HeifPixelFormat format, int32_t bpc)
{
    static const std::map<std::pair<HeifPixelFormat, int32_t>, AVPixelFormat> formatMap = {
        {{HeifPixelFormat::YUV420, BITS_8}, AVPixelFormat::AV_PIX_FMT_YUV420P},
        {{HeifPixelFormat::YUV420, BITS_10}, AVPixelFormat::AV_PIX_FMT_YUV420P10LE},
    };
    auto resIt = formatMap.find(std::make_pair(format, bpc));
    return resIt == formatMap.end() ? AVPixelFormat::AV_PIX_FMT_NONE : resIt->second;
}

static int32_t AvifColorSpaceToFFmpegColorSpace(const Dav1dPicture &pic)
{
    int32_t defaultColorSpace = SWS_CS_ITU709;
    CHECK_ERROR_RETURN_RET_LOG(!pic.seq_hdr, defaultColorSpace, "%{public}s invalid Dav1dPicture header.", __func__);
    static const std::map<Dav1dColorPrimaries, int32_t> colorSpaceMap = {
        {Dav1dColorPrimaries::DAV1D_COLOR_PRI_BT709, SWS_CS_ITU709},
        {Dav1dColorPrimaries::DAV1D_COLOR_PRI_BT601, SWS_CS_ITU601},
        {Dav1dColorPrimaries::DAV1D_COLOR_PRI_SMPTE240, SWS_CS_SMPTE240M},
        {Dav1dColorPrimaries::DAV1D_COLOR_PRI_BT2020, SWS_CS_BT2020},
    };
    auto resIt = colorSpaceMap.find(pic.seq_hdr->pri);
    return resIt == colorSpaceMap.end() ? defaultColorSpace : resIt->second;
}

bool Dav1dDecoder::ConvertToRGB(SwsContext *ctx, Dav1dPicture &pic, ConvertInfo &info)
{
    uint8_t* srcY = reinterpret_cast<uint8_t*>((pic).data[Y_PLANE_INDEX]);
    uint8_t* srcU = reinterpret_cast<uint8_t*>((pic).data[U_PLANE_INDEX]);
    uint8_t* srcV = reinterpret_cast<uint8_t*>((pic).data[V_PLANE_INDEX]);
    uint8_t* srcData[] = { srcY, srcU, srcV };
    int32_t srcLinesize[] = { pic.stride[Y_STRIDE_INDEX], pic.stride[U_STRIDE_INDEX], pic.stride[V_STRIDE_INDEX] };

    uint8_t* dstData[] = { info.dstBuffer };
    int32_t dstLinesize[] = { info.rowStride };

    int ret = sws_scale(ctx, srcData, srcLinesize, 0, pic.p.h, dstData, dstLinesize);
    IMAGE_LOGD("%{public}s sws scale ret : %{public}d", __func__, ret);
    return ret == pic.p.h;
}

static bool SetColorConfig(SwsContext* ctx, const Dav1dPicture &pic)
{
    int32_t *srcColorTable = nullptr;
    int32_t *dstColorTable = nullptr;
    int32_t srcRange = 0;
    int32_t dstRange = 0;
    int32_t brightness = 0;
    int32_t contrast = 0;
    int32_t saturation = 0;
    int32_t ret = sws_getColorspaceDetails(ctx, &srcColorTable, &srcRange, &dstColorTable, &dstRange, &brightness,
        &contrast, &saturation);
    CHECK_ERROR_RETURN_RET_LOG(ret != 0, false, "sws_getColorspaceDetails failed.");
    int32_t srcColorSpace = AvifColorSpaceToFFmpegColorSpace(pic);
    srcRange = pic.seq_hdr->color_range == 0 ? 0 : 1;
    ret = sws_setColorspaceDetails(ctx, sws_getCoefficients(srcColorSpace), srcRange, dstColorTable, dstRange,
        brightness, contrast, saturation);
    IMAGE_LOGD("srcColorSpace %{public}d, srcRange %{public}d, dstRange %{public}d",
        srcColorSpace, srcRange, dstRange);
    return ret == 0;
}

bool Dav1dDecoder::ConvertWithFFmpeg(uint32_t index, ConvertInfo &info)
{
    auto pic = GetOccurDecodeFrame(index);
    CHECK_ERROR_RETURN_RET_LOG(!pic, false,
        "%{public}s failed, %{public}d has not been decoded.", __func__, index);
    AVPixelFormat srcFormat = Dav1dPictureToAVPixelFormat(*pic);
    CHECK_ERROR_RETURN_RET_LOG(srcFormat == AVPixelFormat::AV_PIX_FMT_NONE, false,
        "Dav1dPictureToAVPixelFormat failed.");

    AVPixelFormat dstFormat = PixelFormatToAVPixelFormat(info.desiredPixelFormat);
    CHECK_ERROR_RETURN_RET_LOG(dstFormat == AVPixelFormat::AV_PIX_FMT_NONE, false,
        "PixelFormatToAVPixelFormat failed.");

    SwsContext* ctx = sws_getContext(pic->p.w, pic->p.h, srcFormat,
        pic->p.w, pic->p.h, dstFormat, SWS_POINT, nullptr, nullptr, nullptr);
    CHECK_ERROR_RETURN_RET_LOG(!ctx, false, "SwsContext is nullptr.");

    CHECK_ERROR_RETURN_RET_LOG(!SetColorConfig(ctx, *pic), false, "SetColorConfig failed.");
    bool ret = ConvertToRGB(ctx, *pic, info);
    sws_freeContext(ctx);
    return ret;
}

bool Dav1dDecoder::CreateDecoder()
{
    if (ctx_) {
        return true;
    }
    IMAGE_LOGD("%{public}s IN.", __func__);
    dav1d_default_settings(&settings_);
    settings_.n_threads = DEFAULT_THREAD_NUM;
    return dav1d_open(&ctx_, &settings_) == 0;
}

void Dav1dDecoder::DeleteDecoder()
{
    CHECK_DEBUG_RETURN_LOG(!ctx_, "%{public}s decoder ctx is nullptr.", __func__);
    IMAGE_LOGD("DeleteDecoder in.");
    dav1d_close(&ctx_);
    ctx_ = nullptr;
}

void Dav1dDecoder::ClearPicMap()
{
    decltype(picMap_){}.swap(picMap_);
}

std::shared_ptr<Dav1dPicture> Dav1dDecoder::GetOccurDecodeFrame(uint32_t index)
{
    auto resIt = picMap_.find(index);
    return resIt != picMap_.end() ? resIt->second : nullptr;
}

bool Dav1dDecoder::DecodeFrame(uint32_t index, const std::vector<uint8_t> &frameData)
{
    Dav1dData data;
    int wrapRet = dav1d_data_wrap(&data, frameData.data(), frameData.size(), Dav1dFreeCallback, nullptr);
    CHECK_ERROR_RETURN_RET_LOG(wrapRet != 0, false,
        "%{public}s dav1d_data_wrap failed ret:%{public}d.", __func__, wrapRet);
    CHECK_ERROR_RETURN_RET_LOG(!ctx_, false, "ctx_ is nullptr.");
    int sendRet = dav1d_send_data(ctx_, &data);
    CHECK_ERROR_RETURN_RET_LOG(sendRet < 0, false,
        "%{public}s dav1d_send_data failed ret:%{public}d.", __func__, sendRet);
    std::unique_ptr<Dav1dPicture> pic = std::make_unique<Dav1dPicture>();
    CHECK_ERROR_RETURN_RET_LOG(!pic, false, "%{public}s new Dav1dPicture failed.", __func__);
    CHECK_ERROR_RETURN_RET_LOG(memset_s(pic.get(), sizeof(*pic), 0, sizeof(*pic)) != EOK, false,
        "%{public}s dav1d_data_wrap failed.", __func__);
    int getRet = dav1d_get_picture(ctx_, pic.get());
    CHECK_ERROR_RETURN_RET_LOG(getRet < 0, false,
        "%{public}s dav1d_get_picture failed. ret:%{public}d", __func__, getRet);

    IMAGE_LOGD("size(%{public}d, %{public}d) stride(%{public}zu, %{public}zu) layout(%{public}d) bpc(%{public}d)",
        pic->p.w, pic->p.h, static_cast<size_t>(pic->stride[Y_STRIDE_INDEX]),
        static_cast<size_t>(pic->stride[U_STRIDE_INDEX]), pic->p.layout, pic->p.bpc);

    auto picDeleter = [](Dav1dPicture *p) {
        if (p) {
            dav1d_picture_unref(p);
            delete p;
        }
    };
    picMap_[index] = std::shared_ptr<Dav1dPicture>(pic.release(), picDeleter);
    return true;
}
#endif

bool AvifDecoderImpl::init(HeifStream *stream, HeifFrameInfo *frameInfo)
{
    CHECK_ERROR_RETURN_RET_LOG(!frameInfo, false, "%{public}s frameInfo is nullptr.", __func__);
    size_t len = 0;
    bool copyRet = CopySrcMemory(stream, len);
    if (stream) {
        delete stream;
        stream = nullptr;
    }
    CHECK_ERROR_RETURN_RET(!copyRet, false);
    heif_error err = HeifParser::MakeFromMemory(srcMemory_.get(), len, false, &parser_);
    bool cond = (parser_ == nullptr || err != heif_error_ok);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "make heif parser failed, err: %{public}d.", err);
    primaryImage_ = parser_->GetPrimaryImage();
    CHECK_ERROR_RETURN_RET_LOG(!primaryImage_, false, "avif primary image is nullptr.");
    InitFrameInfo(&primaryImageInfo_, primaryImage_);
    animationImage_ = parser_->GetAnimationImage();
    if (animationImage_) {
        IMAGE_LOGD("%{public}s. image is avis.", __func__);
        InitFrameInfo(&animationImageInfo_, animationImage_);
    }
    *frameInfo = primaryImageInfo_;
    return true;
}

bool AvifDecoderImpl::getSequenceInfo(HeifFrameInfo *frameInfo, size_t *frameCount)
{
    CHECK_ERROR_RETURN_RET_LOG(!frameInfo || !frameCount, false,
        "%{public}s frameInfo or frameCount is nullptr.", __func__);
    CHECK_ERROR_RETURN_RET_LOG(!parser_, false, "%{public}s parser is nullptr.", __func__);
    CHECK_DEBUG_RETURN_RET_LOG(!parser_->IsAvisImage(), false, "%{public}s image is not avis.", __func__);
    *frameInfo = animationImageInfo_;
    uint32_t count = 0;
    auto ret = parser_->GetAvisFrameCount(count);
    CHECK_ERROR_RETURN_RET_LOG(ret != heif_error_ok, false,
        "%{public}s GetAvisFrameCount failed, errCode:%{public}d.", __func__, static_cast<uint32_t>(ret));
    *frameCount = static_cast<size_t>(count);
    return true;
}

bool AvifDecoderImpl::setOutputColor(SkHeifColorFormat heifColor)
{
    return false;
}

bool AvifDecoderImpl::decode(HeifFrameInfo *frameInfo)
{
#ifdef AVIF_DECODE_ENABLE
    (void)frameInfo;
    return DecodeFrame();
#else
    return false;
#endif
}

bool AvifDecoderImpl::decodeSequence(int frameIndex, HeifFrameInfo *frameInfo)
{
#ifdef AVIF_DECODE_ENABLE
    (void)frameInfo;
    CHECK_ERROR_RETURN_RET_LOG(frameIndex < 0, false, "frameIndex is less than zero.");
    CHECK_ERROR_RETURN_RET_LOG(!parser_, false, "parser is nullptr.");
    uint32_t frameCount = 0;
    auto ret = parser_->GetAvisFrameCount(frameCount);
    CHECK_ERROR_RETURN_RET_LOG(ret != heif_error_ok, false,
                               "GetAvisFrameCount failed, ret = %{public}d", ret);
    CHECK_ERROR_RETURN_RET_LOG(static_cast<uint32_t>(frameIndex) >= frameCount, false,
                               "frameIndex is greater than or equal to frameCount");
    return DecodeMovieFrame(frameIndex);
#else
    return false;
#endif
}

void AvifDecoderImpl::setDstBuffer(uint8_t *dstBuffer, size_t rowStride, void *context)
{
    dstMemory_ = dstBuffer;
    rowStride_ = rowStride;
    (void)context;
}

bool AvifDecoderImpl::getScanline(uint8_t *dst)
{
    (void)dst;
    return false;
}

size_t AvifDecoderImpl::skipScanlines(int count)
{
    (void)count;
    return 0;
}

bool AvifDecoderImpl::getImageInfo(HeifFrameInfo *frameInfo)
{
    CHECK_ERROR_RETURN_RET_LOG(!frameInfo, false, "%{public}s frameInfo is nullptr.", __func__);
    *frameInfo = primaryImageInfo_;
    return true;
}

bool AvifDecoderImpl::decodeGainmap()
{
    return false;
}

void AvifDecoderImpl::setGainmapDstBuffer(uint8_t *dstBuffer, size_t rowStride)
{
    return;
}

bool AvifDecoderImpl::getGainmapInfo(HeifFrameInfo *frameInfo)
{
    return false;
}

bool AvifDecoderImpl::getTmapInfo(HeifFrameInfo *frameInfo)
{
    return false;
}

HeifImageHdrType AvifDecoderImpl::getHdrType()
{
    return HeifImageHdrType::UNKNOWN;
}

void AvifDecoderImpl::getVividMetadata(std::vector<uint8_t> &uwaInfo, std::vector<uint8_t> &displayInfo,
    std::vector<uint8_t> &lightInfo)
{
    return;
}

void AvifDecoderImpl::getISOMetadata(std::vector<uint8_t> &isoMetadata)
{
    return;
}

void AvifDecoderImpl::getErrMsg(std::string &errMsg)
{
    return;
}

uint32_t AvifDecoderImpl::getColorDepth()
{
    return 0;
}

bool AvifDecoderImpl::IsAvisImage()
{
    CHECK_ERROR_RETURN_RET(!parser_, false);
    return parser_->IsAvisImage();
}

bool AvifDecoderImpl::IsSupportedPixelFormat(bool isAnimation, PixelFormat format)
{
    static const std::map<AvifBitDepth, std::unordered_set<PixelFormat>> BitDepthToPixelFormat = {
        {AvifBitDepth::Bit_8, {PixelFormat::NV21, PixelFormat::NV12, PixelFormat::RGB_565,
                               PixelFormat::RGBA_8888, PixelFormat::BGRA_8888}},
        {AvifBitDepth::Bit_10, {PixelFormat::RGBA_8888, PixelFormat::BGRA_8888,
                                PixelFormat::NV21, PixelFormat::NV12}},
    };
    auto layout = GetAvifPixelFormat(isAnimation);
    CHECK_ERROR_RETURN_RET_LOG(layout != HeifPixelFormat::YUV420, false,
        "%{public}s unsupported layout : %{public}d.", __func__, static_cast<int32_t>(layout));
    auto bitDepth = GetAvifBitDepth(isAnimation);
    auto it = BitDepthToPixelFormat.find(bitDepth);
    CHECK_ERROR_RETURN_RET_LOG(it == BitDepthToPixelFormat.end(), false,
        "%{public}s unsupported bit depth : %{public}d.", __func__, static_cast<int32_t>(bitDepth));
    return it->second.find(format) != it->second.end();
}

bool AvifDecoderImpl::CopySrcMemory(HeifStream *stream, size_t &len)
{
    CHECK_ERROR_RETURN_RET_LOG(!stream, false, "%{public}s stream is nullptr.", __func__);
    len = stream->getLength();
    CHECK_ERROR_RETURN_RET_LOG(len == 0 || len > MAX_STREAM_LEN, false, "%{public}s invalid stream size.", __func__);
    srcMemory_ = std::make_unique<uint8_t[]>(len);
    CHECK_ERROR_RETURN_RET_LOG(!srcMemory_, false, "%{public}s allocate src memory failed.", __func__);
    size_t actualLen = stream->read(srcMemory_.get(), len);
    CHECK_ERROR_RETURN_RET_LOG(actualLen != len, false, "%{public}s copy src memory failed.", __func__);
    return true;
}

void AvifDecoderImpl::InitFrameInfo(HeifFrameInfo *info, const std::shared_ptr<HeifImage> &image)
{
    CHECK_ERROR_RETURN_LOG(!info|| !image, "InitFrameInfo info or image is nullptr.");
    info->mWidth = image->GetOriginalWidth();
    info->mHeight = image->GetOriginalHeight();
    IMAGE_LOGW("%{public}s width : %{public}d, height : %{public}d", __func__, info->mWidth, info->mHeight);
    info->mRotationAngle = (DEGREE_360 - image->GetRotateDegrees()) % DEGREE_360;
    info->mBytesPerPixel = GetPixelBytes(image->GetDefaultPixelFormat());
    SetColorSpaceInfo(info, image);
}

void AvifDecoderImpl::SetColorSpaceInfo(HeifFrameInfo *info, const std::shared_ptr<HeifImage> &image)
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

uint32_t AvifDecoderImpl::GetPixelBytes(HeifPixelFormat format)
{
    switch (format) {
        case HeifPixelFormat::MONOCHROME:
            return MONO_BYTES;
        case HeifPixelFormat::YUV420:
        case HeifPixelFormat::YUV422:
            return YUV420_BYTES;
        case HeifPixelFormat::YUV444:
            return YUV444_BYTES;
        default:
            break;
    }
    return 0;
}

#ifdef AVIF_DECODE_ENABLE
bool AvifDecoderImpl::InitDecoder()
{
    if (decoder_) {
        return true;
    }
    decoder_ = std::make_unique<Dav1dDecoder>();
    CHECK_ERROR_RETURN_RET_LOG(!decoder_, false, "InitDecoder make failed.");
    return decoder_->CreateDecoder();
}

bool AvifDecoderImpl::DecodeFrame()
{
    CHECK_ERROR_RETURN_RET_LOG(!InitDecoder() || !decoder_, false, "%{public}s InitDecoder failed.", __func__);
    ConvertInfo info {
        .dstBuffer = dstMemory_,
        .dstBufferSize = dstMemorySize_,
        .desiredPixelFormat = desiredPixelFormat_,
        .rowStride = rowStride_ };
    if (!decoder_->GetOccurDecodeFrame(PRIMARY_IMAGE_INDEX)) {
        CHECK_ERROR_RETURN_RET(!parser_ || !primaryImage_, false);
        std::vector<uint8_t> data;
        auto ret = parser_->GetItemData(primaryImage_->GetItemId(), &data);
        CHECK_ERROR_RETURN_RET_LOG(ret != heif_error_ok, false,
            "decode get avif item data failed, ret = %{public}d.", ret);
        CHECK_ERROR_RETURN_RET(!decoder_->DecodeFrame(PRIMARY_IMAGE_INDEX, data), false);
    }
    return decoder_->ConvertWithFFmpeg(PRIMARY_IMAGE_INDEX, info);
}

bool AvifDecoderImpl::IsMemoryExceed(uint32_t groupNum)
{
    uint64_t groupMemorySize = 0;
    int32_t perPicMemorySize = 0;
    AVPixelFormat format = HeifPixelFormatToAVPixelFormat(GetAvifPixelFormat(true),
        static_cast<int32_t>(GetAvifBitDepth(true)));
    CHECK_ERROR_RETURN_RET_LOG(format == AVPixelFormat::AV_PIX_FMT_NONE, true,
        "%{public}s unsupport format.", __func__);
    CHECK_ERROR_RETURN_RET_LOG(animationImageInfo_.mWidth > MAX_IMAGE_SIZE ||
        animationImageInfo_.mHeight > MAX_IMAGE_SIZE, true,
        "%{public}s image size too large.", __func__);
    uint32_t w = FFALIGN(animationImageInfo_.mWidth, DAV1D_SIZE_ALIGNMENT);
    uint32_t h = FFALIGN(animationImageInfo_.mHeight, DAV1D_SIZE_ALIGNMENT);
    perPicMemorySize = av_image_get_buffer_size(format, w, h, DAV1D_PICTURE_ALIGNMENT);
    CHECK_ERROR_RETURN_RET_LOG(perPicMemorySize <= 0, true,
        "%{public}s av_image_get_buffer_size failed.", __func__);
    CHECK_DEBUG_RETURN_RET_LOG(ImageUtils::CheckMulOverflow<uint64_t>(groupNum, perPicMemorySize), true,
        "%{public}s group memory size is exceed.", __func__);
    groupMemorySize = groupNum * perPicMemorySize;
    return ImageUtils::HasOverflowed64(groupMemorySize, dstMemorySize_);
}

std::vector<std::vector<uint32_t>> AvifDecoderImpl::CalculateMiniGroup(uint32_t index, HeifsFrameGroup groupInfo)
{
    std::vector<std::vector<uint32_t>> result;
    uint32_t begin = groupInfo.beginFrameIndex;
    uint32_t end = groupInfo.endFrameIndex;
    CHECK_ERROR_RETURN_RET_LOG(begin >= end || index < begin || index >= end, result,
        "%{public}s Incorrect group information.", __func__);
    uint32_t groupNum = end - begin;
    while (IsMemoryExceed(groupNum)) {
        if (groupNum <= MIN_GROUP_NUM) {
            return result;
        }
        groupNum /= GROUP_DIVIDE_NUM;
    }
    for (uint32_t i = begin; i <= index; i += groupNum) {
        std::vector<uint32_t> tmp;
        for (uint32_t j = i; (j < groupNum + i) && j < end; j++) {
            tmp.emplace_back(j);
        }
        result.emplace_back(std::move(tmp));
    }
    return result;
}

bool AvifDecoderImpl::DecodeMovieFrame(uint32_t index)
{
    CHECK_ERROR_RETURN_RET_LOG(!InitDecoder() || !decoder_, false, "%{public}s InitDecoder failed.", __func__);
    ConvertInfo info {
        .dstBuffer = dstMemory_,
        .dstBufferSize = dstMemorySize_,
        .desiredPixelFormat = desiredPixelFormat_,
        .rowStride = rowStride_ };
    if (decoder_->GetOccurDecodeFrame(index)) {
        return decoder_->ConvertWithFFmpeg(index, info);
    }
    HeifsFrameGroup groupInfo;
    auto ret = parser_->GetHeifsGroupFrameInfo(index, groupInfo);
    CHECK_ERROR_RETURN_RET_LOG(ret != heif_error_ok, false,
                               "GetHeifsGroupFrameInfo failed, ret = %{public}d.", ret);
    auto group = CalculateMiniGroup(index, groupInfo);
    CHECK_ERROR_RETURN_RET_LOG(group.empty(), false, "%{public}s empty group.", __func__);
    for (const auto &miniGroup : group) {
        decoder_->ClearPicMap();
        for (const auto i : miniGroup) {
            std::vector<uint8_t> data;
            ret = parser_->GetAvisFrameData(i, data);
            CHECK_ERROR_RETURN_RET_LOG(ret != heif_error_ok, false,
                "GetAvisFrameData failed, ret = %{public}d.", ret);
            CHECK_ERROR_RETURN_RET(!decoder_->DecodeFrame(i, data), false);
        }
    }
    return decoder_->ConvertWithFFmpeg(index, info);
}
#endif

AvifBitDepth AvifDecoderImpl::GetAvifBitDepth(bool isAnimation)
{
    CHECK_ERROR_RETURN_RET_LOG(!parser_, AvifBitDepth::UNKNOWN, "parser is nullptr.");
    return parser_->GetAvifBitDepth(isAnimation);
}

HeifPixelFormat AvifDecoderImpl::GetAvifPixelFormat(bool isAnimation)
{
    if (isAnimation) {
        CHECK_ERROR_RETURN_RET_LOG(!animationImage_, HeifPixelFormat::UNDEFINED,
            "%{public}s no animationImage", __func__);
        return animationImage_->GetDefaultPixelFormat();
    } else {
        CHECK_ERROR_RETURN_RET_LOG(!primaryImage_, HeifPixelFormat::UNDEFINED,
            "%{public}s no primaryImage", __func__);
        return primaryImage_->GetDefaultPixelFormat();
    }
}

uint32_t AvifDecoderImpl::GetAvisDelayTime(uint32_t index, int32_t &value)
{
    CHECK_ERROR_RETURN_RET(!IsAvisImage(), ERR_MEDIA_FORMAT_UNSUPPORT);
    CHECK_ERROR_RETURN_RET(!parser_, ERR_MEDIA_INVALID_PARAM);
    auto ret = parser_->GetHeifsDelayTime(index, value);
    CHECK_ERROR_RETURN_RET_LOG(ret != heif_error_ok, ERR_MEDIA_INVALID_PARAM,
        "GetAvisDelayTime failed, ret : %{public}d", ret);
    return SUCCESS;
}

} // namespace ImagePlugin
} // namespace OHOS

HeifDecoder* CreateAvifDecoderImpl(void)
{
    return new OHOS::ImagePlugin::AvifDecoderImpl();
}
