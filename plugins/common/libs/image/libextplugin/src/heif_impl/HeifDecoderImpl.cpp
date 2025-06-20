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
#include <dlfcn.h>
#include <sys/timerfd.h>
#include <sys/mman.h>
#include "image_fwk_ext_manager.h"
#include "image_func_timer.h"
#include "image_system_properties.h"
#include "image_trace.h"
#include "image_utils.h"
#include "image_log.h"
#include "media_errors.h"
#include "metadata_convertor.h"
#include "v1_0/buffer_handle_meta_key_type.h"
#include "vpe_utils.h"
#include "iremote_object.h"
#include "iproxy_broker.h"
#include "color_utils.h"

#include "heif_impl/hevc_sw_decode_param.h"

#include <cmath>
#include <sstream>

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "HeifDecoderImpl"

namespace OHOS {
namespace ImagePlugin {
using namespace Media;

using namespace OHOS::HDI::Display::Graphic::Common::V1_0;
const static int LUMA_8_BIT = 8;
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
const static uint32_t HEIF_HARDWARE_TILE_MIN_DIM = 128;
const static uint32_t HEIF_HARDWARE_TILE_MAX_DIM = 4096;
const static uint32_t HEIF_HARDWARE_DISPLAY_MIN_DIM = 128;
const static int IMAGE_ID = 123;

const static uint16_t BT2020_PRIMARIES = 9;
const static std::string HEIF_SHAREMEM_NAME = "HeifRawData";

const std::map<AuxiliaryPictureType, std::string> HEIF_AUXTTYPE_ID_MAP = {
    {AuxiliaryPictureType::GAINMAP, HEIF_AUXTTYPE_ID_GAINMAP},
    {AuxiliaryPictureType::DEPTH_MAP, HEIF_AUXTTYPE_ID_DEPTH_MAP},
    {AuxiliaryPictureType::UNREFOCUS_MAP, HEIF_AUXTTYPE_ID_UNREFOCUS_MAP},
    {AuxiliaryPictureType::LINEAR_MAP, HEIF_AUXTTYPE_ID_LINEAR_MAP},
    {AuxiliaryPictureType::FRAGMENT_MAP, HEIF_AUXTTYPE_ID_FRAGMENT_MAP}
};

static std::mutex g_codecMtxDecode;
static sptr<OHOS::HDI::Codec::Image::V2_1::ICodecImage> g_codecMgrDecode;
class HeifDecodeDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    void OnRemoteDied(const wptr<OHOS::IRemoteObject>& object) override
    {
        IMAGE_LOGW("codec_image_service died");
        std::lock_guard<std::mutex> lk(g_codecMtxDecode);
        g_codecMgrDecode = nullptr;
    }
};

static sptr<OHOS::HDI::Codec::Image::V2_1::ICodecImage> GetCodecManager()
{
    std::lock_guard<std::mutex> lk(g_codecMtxDecode);
    if (g_codecMgrDecode) {
        return g_codecMgrDecode;
    }
    IMAGE_LOGI("need to get ICodecImage");
    g_codecMgrDecode = OHOS::HDI::Codec::Image::V2_1::ICodecImage::Get();
    bool cond = g_codecMgrDecode == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "ICodecImage get failed");
    bool isDeathRecipientAdded = false;
    const sptr<OHOS::IRemoteObject> &remote =
        OHOS::HDI::hdi_objcast<OHOS::HDI::Codec::Image::V2_1::ICodecImage>(g_codecMgrDecode);
    if (remote) {
        sptr<HeifDecodeDeathRecipient> deathCallBack(new HeifDecodeDeathRecipient());
        isDeathRecipientAdded = remote->AddDeathRecipient(deathCallBack);
    }
    if (!isDeathRecipientAdded) {
        IMAGE_LOGI("failed to add deathRecipient for ICodecImage!");
    }
    return g_codecMgrDecode;
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
        case kHeifColorFormat_RGBA_1010102:
            res = PixelFormat::RGBA_1010102;
            break;
        case kHeifColorFormat_P010_NV12:
            res = PixelFormat::YCBCR_P010;
            break;
        case kHeifColorFormat_P010_NV21:
            res = PixelFormat::YCRCB_P010;
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
    gainmapDstMemory_(nullptr), gainmapDstRowStride_(0),
    auxiliaryDstMemory_(nullptr), auxiliaryDstRowStride_(0),
    auxiliaryDstMemorySize_(0), isAuxiliaryDecode_(false),
    auxiliaryDstHwBuffer_(nullptr), gainMapDstHwBuffer_(nullptr) {}

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
    if (stream != nullptr) {
        delete stream;
        stream = nullptr;
    }

    heif_error err = HeifParser::MakeFromMemory(srcMemory_, fileLength, false, &parser_);
    bool cond = (parser_ == nullptr || err != heif_error_ok);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "make heif parser failed, err: %{public}d", err);
    primaryImage_ = parser_->GetPrimaryImage();
    cond = (primaryImage_ == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "heif primary image is null");
    gainmapImage_ = parser_->GetGainmapImage();
    std::shared_ptr<HeifImage> tmapImage = parser_->GetTmapImage();
    if (tmapImage != nullptr) {
        InitFrameInfo(&tmapInfo_, tmapImage);
    }
    return Reinit(frameInfo);
}

GridInfo HeifDecoderImpl::GetGridInfo()
{
    return gridInfo_;
}

bool HeifDecoderImpl::CheckAuxiliaryMap(AuxiliaryPictureType type)
{
    if (parser_ == nullptr) {
        IMAGE_LOGE("Heif parser is nullptr.");
        return false;
    }

    auto iter = HEIF_AUXTTYPE_ID_MAP.find(type);
    switch (type) {
        case AuxiliaryPictureType::GAINMAP:
            auxiliaryImage_ = parser_->GetGainmapImage();
            break;
        case AuxiliaryPictureType::DEPTH_MAP:
        case AuxiliaryPictureType::UNREFOCUS_MAP:
        case AuxiliaryPictureType::LINEAR_MAP:
        case AuxiliaryPictureType::FRAGMENT_MAP:
            auxiliaryImage_ = parser_->GetAuxiliaryMapImage(iter->second);
            break;
        default:
            auxiliaryImage_ = nullptr;
            IMAGE_LOGE("Invalid AuxiliaryPictureType: %{public}d", type);
            break;
    }

    if (auxiliaryImage_ == nullptr) {
        IMAGE_LOGE("Auxiliary map type that does not exist");
        return false;
    }

    return true;
}

bool HeifDecoderImpl::setAuxiliaryMap(AuxiliaryPictureType type)
{
    bool cond = auxiliaryImage_ == nullptr && !CheckAuxiliaryMap(type);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "make heif parser failed");

    InitFrameInfo(&auxiliaryImageInfo_, auxiliaryImage_);
    InitGridInfo(auxiliaryImage_, auxiliaryGridInfo_);
    return true;
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
    std::string imageType = parser_->GetItemType(image->GetItemId());
    if (imageType == "iovl") {
        std::vector<std::shared_ptr<HeifImage>> iovlImages;
        parser_->GetIovlImages(image->GetItemId(), iovlImages);
        if (iovlImages.empty() || iovlImages[0] == nullptr) {
            IMAGE_LOGE("grid image has no tile image");
            return;
        }
        info->mWidth = iovlImages[0]->GetOriginalWidth();
        info->mHeight = iovlImages[0]->GetOriginalHeight();
    } else {
        info->mWidth = image->GetOriginalWidth();
        info->mHeight = image->GetOriginalHeight();
    }
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
    std::string imageType = parser_->GetItemType(image->GetItemId());
    if (imageType == "iovl") {
        std::vector<std::shared_ptr<HeifImage>> iovlImages;
        parser_->GetIovlImages(image->GetItemId(), iovlImages);
        if (iovlImages.empty() || iovlImages[0] == nullptr) {
            IMAGE_LOGE("grid image has no tile image");
            return;
        }
        gridInfo.displayWidth = iovlImages[0]->GetOriginalWidth();
        gridInfo.displayHeight = iovlImages[0]->GetOriginalHeight();
    } else {
        gridInfo.displayWidth = image->GetOriginalWidth();
        gridInfo.displayHeight = image->GetOriginalHeight();
    }

    gridInfo.colorRangeFlag = image->GetColorRangeFlag();
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
    if (imageType == "hvc1" || image->IsMovieImage()) {
        gridInfo.tileWidth = image->GetOriginalWidth();
        gridInfo.tileHeight = image->GetOriginalHeight();
        return;
    }
    if (imageType == "iovl") {
        std::vector<std::shared_ptr<HeifImage>> iovlImages;
        parser_->GetIovlImages(image->GetItemId(), iovlImages);
        if (iovlImages.empty() || iovlImages[0] == nullptr) {
            IMAGE_LOGE("grid image has no tile image");
            return;
        }
        gridInfo.tileWidth = iovlImages[0]->GetOriginalWidth();
        gridInfo.tileHeight = iovlImages[0]->GetOriginalHeight();
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

bool HeifDecoderImpl::copyToAshmem(std::vector<std::vector<uint8_t>> &inputs, std::vector<sptr<Ashmem>> &hwInputs)
{
    ImageTrace trace("HeifDecoderImpl::copyToAshmem, total size: %d", inputs.size());
    hwInputs.clear();
    hwInputs.reserve(inputs.size());
    for (auto& input : inputs) {
        size_t size = input.size();
        sptr<Ashmem> mem = Ashmem::CreateAshmem(HEIF_SHAREMEM_NAME.c_str(), size);
        if (!mem->MapAshmem(PROT_READ | PROT_WRITE)) {
            IMAGE_LOGE("Ashmem map failed");
            return false;
        }
        if (mem == nullptr) {
            IMAGE_LOGE("AshmemCreate failed");
            hwInputs.clear();
            return false;
        }
        if (!mem->WriteToAshmem(input.data(), size, 0)) {
            IMAGE_LOGE("memcpy_s failed with error");
            hwInputs.clear();
            return false;
        }
        hwInputs.push_back(mem);
    }
    return true;
}

GSError HeifDecoderImpl::HwSetColorSpaceData(sptr<SurfaceBuffer>& buffer, GridInfo &gridInfo)
{
    if (buffer == nullptr) {
        IMAGE_LOGE("HwSetColorSpaceData buffer is nullptr");
        return GSERROR_NO_BUFFER;
    }
    if (isGainmapDecode_ || isAuxiliaryDecode_) {
        GetGainmapColorSpace(colorSpaceName_);
    }
    auto colorSpaceSearch = ColorUtils::COLORSPACE_NAME_TO_COLORINFO_MAP.find(colorSpaceName_);
    CM_ColorSpaceInfo colorSpaceInfo =
        (colorSpaceSearch != ColorUtils::COLORSPACE_NAME_TO_COLORINFO_MAP.end()) ? colorSpaceSearch->second :
        CM_ColorSpaceInfo {COLORPRIMARIES_BT601_P, TRANSFUNC_BT709, MATRIX_BT601_P, RANGE_LIMITED};
    if (colorSpaceName_ == ColorManager::ColorSpaceName::NONE &&
        gridInfo.colorRangeFlag == 1) {
        colorSpaceInfo = CM_ColorSpaceInfo {COLORPRIMARIES_BT601_P, TRANSFUNC_BT709, MATRIX_BT601_P, RANGE_FULL};
    }
    std::vector<uint8_t> colorSpaceInfoVec;
    auto ret = MetadataManager::ConvertMetadataToVec(colorSpaceInfo, colorSpaceInfoVec);
    if (ret != GSERROR_OK) {
        return ret;
    }
    IMAGE_LOGI("ColorSpace, ColorPrimaries:%{public}d, TransFunc:%{public}d, Matrix:%{public}d, Range:%{public}d",
        colorSpaceInfo.primaries, colorSpaceInfo.transfunc,
        colorSpaceInfo.matrix, colorSpaceInfo.range);
    return buffer->SetMetadata(ATTRKEY_COLORSPACE_INFO, colorSpaceInfoVec);
}

static bool IsSupportHardwareDecode(const GridInfo &gridInfo)
{
    if (!ImageSystemProperties::GetHeifHardwareDecodeEnabled()) {
        return false;
    }
    return gridInfo.tileWidth >= HEIF_HARDWARE_TILE_MIN_DIM &&
           gridInfo.tileHeight >= HEIF_HARDWARE_TILE_MIN_DIM &&
           gridInfo.tileWidth <= HEIF_HARDWARE_TILE_MAX_DIM &&
           gridInfo.tileHeight <= HEIF_HARDWARE_TILE_MAX_DIM &&
           gridInfo.displayWidth >= HEIF_HARDWARE_DISPLAY_MIN_DIM &&
           gridInfo.displayHeight >= HEIF_HARDWARE_DISPLAY_MIN_DIM;
}

bool HeifDecoderImpl::decode(HeifFrameInfo *frameInfo)
{
    ImageTrace trace("HeifDecoderImpl::decode");
    if (!IsSupportHardwareDecode(gridInfo_)) {
        return SwDecode();
    }
    sptr<SurfaceBuffer> hwBuffer;
    IMAGE_LOGD("decode sapmpleSize:%{public}d", sampleSize_);
    bool decodeSuccess = HwDecodeImage(primaryImage_, gridInfo_, &hwBuffer, true);
    if (decodeSuccess) {
        ImageUtils::DumpDataIfDumpEnabled(reinterpret_cast<const char *>(hwBuffer->GetVirAddr()),
            hwBuffer->GetSize(), "heif_hardware_decode", IMAGE_ID);
    } else if (sampleSize_ != DEFAULT_SCALE_SIZE) {
        return false;
    } else {
        return SwDecode();
    }

    bool hwApplyAlphaImageRes = HwApplyAlphaImage(primaryImage_, dstMemory_, dstRowStride_);
    if (!hwApplyAlphaImageRes && sampleSize_ == DEFAULT_SAMPLE_SIZE) {
        SwApplyAlphaImage(primaryImage_, dstMemory_, dstRowStride_);
    }
    if (hwBuffer && (hwBuffer->GetUsage() & BUFFER_USAGE_MEM_MMZ_CACHE)) {
        GSError err = hwBuffer->InvalidateCache();
        if (err != GSERROR_OK) {
            IMAGE_LOGE("InvalidateCache failed, GSError=%{public}d", err);
        }
    }
    return true;
}

bool HeifDecoderImpl::SwDecode(bool isSharedMemory)
{
    HevcSoftDecodeParam param {
            gridInfo_, Media::PixelFormat::UNKNOWN, outPixelFormat_,
            dstMemory_, 0,
            static_cast<uint32_t>(dstRowStride_), dstHwBuffer_,
            isSharedMemory, nullptr, 0
    };
    bool decodeRes = SwDecodeImage(primaryImage_, param, gridInfo_, true);
    if (!decodeRes) {
        return false;
    }
    SwApplyAlphaImage(primaryImage_, dstMemory_, dstRowStride_);
    if (dstHwBuffer_ && (dstHwBuffer_->GetUsage() & BUFFER_USAGE_MEM_MMZ_CACHE)) {
        GSError err = dstHwBuffer_->Map();
        if (err != GSERROR_OK) {
            IMAGE_LOGE("SurfaceBuffer Map failed, GSError=%{public}d", err);
            return true;
        }
        err = dstHwBuffer_->FlushCache();
        if (err != GSERROR_OK) {
            IMAGE_LOGE("FlushCache failed, GSError=%{public}d", err);
        }
    }
    return true;
}

bool HeifDecoderImpl::DoDecodeAuxiliaryImage(std::shared_ptr<HeifImage> &auxiliaryImage, GridInfo &auxiliaryGridInfo,
                                             uint8_t *auxiliaryDstMemory, size_t auxiliaryDstRowStride)
{
    sptr<SurfaceBuffer> hwBuffer;
    bool decodeRes = HwDecodeImage(auxiliaryImage, auxiliaryGridInfo, &hwBuffer, false);
    if (!decodeRes && sampleSize_ != DEFAULT_SCALE_SIZE) {
        return false;
    }
    if (!decodeRes) {
        sptr<SurfaceBuffer> swHwBuffer;
        bool swdecodeRes = SwDecodeAuxiliaryImage(auxiliaryImage, auxiliaryGridInfo, &swHwBuffer);
        if (!swdecodeRes) {
            IMAGE_LOGE("HeifDecoderImpl::SwDecodeAuxiliaryImage failed too");
            return false;
        }
        return true;
    }
    return true;
}

bool HeifDecoderImpl::decodeGainmap()
{
    ImageTrace trace("HeifDecoderImpl::decodeGainmap");
    return DoDecodeAuxiliaryImage(gainmapImage_, gainmapGridInfo_, gainmapDstMemory_, gainmapDstRowStride_);
}

bool HeifDecoderImpl::decodeAuxiliaryMap()
{
    ImageTrace trace("HeifDecoderImpl::decodeAuxiliaryMap");
    if (auxiliaryImage_ != nullptr && parser_ != nullptr &&
        parser_->GetItemType(auxiliaryImage_->GetItemId()) == "mime") {
        return HwDecodeMimeImage(auxiliaryImage_);
    }
    return DoDecodeAuxiliaryImage(auxiliaryImage_, auxiliaryGridInfo_, auxiliaryDstMemory_, auxiliaryDstRowStride_);
}

void HeifDecoderImpl::AllocateHwOutputBuffer(sptr<SurfaceBuffer> &hwBuffer, bool isPrimary)
{
    //hardware decode buffer.
    if (isPrimary) {
        hwBuffer = sptr<SurfaceBuffer>(dstHwBuffer_);
    } else if (isGainmapDecode_) {
        hwBuffer = sptr<SurfaceBuffer>(gainMapDstHwbuffer_);
    } else if (isAuxiliaryDecode_) {
        hwBuffer = sptr<SurfaceBuffer>(auxiliaryDstHwbuffer_);
    }
}

bool HeifDecoderImpl::HwDecodeImage(std::shared_ptr<HeifImage> &image, GridInfo &gridInfo,
    sptr<SurfaceBuffer> *outBuffer, bool isPrimary)
{
    bool cond = (outPixelFormat_ == PixelFormat::UNKNOWN);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "unknown pixel type: %{public}d", outPixelFormat_);

    cond = (image == nullptr || outBuffer == nullptr);
    CHECK_ERROR_RETURN_RET(cond, false);

    std::string imageType = parser_->GetItemType(image->GetItemId());
    if (imageType == "iden") {
        bool res = HwDecodeIdenImage(image, gridInfo, outBuffer, isPrimary);
        return res;
    }

    GraphicPixelFormat inPixelFormat = GetInPixelFormat(image);
    sptr<SurfaceBuffer> hwBuffer;
    AllocateHwOutputBuffer(hwBuffer, isPrimary);
    if (hwBuffer == nullptr) {
        IMAGE_LOGE("decode AllocateOutputBuffer return null");
        return false;
    }
    if (IsDirectYUVDecode()) {
        inPixelFormat = static_cast<GraphicPixelFormat>(hwBuffer->GetFormat());
    }
    GraphicPixelFormat inPixelFormat = static_cast<GraphicPixelFormat>(hwBuffer->GetFormat());
    bool res = false;
    IMAGE_LOGI("HeifDecoderImpl::DecodeImage width: %{public}d, height: %{public}d, imageType: %{public}s,"
        "inPixelFormat: %{public}d", gridInfo.displayWidth, gridInfo.displayHeight, imageType.c_str(), inPixelFormat);
    if (imageType == "grid") {
        gridInfo.enableGrid = true;
        res = HwDecodeGrids(image, gridInfo, hwBuffer);
    } else if (imageType == "hvc1") {
        gridInfo.enableGrid = false;
        res = HwDecodeSingleImage(image, gridInfo, hwBuffer);
    }
    if (res) {
        *outBuffer = hwBuffer;
    }
    return res;
}

void HeifDecoderImpl::HwPrepareUnPackedInput(std::vector<std::shared_ptr<HeifImage>> tileImages,
    std::vector<std::vector<uint8_t>> &unPackedInput, size_t gridCount)
{
    unPackedInput.resize(gridCount + 1);
    for (size_t index = 0; index < gridCount; ++index) {
        std::shared_ptr<HeifImage> &tileImage = tileImages[index];
        if (index == 0) {
            // get hvcc header
            parser_->GetItemData(tileImage->GetItemId(), &unPackedInput[index], heif_only_header);
            ProcessChunkHead(unPackedInput[index].data(), unPackedInput[index].size());
        }
        parser_->GetItemData(tileImage->GetItemId(), &unPackedInput[index + 1], heif_no_header);
        ProcessChunkHead(unPackedInput[index + 1].data(), unPackedInput[index + 1].size());
    }
}

void HeifDecoderImpl::SetHwDecodeInfo(GridInfo &gridInfo,
    OHOS::HDI::Codec::Image::V2_1::CodecHeifDecInfo &heifDecodeInfo)
{
    OHOS::HDI::Codec::Image::V2_1::GridInfo hwGridInfo = {
        gridInfo.displayWidth,
        gridInfo.displayHeight,
        gridInfo.enableGrid,
        gridInfo.cols,
        gridInfo.rows,
        gridInfo.tileWidth,
        gridInfo.tileHeight,
    };
    heifDecodeInfo = {
        .gridInfo = hwGridInfo,
        .sampleSize = sampleSize_,
    };
}

bool HeifDecoderImpl::HwDecodeGrids(std::shared_ptr<HeifImage> &image,
    GridInfo &gridInfo, sptr<SurfaceBuffer> &hwBuffer)
{
    if (image == nullptr) {
        IMAGE_LOGE("HeifDecoderImpl::DecodeGrids image is nullptr");
        return false;
    }
    std::vector<std::shared_ptr<HeifImage>> tileImages;
    parser_->GetTileImages(image->GetItemId(), tileImages);
    if (tileImages.empty()) {
        IMAGE_LOGE("grid image has no tile image");
        return false;
    }
    size_t gridCount = tileImages.size();
    if (gridCount != (gridInfo.cols * gridInfo.rows)) {
        IMAGE_LOGE("grid count not equal actual decode quantity");
        return false;
    }
    std::vector<std::vector<uint8_t>> inputs;
    HwPrepareUnPackedInput(tileImages, inputs, gridCount);
    GridInfo tempGridInfo = gridInfo;
    std::vector<sptr<Ashmem>> hwInputs;
    if (!copyToAshmem(inputs, hwInputs)) {
        return false;
    }
    auto ret = HwSetColorSpaceData(hwBuffer, gridInfo);
    if (ret != GSERROR_OK) {
        IMAGE_LOGE("SetColorSpaceInfo GetMetadata failed, return value is %{public}d", ret);
        return false;
    }
    OHOS::HDI::Codec::Image::V2_1::CodecHeifDecInfo heifDecodeInfo;
    SetHwDecodeInfo(gridInfo, heifDecodeInfo);
    auto output = sptr<HDI::Base::NativeBuffer>::MakeSptr(hwBuffer->GetBufferHandle());
    sptr<OHOS::HDI::Codec::Image::V2_1::ICodecImage> codec = GetCodecManager();
    CHECK_ERROR_RETURN_RET(codec == nullptr, false);
    int32_t result = codec->DoHeifDecode(hwInputs, output, heifDecodeInfo);
    if (result != SUCCESS) {
        IMAGE_LOGE("heif hw decoder return error: %{public}d, width: %{public}d, height: %{public}d,"
            " imageType: grid, inPixelFormat: %{public}d, colNum: %{public}d, rowNum: %{public}d,"
            " tileWidth: %{public}d, tileHeight: %{public}d, hvccLen: %{public}zu",
            result, gridInfo.displayWidth, gridInfo.displayHeight, hwBuffer->GetFormat(), gridInfo.cols,
            gridInfo.rows, gridInfo.tileWidth, gridInfo.tileHeight, inputs[0].size());
        SetHardwareDecodeErrMsg(gridInfo.tileWidth, gridInfo.tileHeight);
        return false;
    }
    return true;
}

bool HeifDecoderImpl::HwDecodeIdenImage(std::shared_ptr<HeifImage> &image, GridInfo &gridInfo,
    sptr<SurfaceBuffer> *outBuffer, bool isPrimary)
{
    bool cond = !image;
    CHECK_ERROR_RETURN_RET(cond, false);
    std::shared_ptr<HeifImage> idenImage;
    parser_->GetIdenImage(image->GetItemId(), idenImage);
    cond = idenImage == nullptr || idenImage == image;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "invalid iden image");
    return HwDecodeImage(idenImage, gridInfo, outBuffer, isPrimary);
}

bool HeifDecoderImpl::HwDecodeSingleImage(std::shared_ptr<HeifImage> &image,
    GridInfo &gridInfo, sptr<SurfaceBuffer> &hwBuffer)
{
    if (image == nullptr) {
        IMAGE_LOGE("HeifDecoderImpl::DecodeSingleImage image is nullptr");
        return false;
    }
    std::vector<std::vector<uint8_t>> inputs(GRID_NUM_2);
    parser_->GetItemData(image->GetItemId(), &inputs[0], heif_only_header);
    ProcessChunkHead(inputs[0].data(), inputs[0].size());
    parser_->GetItemData(image->GetItemId(), &inputs[1], heif_no_header);
    ProcessChunkHead(inputs[1].data(), inputs[1].size());
    std::vector<sptr<Ashmem>> hwInputs;
    if (!copyToAshmem(inputs, hwInputs)) {
        return false;
    }
    auto ret = HwSetColorSpaceData(hwBuffer, gridInfo);
    if (ret != GSERROR_OK) {
        IMAGE_LOGE("SetColorSpaceInfo GetMetadata failed, return value is %{public}d", ret);
        return false;
    }
    OHOS::HDI::Codec::Image::V2_1::CodecHeifDecInfo heifDecodeInfo;
    SetHwDecodeInfo(gridInfo, heifDecodeInfo);
    auto output = sptr<HDI::Base::NativeBuffer>::MakeSptr(hwBuffer->GetBufferHandle());
    sptr<OHOS::HDI::Codec::Image::V2_1::ICodecImage> codec = GetCodecManager();
    CHECK_ERROR_RETURN_RET(codec == nullptr, false);
    int32_t result = codec->DoHeifDecode(hwInputs, output, heifDecodeInfo);
    if (result != SUCCESS) {
        IMAGE_LOGE("heif hw decoder return error: %{public}d, width: %{public}d, height: %{public}d,"
            " imageType: hvc1, inPixelFormat: %{public}d, colNum: %{public}d, rowNum: %{public}d,"
            " tileWidth: %{public}d, tileHeight: %{public}d, hvccLen: %{public}zu, dataLen: %{public}zu",
            result, gridInfo.displayWidth, gridInfo.displayHeight, hwBuffer->GetFormat(), gridInfo.cols,
            gridInfo.rows, gridInfo.tileWidth, gridInfo.tileHeight, inputs[0].size(), inputs[1].size());
        SetHardwareDecodeErrMsg(gridInfo.tileWidth, gridInfo.tileHeight);
        return false;
    }
    return true;
}

bool HeifDecoderImpl::HwDecodeMimeImage(std::shared_ptr<HeifImage> &image)
{
    if (image == nullptr) {
        IMAGE_LOGE("HeifDecoderImpl::DecodeSingleImage image is nullptr");
        return false;
    }
    std::vector<uint8_t> inputs;
    parser_->GetItemData(image->GetItemId(), &inputs, heif_only_header);
    ProcessChunkHead(inputs.data(), inputs.size());

    if (auxiliaryDstMemory_ == nullptr || auxiliaryDstMemorySize_ == 0 || inputs.size() == 0) {
        IMAGE_LOGE("%{public}s: params fail auxiliaryDstMemorySize_ is %{public}zu, input size is %{public}zu",
            __func__, auxiliaryDstMemorySize_, inputs.size());
        return false;
    }
    if (memcpy_s(auxiliaryDstMemory_, auxiliaryDstMemorySize_, inputs.data(), inputs.size()) != EOK) {
        IMAGE_LOGE("%{public}s: memcpy failed, auxiliaryDstMemorySize_ is %{public}zu, input size is %{public}ld",
            __func__, auxiliaryDstMemorySize_, inputs.size());
        return false;
    }
    return true;
}

bool HeifDecoderImpl::SwDecodeImage(std::shared_ptr<HeifImage> &image, HevcSoftDecodeParam &param,
                                    GridInfo &gridInfo, bool isPrimary)
{
    ImageFuncTimer imageFuncTime("HeifDecoderImpl::%s, desiredpixelformat: %d", __func__, outPixelFormat_);
    if (outPixelFormat_ == PixelFormat::UNKNOWN) {
        IMAGE_LOGE("unknown pixel type: %{public}d", outPixelFormat_);
        return false;
    }
    if (image == nullptr) {
        return false;
    }

    static ImageFwkExtManager imageFwkExtManager;
    if (image->IsMovieImage()) {
        return SwDecodeMovieFirstFrameImage(imageFwkExtManager, image, param);
    }
    std::string imageType = parser_->GetItemType(image->GetItemId());
    if (imageType == "iden") {
        return SwDecodeIdenImage(image, param, gridInfo, isPrimary);
    }

    bool res = false;
    if (imageType == "grid") {
        param.gridInfo.enableGrid = true;
        gridInfo.enableGrid = true;
        res = SwDecodeGrids(imageFwkExtManager, image, param);
    } else if (imageType == "hvc1") {
        param.gridInfo.enableGrid = false;
        gridInfo.enableGrid = false;
        res = SwDecodeSingleImage(imageFwkExtManager, image, param);
    } else if (imageType == "iovl") {
        param.gridInfo.enableGrid = false;
        gridInfo.enableGrid = false;
        res = SwDecodeIovls(imageFwkExtManager, image, param);
    }
    return res;
}

bool HeifDecoderImpl::SwDecodeGrids(ImageFwkExtManager &extManager,
                                    std::shared_ptr<HeifImage> &image, HevcSoftDecodeParam &param)
{
    bool cond = extManager.hevcSoftwareDecodeFunc_ == nullptr && !extManager.LoadImageFwkExtNativeSo();
    CHECK_ERROR_RETURN_RET(cond, false);
    cond = param.dstBuffer == nullptr || param.dstStride == 0;
    CHECK_ERROR_RETURN_RET(cond, false);
    std::vector<std::shared_ptr<HeifImage>> tileImages;
    parser_->GetTileImages(image->GetItemId(), tileImages);
    cond = tileImages.empty();
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "grid image has no tile image");
    size_t numGrid = tileImages.size();
    std::vector<std::vector<uint8_t>> inputs(numGrid);

    for (size_t index = 0; index < numGrid; ++index) {
        std::shared_ptr<HeifImage> &tileImage = tileImages[index];
        parser_->GetItemData(tileImage->GetItemId(),
                             &inputs[index], index == 0 ? heif_header_data : heif_no_header);
        ProcessChunkHead(inputs[index].data(), inputs[index].size());
    }

    int32_t retCode = extManager.hevcSoftwareDecodeFunc_(inputs, param);
    cond = retCode != 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "SwDecodeGrids decode failed: %{public}d", retCode);
    return true;
}

bool HeifDecoderImpl::SwDecodeIovls(ImageFwkExtManager &extManager,
                                    std::shared_ptr<HeifImage> &image, HevcSoftDecodeParam &param)
{
    if (extManager.hevcSoftwareDecodeFunc_ == nullptr && !extManager.LoadImageFwkExtNativeSo()) {
        return false;
    }
    if (param.dstBuffer == nullptr || param.dstStride == 0) {
        return false;
    }
    std::vector<std::shared_ptr<HeifImage>> iovlImages;
    parser_->GetIovlImages(image->GetItemId(), iovlImages);
    if (iovlImages.empty()) {
        IMAGE_LOGE("iovl image has no tile image");
        return false;
    }

    return SwDecodeSingleImage(extManager, iovlImages[0], param);
}

bool HeifDecoderImpl::SwDecodeIdenImage(std::shared_ptr<HeifImage> &image,
                                        HevcSoftDecodeParam &param, GridInfo &gridInfo, bool isPrimary)
{
    bool cond = !image;
    CHECK_ERROR_RETURN_RET(cond, false);
    std::shared_ptr<HeifImage> idenImage;
    parser_->GetIdenImage(image->GetItemId(), idenImage);
    cond = idenImage == nullptr || idenImage == image;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "invalid iden image");
    return SwDecodeImage(idenImage, param, gridInfo, isPrimary);
}

bool HeifDecoderImpl::SwDecodeSingleImage(ImageFwkExtManager &extManager,
                                          std::shared_ptr<HeifImage> &image, HevcSoftDecodeParam &param)
{
    if (extManager.hevcSoftwareDecodeFunc_ == nullptr && !extManager.LoadImageFwkExtNativeSo()) {
        return false;
    }
    bool cond = (param.dstBuffer == nullptr || param.dstStride == 0);
    CHECK_ERROR_RETURN_RET(cond, false);
    std::vector<std::vector<uint8_t>> inputs(1);
    parser_->GetItemData(image->GetItemId(), &inputs[0], heif_header_data);
    ProcessChunkHead(inputs[0].data(), inputs[0].size());

    int32_t retCode = extManager.hevcSoftwareDecodeFunc_(inputs, param);
    if (retCode != 0) {
        IMAGE_LOGE("SwDecodeSingleImage decode failed: %{public}d", retCode);
        return false;
    }
    return true;
}

bool HeifDecoderImpl::SwDecodeMovieFirstFrameImage(ImageFwkExtManager &extManager,
    std::shared_ptr<HeifImage> &image, HevcSoftDecodeParam &param)
{
    if (extManager.hevcSoftwareDecodeFunc_ == nullptr && !extManager.LoadImageFwkExtNativeSo()) {
        return false;
    }
    bool cond = (param.dstBuffer == nullptr || param.dstStride == 0);
    CHECK_ERROR_RETURN_RET(cond, false);
    std::vector<std::vector<uint8_t>> inputs(1);
    parser_->GetMovieFrameData(0, &inputs[0], heif_header_data);
    ProcessChunkHead(inputs[0].data(), inputs[0].size());

    int32_t retCode = extManager.hevcSoftwareDecodeFunc_(inputs, param);
    if (retCode != 0) {
        IMAGE_LOGE("SwDecodeMovieFirstFrameImage decode failed: %{public}d", retCode);
        return false;
    }
    return true;
}

bool HeifDecoderImpl::SwDecodeAuxiliaryImage(std::shared_ptr<HeifImage> &gainmapImage,
                                             GridInfo &gainmapGridInfo, sptr<SurfaceBuffer> *outputBuf)
{
    ImageTrace trace("HeifDecoderImpl::SwdecodeGainmap");
    uint32_t width = gainmapImage->GetOriginalWidth();
    uint32_t height = gainmapImage->GetOriginalHeight();
    sptr<SurfaceBuffer> output = SurfaceBuffer::Create();
    BufferRequestConfig = {
        .width = width,
        .height = height,
        .format = GRAPHIC_PIXEL_FMT_YCBCR_420_SP,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0;
    }
    GSError ret = output->Alloc(config);
    bool cond = ret != GSERROR_OK;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "output->alloc(config)faild, GSError=%{public}d", ret);
    if (!DoSwDecodeAuxiliaryImage(gainmapImage, gainmapGridInfo, output, outputBuf)) {
        IMAGE_LOGE("HDR-IMAGE SwDecodeGainmap failed");
    }
    return true;
}

Media::PixelFormat GetDecodeHeifFormat(std::shared_ptr<HeifImage> &heifImage)
{
    switch (heifImage->GetDefaultPixelFormat()) {
        case  HeifPixelFormat::MONOCHROME:
            return PixelFormat::YUV_400;
        case HeifPixelFormat::YUV420:
            return PixelFormat::NV12;
        default:
            return PixelFormat::UNKNOWN;
    }
    return PixelFormat::UNKNOWN;
}

bool HeifDecoderImpl::DoSwDecodeAuxiliaryImage(std::shared_ptr<HeifImage> &gainmapImage, GridInfo &gainmapgridInfo,
    sptr<SurfaceBuffer> &output, sptr<SurfaceBuffer> *outputBuf)
{
    PixelFormat gainmapSrcFmt = GetDecodeHeifFormat(gainmapImage);
    PixelFormat gainmapDstFmt = PixelFormat::UNKNOWN;
    if (gainmapSrcFmt == PixelFormat::UNKNOWN) {
        IMAGE_LOGE("HDR-IMAGE Unsupported gainmap default DstFmt");
        return false;
    }
    uint32_t gainmapRowStride;
    uint8_t *gainmapDstBuffer;
    if (isGainmapDecode_) {
        gainmapDstFmt = PixelFormat::RGBA_8888;
        gainmapDstBuffer = gainmapDstMemory_;
        gainmapRowStride = static_cast<uint32_t>(gainmapDstRowStride_);
    } else {
        gainmapDstFmt = outPixelFormat_;
        gainmapDstBuffer = auxiliaryDstMemory_;
        gainmapRowStride = static_cast<uint32_t>(auxiliaryDstRowStride_);
    }
    OH_NativeBuffer_Planes *dataPlanesInfo = nullptr;
    output->GetPlanesInfo((void **)&dataPlanesInfo);
    bool cond = (dataPlanesInfo == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "failed to get src buffer planes info.");
    void *nativeBuffer = output.GetRefPtr();
    int32_t err = ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
    if (err != OHOS::GSERROR_OK) {
        return false;
    }
    uint32_t gainmapStride = static_cast<uint32_t>(output->GetStride());
    uint32_t gainmapMemorySize = gainmapStride * static_cast<uint32_t>(output->GetHeight());
    HevcSoftDecodeParam gainmapParam {
        gainmapgridInfo, gainmapSrcFmt, gainmapDstFmt,
        gainmapDstBuffer, gainmapMemorySize,
        gainmapStride, nullptr, false, static_cast<void *>(nativeBuffer), gainmapRowStride
    };
    if (!SwDecodeImage(gainmapImage, gainmapParam, gainmapgridInfo, false)) {
        ImageUtils::SurfaceBuffer_Unreference(nativeBuffer);
        IMAGE_LOGE("HDR-IMAGE SwDecodeImage failed");
        return false;
    }
    *outputBuf = output;
    if (output != nullptr) {
        ImageUtils::SurfaceBuffer_Unreference(nativeBuffer);
    }
    return true;
}

static bool IsEmptyBuffer(uint8_t *buffer, uint32_t width, uint32_t height, uint32_t bpp, uint32_t rowStride)
{
    bool cond = buffer == nullptr;
    CHECK_ERROR_RETURN_RET(cond, true);
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

static bool FillAlphaChannel(std::shared_ptr<HeifImage> &masterImage, uint8_t *alphaMemory,
                             size_t alphaStride, uint8_t *dstMemory, size_t dstRowStride)
{
    // merge alpha channel
    uint8_t *alphaRowStart = alphaMemory;
    uint8_t *dstRowStart = dstMemory;
    uint32_t width = masterImage->GetOriginalWidth();
    uint32_t height = masterImage->GetOriginalHeight();
    bool cond = IsEmptyBuffer(reinterpret_cast<uint8_t*>(alphaMemory), width, height, 1, alphaStride);
    CHECK_ERROR_RETURN_RET(cond, false);

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
        alphaRowStart += alphaStride;
        dstRowStart += dstRowStride;
    }
    return true;
}

static bool IsValidAlphaImage(std::shared_ptr<HeifImage> &masterImage, std::shared_ptr<HeifImage> &alphaImage,
                              PixelFormat dstPixFmt, bool isHardware)
{
    return alphaImage != nullptr && alphaImage != masterImage &&
        alphaImage->GetOriginalWidth() == masterImage->GetOriginalWidth() &&
        alphaImage->GetOriginalHeight() == masterImage->GetOriginalHeight() &&
        ((isHardware && alphaImage->GetDefaultPixelFormat() == HeifPixelFormat::YUV420) ||
        (!isHardware && (alphaImage->GetDefaultPixelFormat() == HeifPixelFormat::YUV420 ||
        alphaImage->GetDefaultPixelFormat() == HeifPixelFormat::MONOCHROME))) &&
        alphaImage->GetLumaBitNum() == LUMA_8_BIT &&
        (dstPixFmt == PixelFormat::RGBA_8888 || dstPixFmt == PixelFormat::BGRA_8888);
}

bool HeifDecoderImpl::HwApplyAlphaImage(std::shared_ptr<HeifImage> &masterImage,
                                        uint8_t *dstMemory, size_t dstRowStride)
{
    // check alpha image is available
    if (masterImage == nullptr || IsDirectYUVDecode()) {
        return false;
    }
    std::shared_ptr<HeifImage> alphaImage = masterImage->GetAlphaImage();
    if (!IsValidAlphaImage(masterImage, alphaImage, outPixelFormat_, true)) {
        return false;
    }

    // decode alpha image
    GridInfo alphaGridInfo;
    sptr<SurfaceBuffer> hwBuffer;
    InitGridInfo(alphaImage, alphaGridInfo);
    bool decodeRes = HwDecodeImage(alphaImage, alphaGridInfo, &hwBuffer, false);
    if (!decodeRes) {
        IMAGE_LOGE("hw decode alpha image failed");
        return false;
    }

    // merge alpha channel
    return FillAlphaChannel(masterImage, reinterpret_cast<uint8_t *>(hwBuffer->GetVirAddr()),
                            hwBuffer->GetStride(), dstMemory, dstRowStride);
}

bool HeifDecoderImpl::SwApplyAlphaImage(std::shared_ptr<HeifImage> &masterImage,
                                        uint8_t *dstMemory, size_t dstRowStride)
{
    // check alpha image is available
    if (masterImage == nullptr || IsDirectYUVDecode()) {
        return false;
    }
    std::shared_ptr<HeifImage> alphaImage = masterImage->GetAlphaImage();
    if (!IsValidAlphaImage(masterImage, alphaImage, outPixelFormat_, false)) {
        return false;
    }

    GridInfo alphaGridInfo;
    InitGridInfo(alphaImage, alphaGridInfo);
    uint32_t alphaStride = alphaImage->GetOriginalWidth();
    uint32_t alphaMemorySize = alphaStride * alphaImage->GetOriginalHeight();
    PixelFormat alphaDstFmt = PixelFormat::ALPHA_8;
    std::unique_ptr<uint8_t[]> alphaMemory = std::make_unique<uint8_t[]>(alphaMemorySize);
    HevcSoftDecodeParam param {
        alphaGridInfo, Media::PixelFormat::UNKNOWN, alphaDstFmt,
        alphaMemory.get(), alphaMemorySize, alphaStride, nullptr, false, nullptr, 0
    };
    bool decodeRes = SwDecodeImage(alphaImage, param, alphaGridInfo, false);
    bool cond = !decodeRes;
    CHECK_ERROR_RETURN_RET(cond, false);

    // merge alpha channel
    return FillAlphaChannel(masterImage, alphaMemory.get(), alphaStride, dstMemory, dstRowStride);
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

bool HeifDecoderImpl::IsHeifAlphaYuv400()
{
    std::shared_ptr<HeifImage> alphaImage = primaryImage_->GetAlphaImage();
    if (alphaImage == nullptr) {
        return false;
    }
    if (alphaImage->GetDefaultPixelFormat() != HeifPixelFormat::YUV420) {
        IMAGE_LOGE("heif alphaImage is not YUV420");
        return true;
    }
    return false;
}

bool HeifDecoderImpl::IsHeifGainmapYuv400()
{
    if (gainmapImage_ == nullptr) {
        return false;
    }
    if (gainmapImage_->GetDefaultPixelFormat() != HeifPixelFormat::YUV420) {
        IMAGE_LOGE("heif gainmapImage is not YUV420");
        return true;
    }
    return false;
}

int32_t HeifDecoderImpl::GetPrimaryLumaBitNum()
{
    return primaryImage_->GetLumaBitNum();
}

bool HeifDecoderImpl::IsDirectYUVDecode()
{
    if (dstHwBuffer_ == nullptr || isGainmapDecode_) {
        return false;
    }
    if (primaryImage_->GetLumaBitNum() == LUMA_10_BIT) {
        return outPixelFormat_ == Media::PixelFormat::YCRCB_P010 || outPixelFormat_ == Media::PixelFormat::YCBCR_P010;
    }
    return outPixelFormat_ == Media::PixelFormat::NV21 || outPixelFormat_ == Media::PixelFormat::NV12;
}

bool HeifDecoderImpl::IsAuxiliaryDirectYUVDecode(std::shared_ptr<HeifImage> &auxiliaryImage)
{
    if (auxiliaryDstHwBuffer_ == nullptr || isGainmapDecode_) {
        return false;
    }
    if (auxiliaryImage->GetLumaBitNum() == LUMA_10_BIT) {
        return outPixelFormat_ == Media::PixelFormat::YCRCB_P010 || outPixelFormat_ == Media::PixelFormat::YCBCR_P010;
    }
    return outPixelFormat_ == Media::PixelFormat::NV21 || outPixelFormat_ == Media::PixelFormat::NV12;
}

bool HeifDecoderImpl::decodeSequence(int frameIndex, HeifFrameInfo *frameInfo)
{
    // unimplemented
    return false;
}

void HeifDecoderImpl::SetSampleFormat(uint32_t sampleSize, ColorManager::ColorSpaceName colorSpaceName)
{
    sampleSize_ = sampleSize;
    colorSpaceName_ = colorSpaceName;
}

void HeifDecoderImpl::GetGainmapColorSpace(ColorManager::ColorSpaceName &gainmapColor)
{
    if (gainmapImageInfo_.hasNclxColor) {
        gainmapColor = ColorUtils::CicpToColorSpace(gainmapImageInfo_.nclxColor.colorPrimaries,
            gainmapImageInfo_.nclxColor.transferCharacteristics, gainmapImageInfo_.nclxColor.matrixCoefficients,
            gainmapImageInfo_.nclxColor.fullRangeFlag);
    }
}

void HeifDecoderImpl::setDstBuffer(uint8_t *dstBuffer, size_t rowStride, void *context)
{
    dstMemory_ = dstBuffer;
    dstRowStride_ = rowStride;
    dstHwBuffer_ = reinterpret_cast<SurfaceBuffer*>(context);
}

void HeifDecoderImpl::setGainmapDstBuffer(uint8_t* dstBuffer, size_t rowStride, void *context)
{
    gainmapDstMemory_ = dstBuffer;
    gainmapDstRowStride_ = rowStride;
    regionInfo_.isGainmapImage = true;
    isGainmapDecode_ = true;
    gainMapDstHwbuffer_ = reinterpret_cast<SurfaceBuffer*>(context);
}

void HeifDecoderImpl::setAuxiliaryDstBuffer(uint8_t* dstBuffer, size_t dstSize, size_t rowStride, void *context)
{
    auxiliaryDstMemory_ = dstBuffer;
    auxiliaryDstMemorySize_ = dstSize;
    auxiliaryDstRowStride_ = rowStride;
    isAuxiliaryDecode_ = true;
    auxiliaryDstHwBuffer_ = reinterpret_cast<SurfaceBuffer*>(context);
    sampleSize_ = DEFAULT_SCALE_SIZE;
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

bool HeifDecoderImpl::getAuxiliaryMapInfo(HeifFrameInfo* frameInfo)
{
    if (frameInfo != nullptr) {
        *frameInfo = auxiliaryImageInfo_;
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
    if (primaryImage_->GetLumaBitNum() == LUMA_10_BIT && imageInfo_.hasNclxColor &&
        imageInfo_.nclxColor.colorPrimaries == BT2020_PRIMARIES) {
        return uwaInfo.empty() ? HeifImageHdrType::ISO_SINGLE : HeifImageHdrType::VIVID_SINGLE;
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

void HeifDecoderImpl::getFragmentMetadata(Media::Rect& fragmentMetadata)
{
    HeifFragmentMetadata metadata = primaryImage_->GetFragmentMetadata();
    fragmentMetadata.width = static_cast<int32_t>(metadata.width);
    fragmentMetadata.height = static_cast<int32_t>(metadata.height);
    fragmentMetadata.left = static_cast<int32_t>(metadata.horizontalOffset);
    fragmentMetadata.top = static_cast<int32_t>(metadata.verticalOffset);
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

uint32_t HeifDecoderImpl::getColorDepth()
{
    // no need to implement
    return 0;
}
} // namespace ImagePlugin
} // namespace OHOS
#endif

HeifDecoder* CreateHeifDecoderImpl(void)
{
#ifdef HEIF_HW_DECODE_ENABLE
    return new OHOS::ImagePlugin::HeifDecoderImpl();
#else
    return nullptr;
#endif
}
