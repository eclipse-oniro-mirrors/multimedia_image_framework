/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "image_source.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <vector>
#ifdef SUT_DECODE_ENABLE
#include <dlfcn.h>
#include <unistd.h>
#endif

#include "image_trace.h"
#include "image_log.h"
#include "image_packer.h"
#include "image_system_properties.h"
#include "image_utils.h"
#include "media_errors.h"
#include "memory_manager.h"
#include "pixel_astc.h"
#include "securec.h"
#include "source_stream.h"
#if !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "surface_buffer.h"
#include "native_buffer.h"
#include "v1_0/buffer_handle_meta_key_type.h"
#include "v1_0/cm_color_space.h"
#include "v1_0/hdr_static_metadata.h"
#include "display/graphic/common/v2_1/cm_color_space.h"
#include "v2_2/cm_color_space.h"
#include "v2_2/buffer_handle_meta_key_type.h"
#include "vpe_utils.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageSource"

namespace OHOS {
namespace Media {
using namespace std;
using namespace ImagePlugin;
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
using namespace HDI::Display::Graphic::Common::V1_0;
#endif

static const uint8_t NUM_0 = 0;
static const uint8_t NUM_1 = 1;
static const uint8_t NUM_2 = 2;
static const uint8_t NUM_3 = 3;
static const uint8_t NUM_4 = 4;
static const uint8_t NUM_6 = 6;
static const uint8_t NUM_8 = 8;
static const uint8_t NUM_16 = 16;
static const uint8_t NUM_24 = 24;
static const uint32_t ASTC_MAGIC_ID = 0x5CA1AB13;
static const int ASTC_SIZE = 512 * 512;
static const size_t ASTC_HEADER_SIZE = 16;
static const uint8_t ASTC_HEADER_BLOCK_X = 4;
static const uint8_t ASTC_HEADER_BLOCK_Y = 5;
static const uint8_t ASTC_HEADER_DIM_X = 7;
static const uint8_t ASTC_HEADER_DIM_Y = 10;
constexpr uint8_t ASTC_EXTEND_INFO_TLV_NUM6 = 6; // curren only six group TLV
constexpr uint32_t ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH = 4; // 4 bytes to discripte for extend info summary bytes
constexpr uint8_t TLV_LEAST_BYTES = 5; // sizeof(uint8_t) + sizeof(uint32_t)
constexpr size_t MAX_INT32 = 2147483647; // int32 max 2147483647
constexpr int32_t ASTC_MAX_SIZE = 8192;
constexpr size_t ASTC_TLV_SIZE = 10; // 10 is tlv size, colorspace size
constexpr uint8_t ASTC_OPTION_QUALITY = 85;

#ifdef SUT_DECODE_ENABLE
constexpr uint8_t ASTC_HEAD_BYTES = 16;
constexpr uint8_t SUT_HEAD_BYTES = 16;
constexpr uint32_t SUT_FILE_SIGNATURE = 0x5CA1AB13;
#ifdef SUT_PATH_X64
static const std::string g_textureSuperDecSo = "/system/lib64/libtextureSuperDecompress.z.so";
#else
static const std::string g_textureSuperDecSo = "/system/lib/libtextureSuperDecompress.z.so";
#endif
constexpr uint8_t EXPAND_ASTC_INFO_MAX_DEC = 16; // reserve max 16 groups TLV info

struct AstcOutInfo {
    uint8_t *astcBuf;
    int32_t astcBytes;
    uint8_t expandNums; // groupNum of TLV extInfo
    uint8_t expandInfoType[EXPAND_ASTC_INFO_MAX_DEC];
    int32_t expandInfoBytes[EXPAND_ASTC_INFO_MAX_DEC];
    uint8_t *expandInfoBuf[EXPAND_ASTC_INFO_MAX_DEC];
    int32_t expandInfoCapacity[EXPAND_ASTC_INFO_MAX_DEC];
    int32_t expandTotalBytes;
    int32_t pureSutBytes;
};

struct SutInInfo {
    const uint8_t *sutBuf;
    int32_t sutBytes;
};

using GetSuperCompressAstcSize = size_t (*)(const uint8_t *, size_t);
using SuperDecompressTexture = bool (*)(const SutInInfo &, AstcOutInfo &);
using IsSut = bool (*)(const uint8_t *, size_t);
using GetTextureInfoFromSut = bool (*)(const uint8_t *, size_t, uint32_t &, uint32_t &, uint32_t &);
using GetExpandInfoFromSut = bool (*)(const SutInInfo &, AstcOutInfo &, bool);
class SutDecSoManager {
public:
    SutDecSoManager();
    ~SutDecSoManager();
    bool LoadSutDecSo();
    GetSuperCompressAstcSize sutDecSoGetSizeFunc_;
    SuperDecompressTexture sutDecSoDecFunc_;
    GetTextureInfoFromSut getTextureInfoFunc_;
    GetExpandInfoFromSut getExpandInfoFromSutFunc_;
private:
    bool sutDecSoOpened_;
    void *textureDecSoHandle_;
    void DlcloseHandle();
    std::mutex sutDecSoMutex_ = {};
};

static SutDecSoManager g_sutDecSoManager;

SutDecSoManager::SutDecSoManager()
{
    sutDecSoOpened_ = false;
    textureDecSoHandle_ = nullptr;
    sutDecSoGetSizeFunc_ = nullptr;
    sutDecSoDecFunc_ = nullptr;
    getTextureInfoFunc_ = nullptr;
    getExpandInfoFromSutFunc_ = nullptr;
}

SutDecSoManager::~SutDecSoManager()
{
    bool cond = (!sutDecSoOpened_ || textureDecSoHandle_ == nullptr);
    CHECK_DEBUG_RETURN_LOG(cond, "[ImageSource] astcenc dec so is not be opened when dlclose!");
    cond = dlclose(textureDecSoHandle_) != 0;
    CHECK_ERROR_RETURN_LOG(cond, "[ImageSource] astcenc dlclose failed: %{public}s!", g_textureSuperDecSo.c_str());
}

static bool CheckClBinIsExist(const std::string &name)
{
    return (access(name.c_str(), F_OK) != -1); // -1 means that the file is  not exist
}

void SutDecSoManager::DlcloseHandle()
{
    if (textureDecSoHandle_ != nullptr) {
        dlclose(textureDecSoHandle_);
        textureDecSoHandle_ = nullptr;
    }
}

bool SutDecSoManager::LoadSutDecSo()
{
    std::lock_guard<std::mutex> lock(sutDecSoMutex_);
    if (!sutDecSoOpened_) {
        bool cond = CheckClBinIsExist(g_textureSuperDecSo);
        CHECK_ERROR_RETURN_RET_LOG(!cond, false, "[ImageSource] %{public}s! is not found", g_textureSuperDecSo.c_str());
        textureDecSoHandle_ = dlopen(g_textureSuperDecSo.c_str(), 1);
        cond = (textureDecSoHandle_ == nullptr);
        CHECK_ERROR_RETURN_RET_LOG(cond, false, "[ImageSource] astc libtextureSuperDecompress dlopen failed!");
        sutDecSoGetSizeFunc_ =
            reinterpret_cast<GetSuperCompressAstcSize>(dlsym(textureDecSoHandle_, "GetSuperCompressAstcSize"));
        if (sutDecSoGetSizeFunc_ == nullptr) {
            IMAGE_LOGE("[ImageSource] astc GetSuperCompressAstcSize dlsym failed!");
            DlcloseHandle();
            return false;
        }
        sutDecSoDecFunc_ =
            reinterpret_cast<SuperDecompressTexture>(dlsym(textureDecSoHandle_, "SuperDecompressTextureTlv"));
        if (sutDecSoDecFunc_ == nullptr) {
            IMAGE_LOGE("[ImageSource] astc SuperDecompressTextureTlv dlsym failed!");
            DlcloseHandle();
            return false;
        }
        getTextureInfoFunc_ =
            reinterpret_cast<GetTextureInfoFromSut>(dlsym(textureDecSoHandle_, "GetTextureInfoFromSut"));
        if (getTextureInfoFunc_ == nullptr) {
            IMAGE_LOGE("[ImageSource] astc GetTextureInfoFromSut dlsym failed!");
            DlcloseHandle();
            return false;
        }
        getExpandInfoFromSutFunc_ =
            reinterpret_cast<GetExpandInfoFromSut>(dlsym(textureDecSoHandle_, "GetExpandInfoFromSut"));
        if (getExpandInfoFromSutFunc_ == nullptr) {
            IMAGE_LOGE("[ImageSource] astc GetExpandInfoFromSut dlsym failed!");
            DlcloseHandle();
            return false;
        }
        sutDecSoOpened_ = true;
    }
    return true;
}
#endif

bool ImageSource::IsASTC(const uint8_t *fileData, size_t fileSize) __attribute__((no_sanitize("cfi")))
{
    if (fileData == nullptr || fileSize < ASTC_HEADER_SIZE) {
        IMAGE_LOGE("[ImageSource]IsASTC fileData incorrect.");
        return false;
    }
    uint32_t magicVal = static_cast<uint32_t>(fileData[NUM_0]) +
        (static_cast<uint32_t>(fileData[NUM_1]) << NUM_8) +
        (static_cast<uint32_t>(fileData[NUM_2]) << NUM_16) +
        (static_cast<uint32_t>(fileData[NUM_3]) << NUM_24);
    if (magicVal == ASTC_MAGIC_ID) {
        return true;
    }
#ifdef SUT_DECODE_ENABLE
    if (magicVal == SUT_FILE_SIGNATURE) {
        return true;
    }
#endif
    return false;
}

bool ImageSource::IsASTCSource()
{
    if (isAstc_.has_value()) {
        return isAstc_.value();
    }
    if (sourceStreamPtr_ == nullptr) {
        return false;
    }
    uint32_t savedPosition = sourceStreamPtr_->Tell();
    if (savedPosition == sourceStreamPtr_->GetStreamSize()) {
        return false;
    }
    if (!sourceStreamPtr_->Seek(0)) {
        return false;
    }
    uint32_t streamStartPosition = sourceStreamPtr_->Tell();
    ImagePlugin::DataStreamBuffer outData;
    uint32_t ret = GetData(outData, ASTC_HEADER_SIZE);
    bool detected = ret == SUCCESS && IsASTC(outData.inputStreamBuffer, outData.dataSize);
    uint32_t restorePosition = savedPosition >= streamStartPosition ?
        savedPosition - streamStartPosition : savedPosition;
    bool isPositionRestored = sourceStreamPtr_->Seek(restorePosition);
    if (ret != SUCCESS || !isPositionRestored) {
        return false;
    }
    isAstc_ = detected;
    return isAstc_.value();
}

bool ImageSource::GetImageInfoForASTC(ImageInfo &imageInfo, const uint8_t *sourceFilePtr)
{
    ASTCInfo astcInfo;
    bool cond = (!sourceStreamPtr_);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[ImageSource] get astc image info null.");
    cond = !GetASTCInfo(sourceFilePtr, sourceStreamPtr_->GetStreamSize(), astcInfo);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[ImageSource] get astc image info failed.");
    imageInfo.size = astcInfo.size;
    switch (astcInfo.blockFootprint.width) {
        case NUM_4: {
            imageInfo.pixelFormat = PixelFormat::ASTC_4x4;
            break;
        }
        case NUM_6: {
            imageInfo.pixelFormat = PixelFormat::ASTC_6x6;
            break;
        }
        case NUM_8: {
            imageInfo.pixelFormat = PixelFormat::ASTC_8x8;
            break;
        }
        default:
            IMAGE_LOGE("[ImageSource]GetImageInfoForASTC pixelFormat is unknown.");
            imageInfo.pixelFormat = PixelFormat::UNKNOWN;
    }
    return true;
}

#ifdef SUT_DECODE_ENABLE
static size_t GetAstcSizeBytes(const uint8_t *fileBuf, size_t fileSize)
{
    bool cond = (fileBuf == nullptr) || (fileSize <= ASTC_HEAD_BYTES);
    CHECK_ERROR_RETURN_RET_LOG(cond, 0,
                               "astc GetAstcSizeBytes input is nullptr or fileSize is smaller than ASTC HEADER");
    cond = !g_sutDecSoManager.LoadSutDecSo() || g_sutDecSoManager.sutDecSoGetSizeFunc_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, 0,
                               "[ImageSource] SUT dec so dlopen failed or sutDecSoGetSizeFunc_ is nullptr!");
    return g_sutDecSoManager.sutDecSoGetSizeFunc_(fileBuf, fileSize);
}

static void FreeAllExtMemSut(AstcOutInfo &astcInfo)
{
    uint8_t maxIdx = std::min(static_cast<uint8_t>(EXPAND_ASTC_INFO_MAX_DEC), astcInfo.expandNums);
    for (uint8_t idx = 0; idx < maxIdx; idx++) {
        if (astcInfo.expandInfoBuf[idx] != nullptr) {
            free(astcInfo.expandInfoBuf[idx]);
        }
    }
}

static bool FillAstcSutExtInfo(AstcOutInfo &astcInfo, SutInInfo &sutInfo)
{
    bool cond = !g_sutDecSoManager.LoadSutDecSo() || g_sutDecSoManager.getExpandInfoFromSutFunc_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[ImageSource] SUT dec getExpandInfoFromSutFunc_ is nullptr!");
    cond = !g_sutDecSoManager.getExpandInfoFromSutFunc_(sutInfo, astcInfo, false);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[ImageSource] GetExpandInfoFromSut failed!");
    if (astcInfo.expandNums > EXPAND_ASTC_INFO_MAX_DEC) {
        IMAGE_LOGE("[ImageSource] expandNums %{public}d exceeds max %{public}d",
            astcInfo.expandNums, EXPAND_ASTC_INFO_MAX_DEC);
        return false;
    }
    int32_t expandTotalBytes = 0;
    for (uint8_t idx = 0; idx < astcInfo.expandNums; idx++) {
        astcInfo.expandInfoCapacity[idx] = astcInfo.expandInfoBytes[idx];
        if (astcInfo.expandInfoBytes[idx] <= 0) {
            IMAGE_LOGE("[ImageSource] expandInfoBytes[%{public}d] is invalid", idx);
            return false;
        }
        astcInfo.expandInfoBuf[idx] = static_cast<uint8_t *>(malloc(astcInfo.expandInfoCapacity[idx]));
        if (astcInfo.expandInfoBuf[idx] == nullptr) {
            IMAGE_LOGE("[ImageSource] astcInfo.expandInfoBuf malloc failed!");
            return false;
        }
        expandTotalBytes += sizeof(uint8_t) + sizeof(int32_t) + astcInfo.expandInfoBytes[idx];
    }
    return astcInfo.expandTotalBytes == expandTotalBytes;
}

static bool CheckExtInfoForPixelmap(AstcOutInfo &astcInfo, unique_ptr<PixelAstc> &pixelAstc)
{
    uint8_t colorSpace = 0;
    if (astcInfo.expandNums > EXPAND_ASTC_INFO_MAX_DEC) {
        IMAGE_LOGE("CheckExtInfoForPixelmap expandNums %{public}d exceeds max", astcInfo.expandNums);
        return false;
    }
    for (uint8_t idx = 0; idx < astcInfo.expandNums; idx++) {
        if (astcInfo.expandInfoBuf[idx] == nullptr) {
            continue;
        }
        switch (static_cast<AstcExtendInfoType>(astcInfo.expandInfoType[idx])) {
            case AstcExtendInfoType::COLOR_SPACE:
                if (astcInfo.expandInfoBytes[idx] < 1) {
                    IMAGE_LOGE("CheckExtInfoForPixelmap COLOR_SPACE expandInfoBytes is invalid");
                    return false;
                }
                colorSpace = *astcInfo.expandInfoBuf[idx];
                break;
            default:
                return false;
        }
    }
#ifdef IMAGE_COLORSPACE_FLAG
    pixelAstc->InnerSetColorSpace(static_cast<ColorManager::ColorSpaceName>(colorSpace), true);
#endif
    return true;
}

static bool TextureSuperCompressDecodeInit(AstcOutInfo *astcInfo, SutInInfo *sutInfo, size_t inBytes, size_t outBytes)
{
    bool ret = (memset_s(astcInfo, sizeof(AstcOutInfo), 0, sizeof(AstcOutInfo)) == 0) &&
               (memset_s(sutInfo, sizeof(SutInInfo), 0, sizeof(SutInInfo)) == 0);
    if (!ret) {
        IMAGE_LOGE("astc SuperDecompressTexture memset failed!");
        return false;
    }
    bool cond = inBytes > static_cast<size_t>(std::numeric_limits<int32_t>::max());
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "astc SuperDecompressTexture inBytes overflow!");
    sutInfo->sutBytes = static_cast<int32_t>(inBytes);
    cond = outBytes > static_cast<size_t>(std::numeric_limits<int32_t>::max());
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "astc SuperDecompressTexture outBytes overflow!");
    astcInfo->astcBytes = static_cast<int32_t>(outBytes);
    return true;
}

static bool TextureSuperCompressDecode(const uint8_t *inData, size_t inBytes, uint8_t *outData, size_t outBytes,
    unique_ptr<PixelAstc> &pixelAstc)
{
    size_t preOutBytes = outBytes;
    bool cond = (inData == nullptr) || (outData == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "astc TextureSuperCompressDecode input check failed!");
    cond = !g_sutDecSoManager.LoadSutDecSo() || g_sutDecSoManager.sutDecSoDecFunc_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "[ImageSource] SUT dec so dlopen failed or sutDecSoDecFunc_ is nullptr!");
    AstcOutInfo astcInfo = {0};
    SutInInfo sutInfo = {0};
    cond = !TextureSuperCompressDecodeInit(&astcInfo, &sutInfo, inBytes, outBytes);
    CHECK_ERROR_RETURN_RET(cond, false);
    sutInfo.sutBuf = inData;
    astcInfo.astcBuf = outData;
    if (!FillAstcSutExtInfo(astcInfo, sutInfo)) {
        FreeAllExtMemSut(astcInfo);
        IMAGE_LOGE("[ImageSource] SUT dec FillAstcSutExtInfo failed!");
        return false;
    }
    if (!g_sutDecSoManager.sutDecSoDecFunc_(sutInfo, astcInfo)) {
        IMAGE_LOGE("astc SuperDecompressTexture process failed!");
        FreeAllExtMemSut(astcInfo);
        return false;
    }
    if (!CheckExtInfoForPixelmap(astcInfo, pixelAstc)) {
        IMAGE_LOGE("astc SuperDecompressTexture could not get ext info!");
        FreeAllExtMemSut(astcInfo);
        return false;
    }
    FreeAllExtMemSut(astcInfo);
    cond = astcInfo.astcBytes < 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "astc SuperDecompressTexture astcInfo.astcBytes sub overflow!");
    outBytes = static_cast<size_t>(astcInfo.astcBytes);
    cond = outBytes != preOutBytes;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "astc SuperDecompressTexture Dec size is predicted failed!");
    return true;
}
#endif

static uint32_t GetDataSize(uint8_t *buf)
{
    return static_cast<uint32_t>(buf[NUM_0]) +
        (static_cast<uint32_t>(buf[NUM_1]) << NUM_8) +
        (static_cast<uint32_t>(buf[NUM_2]) << NUM_16) +
        (static_cast<uint32_t>(buf[NUM_3]) << NUM_24);
}

void ReleaseExtendInfoMemory(AstcExtendInfo &extendInfo)
{
    for (uint8_t idx = 0; idx < extendInfo.extendNums; idx++) {
        if (extendInfo.extendInfoValue[idx] != nullptr) {
            free(extendInfo.extendInfoValue[idx]);
            extendInfo.extendInfoValue[idx] = nullptr;
        }
    }
}

bool HandleMetadataCopy(std::vector<uint8_t>& dest, const uint8_t *src, size_t length)
{
    if (length > MAX_TLV_METADATA_SIZE) {
        IMAGE_LOGE("[AstcCodec] HandleMetadataCopy length too large: %{public}zu", length);
        return false;
    }
    dest.resize(length);
    if (memcpy_s(dest.data(), length, src, length) != 0) {
        IMAGE_LOGE("[AstcCodec] WriteAstcExtendInfo memcpy failed!");
        return false;
    }
    return true;
}

bool ProcessAstcMetadata(PixelAstc* pixelAstc, size_t astcSize, const AstcMetadata& astcMetadata)
{
    bool cond = (pixelAstc == nullptr);
    CHECK_ERROR_RETURN_RET(cond, false);
    if (pixelAstc->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        Size desiredSize = { astcSize, 1 };
        MemoryData memoryData = { nullptr, astcSize, "CreatePixelMapForASTC Data", desiredSize,
                                  pixelAstc->GetPixelFormat() };
        memoryData.usage = pixelAstc->GetNoPaddingUsage();
        auto dstMemory = MemoryManager::CreateMemory(AllocatorType::DMA_ALLOC, memoryData);
        if (!dstMemory || dstMemory->data.data == nullptr) {
            IMAGE_LOGE("%{public}s CreateMemory failed", __func__);
            return false;
        }
        if (memcpy_s(dstMemory->data.data, astcSize, pixelAstc->GetPixels(), astcSize) != 0) {
            IMAGE_LOGE("%{public}s memcpy failed", __func__);
            dstMemory->Release();
            return false;
        }
        pixelAstc->SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data,
                                 dstMemory->data.size, dstMemory->GetType(), nullptr);
    }
    pixelAstc->SetAstcHdr(true);

    if (pixelAstc->IsHdr() && pixelAstc->GetFd() != nullptr) {
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
        sptr<SurfaceBuffer> dstBuffer(reinterpret_cast<SurfaceBuffer*>(pixelAstc->GetFd()));
        GSError ret = dstBuffer->SetMetadata(ATTRKEY_HDR_METADATA_TYPE, astcMetadata.hdrMetadataTypeVec);
        CHECK_ERROR_RETURN_RET_LOG(ret != GSERROR_OK, false, "%{public}s METADATA_TYPE set failed", __func__);
        ret = dstBuffer->SetMetadata(ATTRKEY_COLORSPACE_INFO, astcMetadata.colorSpaceInfoVec);
        CHECK_ERROR_RETURN_RET_LOG(ret != GSERROR_OK, false, "%{public}s COLORSPACE_INFO set failed", __func__);
        bool vpeRet = VpeUtils::SetSbStaticMetadata(dstBuffer, astcMetadata.staticData);
        CHECK_ERROR_RETURN_RET_LOG(!vpeRet, false, "%{public}s staticData set failed", __func__);
        vpeRet = VpeUtils::SetSbDynamicMetadata(dstBuffer, astcMetadata.dynamicData);
        CHECK_ERROR_RETURN_RET_LOG(!vpeRet, false, "%{public}s dynamicData set failed", __func__);
#endif
        return true;
    }
    return false;
}

static bool GetExtInfoForPixelAstc(AstcExtendInfo &extInfo, unique_ptr<PixelAstc> &pixelAstc, size_t astcSize)
{
    uint8_t colorSpace = 0;
    uint8_t pixelFmt = 0;
    AstcMetadata astcMetadata;

    for (uint8_t idx = 0; idx < extInfo.extendNums; idx++) {
        AstcExtendInfoType infoType = static_cast<AstcExtendInfoType>(extInfo.extendInfoType[idx]);
        uint8_t* infoValue =  extInfo.extendInfoValue[idx];
        uint32_t infoLength = extInfo.extendInfoLength[idx];

        if (infoValue == nullptr) {
            continue;
        }

        switch (infoType) {
            case AstcExtendInfoType::COLOR_SPACE:
                if (infoLength < 1) {
                    IMAGE_LOGE("GetExtInfoForPixelAstc COLOR_SPACE infoLength is 0");
                    return false;
                }
                colorSpace = *infoValue;
                break;
            case AstcExtendInfoType::PIXEL_FORMAT:
                if (infoLength < 1) {
                    IMAGE_LOGE("GetExtInfoForPixelAstc PIXEL_FORMAT infoLength is 0");
                    return false;
                }
                pixelFmt = *infoValue;
                break;
            case AstcExtendInfoType::HDR_METADATA_TYPE:
                // Additional fix (not migrated code): check HandleMetadataCopy return value
                // to avoid silently swallowing memcpy failures.
                if (!HandleMetadataCopy(astcMetadata.hdrMetadataTypeVec, infoValue, infoLength)) {
                    return false;
                }
                break;
            case AstcExtendInfoType::HDR_COLORSPACE_INFO:
                // Additional fix (not migrated code): same as above.
                if (!HandleMetadataCopy(astcMetadata.colorSpaceInfoVec, infoValue, infoLength)) {
                    return false;
                }
                break;
            case AstcExtendInfoType::HDR_STATIC_DATA:
                // Additional fix (not migrated code): same as above.
                if (!HandleMetadataCopy(astcMetadata.staticData, infoValue, infoLength)) {
                    return false;
                }
                break;
            case AstcExtendInfoType::HDR_DYNAMIC_DATA:
                // Additional fix (not migrated code): same as above.
                if (!HandleMetadataCopy(astcMetadata.dynamicData, infoValue, infoLength)) {
                    return false;
                }
                break;
            default:
                return false;
        }
    }
#ifdef IMAGE_COLORSPACE_FLAG
    ColorManager::ColorSpace grColorspace (static_cast<ColorManager::ColorSpaceName>(colorSpace));
    pixelAstc->InnerSetColorSpace(grColorspace, true);
#endif
    if (static_cast<PixelFormat>(pixelFmt) == PixelFormat::RGBA_1010102 &&
        !ProcessAstcMetadata(pixelAstc.get(), astcSize, astcMetadata)) {
        IMAGE_LOGE("GetExtInfoForPixelAstc ProcessAstcMetadata failed!");
        return false;
    }
    return true;
}

static bool CheckAstcExtInfoBytes(AstcExtendInfo &extInfo, size_t astcSize, size_t fileSize)
{
    if (extInfo.extendBufferSumBytes + astcSize + ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH != fileSize) {
        IMAGE_LOGE("CheckAstcExtInfoBytes extendBufferSumBytes is large than filesize");
        return false;
    }
    return true;
}

static bool ResolveExtInfo(const uint8_t *sourceFilePtr, size_t astcSize, size_t fileSize,
    unique_ptr<PixelAstc> &pixelAstc)
{
    uint8_t *extInfoBuf = const_cast<uint8_t*>(sourceFilePtr) + astcSize;
    /* */
    AstcExtendInfo extInfo = {0};
    bool invalidData = (astcSize + ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH >= fileSize) ||
        (memset_s(&extInfo, sizeof(AstcExtendInfo), 0, sizeof(AstcExtendInfo)) != 0);
    bool cond = invalidData;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "ResolveExtInfo file data is invalid!");
    extInfo.extendBufferSumBytes = GetDataSize(extInfoBuf);
    cond = !CheckAstcExtInfoBytes(extInfo, astcSize, fileSize);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "ResolveExtInfo file size is not equal to astc add ext bytes!");
    extInfoBuf += ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH;
    int32_t leftBytes = static_cast<int32_t>(extInfo.extendBufferSumBytes);
    for (uint8_t idx = 0; leftBytes > 0; idx++) {
        if (idx == ASTC_EXTEND_INFO_TLV_NUM6) {
            ReleaseExtendInfoMemory(extInfo);
            return false;
        }
        if (leftBytes < TLV_LEAST_BYTES) {
            ReleaseExtendInfoMemory(extInfo);
            return false;
        }
        extInfo.extendInfoType[idx] = *extInfoBuf++; // type
        leftBytes--;
        uint32_t expendInfoBytesUnSign = GetDataSize(extInfoBuf);
        extInfoBuf += sizeof(uint32_t);
        leftBytes -= sizeof(uint32_t);
        if (expendInfoBytesUnSign > MAX_INT32 || static_cast<uint32_t>(leftBytes) < expendInfoBytesUnSign) {
            ReleaseExtendInfoMemory(extInfo);
            return false;
        }
        extInfo.extendInfoLength[idx] = expendInfoBytesUnSign;
        extInfo.extendInfoValue[idx] = static_cast<uint8_t *>(malloc(extInfo.extendInfoLength[idx]));
        if (extInfo.extendInfoValue[idx] == nullptr) {
            ReleaseExtendInfoMemory(extInfo);
            return false;
        }
        if (memcpy_s(extInfo.extendInfoValue[idx], extInfo.extendInfoLength[idx], extInfoBuf,
            extInfo.extendInfoLength[idx]) != 0) {
            free(extInfo.extendInfoValue[idx]);
            extInfo.extendInfoValue[idx] = nullptr;
            ReleaseExtendInfoMemory(extInfo);
            return false;
        }
        extInfoBuf += expendInfoBytesUnSign;
        leftBytes -= static_cast<int32_t>(expendInfoBytesUnSign);
        extInfo.extendNums++;
    }
    if (leftBytes != 0) {
        ReleaseExtendInfoMemory(extInfo);
        return false;
    }
    // Additional fix (not migrated code): previously the GetExtInfoForPixelAstc failure was
    // ignored and true was still returned; now propagate the failure to avoid silently
    // swallowing HDR/colorspace metadata parse failures.
    if (!GetExtInfoForPixelAstc(extInfo, pixelAstc, astcSize)) {
        IMAGE_LOGE("ResolveExtInfo Could not get ext info!");
        ReleaseExtendInfoMemory(extInfo);
        return false;
    }
    ReleaseExtendInfoMemory(extInfo);
    return true;
}

#ifdef SUT_DECODE_ENABLE
static bool FormatIsSUT(const uint8_t *fileData, size_t fileSize)
{
    if (fileData == nullptr || fileSize < SUT_HEAD_BYTES) {
        IMAGE_LOGE("FormatIsSUT fileData incorrect.");
        return false;
    }
    uint32_t magicVal = static_cast<uint32_t>(fileData[NUM_0]) +
        (static_cast<uint32_t>(fileData[NUM_1]) << NUM_8) +
        (static_cast<uint32_t>(fileData[NUM_2]) << NUM_16) +
        (static_cast<uint32_t>(fileData[NUM_3]) << NUM_24);
    return magicVal == SUT_FILE_SIGNATURE;
}
#endif

#if !defined(CROSS_PLATFORM)
AllocatorType CalculateAllocatorType(const AllocatorType& optAllocatorType, const Size& size, uint64_t& usage)
{
    if (optAllocatorType != AllocatorType::DEFAULT) {
        return optAllocatorType;
    }

    const int64_t area = static_cast<int64_t>(size.width) * size.height;
    if (ImageSystemProperties::GetAstcEnabled() && area >= ASTC_SIZE) {
        return AllocatorType::DMA_ALLOC;
    }

    if (ImageSystemProperties::GetAstcEnabled() && ImageSystemProperties::GetDefaultDmaNoPaddingEnabled() &&
        ImageSystemProperties::GetNoPaddingEnabled()) {
        usage |= BUFFER_USAGE_PREFER_NO_PADDING | BUFFER_USAGE_ALLOC_NO_IPC;
        return AllocatorType::DMA_ALLOC;
    }
    return AllocatorType::SHARE_MEM_ALLOC;
}
#endif

static bool ReadFileAndResoveAstc(size_t fileSize, size_t astcSize, unique_ptr<PixelAstc> &pixelAstc,
    const uint8_t *sourceFilePtr, const DecodeOptions &opts)
{
#if !(defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM))
    Size desiredSize = {astcSize, 1};
    MemoryData memoryData = {nullptr, astcSize, "CreatePixelMapForASTC Data", desiredSize, pixelAstc->GetPixelFormat()};
    ImageInfo pixelAstcInfo;
    pixelAstc->GetImageInfo(pixelAstcInfo);
    AllocatorType allocatorType = CalculateAllocatorType(opts.allocatorType, pixelAstcInfo.size, memoryData.usage);
    std::unique_ptr<AbsMemory> dstMemory = MemoryManager::CreateMemory(allocatorType, memoryData);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("ReadFileAndResoveAstc CreateMemory failed");
        return false;
    }
    pixelAstc->SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data, dstMemory->data.size, dstMemory->GetType(),
        nullptr);
    bool successMemCpyOrDec = true;
#ifdef SUT_DECODE_ENABLE
    if (FormatIsSUT(sourceFilePtr, fileSize)) {
        successMemCpyOrDec = TextureSuperCompressDecode(sourceFilePtr, fileSize,
            static_cast<uint8_t *>(dstMemory->data.data), astcSize, pixelAstc);
        IMAGE_LOGD("ReadFileAndResoveAstc colorspace %{public}d",
            pixelAstc->InnerGetGrColorSpace().GetColorSpaceName());
    } else {
#endif
        if (memcpy_s(dstMemory->data.data, astcSize, sourceFilePtr, astcSize) != 0) {
            IMAGE_LOGE("[ImageSource] astc memcpy_s failed!");
            successMemCpyOrDec = false;
        }
        successMemCpyOrDec = successMemCpyOrDec && ((fileSize == astcSize) ||
            ((fileSize > astcSize) && ResolveExtInfo(sourceFilePtr, astcSize, fileSize, pixelAstc)));
#ifdef SUT_DECODE_ENABLE
    }
#endif
    if (!successMemCpyOrDec) {
        return false;
    }
#endif
    return true;
}

unique_ptr<PixelMap> ImageSource::CreatePixelMapForASTC(uint32_t &errorCode, const DecodeOptions &opts)
#if defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
{
    errorCode = ERROR;
    return nullptr;
}
#else
{
    ImageTrace imageTrace("CreatePixelMapForASTC");
    unique_ptr<PixelAstc> pixelAstc = make_unique<PixelAstc>();
    ImageInfo info;
    if (!sourceStreamPtr_) {
        IMAGE_LOGE("[ImageSource] CreatePixelMapForASTC sourceStreamPtr_ is null.");
        errorCode = ERR_IMAGE_DATA_ABNORMAL;
        return nullptr;
    }
    uint8_t *sourceFilePtr = sourceStreamPtr_->GetDataPtr();
    if (sourceFilePtr == nullptr) {
        IMAGE_LOGE("[ImageSource] CreatePixelMapForASTC sourceFilePtr is null.");
        errorCode = ERR_IMAGE_DATA_ABNORMAL;
        return nullptr;
    }
    if (!GetImageInfoForASTC(info, sourceFilePtr)) {
        IMAGE_LOGE("[ImageSource] get astc image info failed.");
        return nullptr;
    }
    errorCode = pixelAstc->SetImageInfo(info);
    pixelAstc->SetAstcRealSize(info.size);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]update pixelmap info error ret:%{public}u.", errorCode);
        return nullptr;
    }
    pixelAstc->SetEditable(false);
    size_t fileSize = sourceStreamPtr_->GetStreamSize();
    bool isSUT = false;
#ifdef SUT_DECODE_ENABLE
    isSUT = FormatIsSUT(sourceFilePtr, fileSize);
    size_t astcSize = !isSUT ?
        ImageUtils::GetAstcBytesCount(info) : GetAstcSizeBytes(sourceFilePtr, fileSize);
    if (astcSize == 0) {
        IMAGE_LOGE("[ImageSource] astc GetAstcSizeBytes failed.");
        return nullptr;
    }
#else
    size_t astcSize = ImageUtils::GetAstcBytesCount(info);
#endif
    if (!isSUT && astcSize > fileSize) {
        IMAGE_LOGE("[ImageSource] astcSize > fileSize.");
        return nullptr;
    }
    if (!ReadFileAndResoveAstc(fileSize, astcSize, pixelAstc, sourceFilePtr, opts)) {
        IMAGE_LOGE("[ImageSource] astc ReadFileAndResoveAstc failed.");
        return nullptr;
    }
    pixelAstc->SetAstc(true);
    ImageUtils::FlushSurfaceBuffer(pixelAstc.get());
    return pixelAstc;
}
#endif

bool ImageSource::GetASTCInfo(const uint8_t *fileData, size_t fileSize, ASTCInfo &astcInfo)
{
    bool cond = (fileData == nullptr) || (fileSize < ASTC_HEADER_SIZE);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[ImageSource]IsASTC fileData incorrect.");
    uint32_t magicVal = static_cast<uint32_t>(fileData[NUM_0]) +
        (static_cast<uint32_t>(fileData[NUM_1]) << NUM_8) +
        (static_cast<uint32_t>(fileData[NUM_2]) << NUM_16) +
        (static_cast<uint32_t>(fileData[NUM_3]) << NUM_24);
    if (magicVal == ASTC_MAGIC_ID) {
        unsigned int astcWidth = static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_X]) +
            (static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_X + 1]) << NUM_8) +
            (static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_X + NUM_2]) << NUM_16);
        unsigned int astcHeight = static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_Y]) +
            (static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_Y + 1]) << NUM_8) +
            (static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_Y + NUM_2]) << NUM_16);
        astcInfo.size.width = static_cast<int32_t>(astcWidth);
        astcInfo.size.height = static_cast<int32_t>(astcHeight);
        astcInfo.blockFootprint.width = fileData[ASTC_HEADER_BLOCK_X];
        astcInfo.blockFootprint.height = fileData[ASTC_HEADER_BLOCK_Y];
        if (astcInfo.blockFootprint.width != astcInfo.blockFootprint.height) {
            IMAGE_LOGE("[ImageSource]GetASTCInfo blockFootprint failed");
            return false;
        }
        return true;
    }
#ifdef SUT_DECODE_ENABLE
    if (!g_sutDecSoManager.LoadSutDecSo() || g_sutDecSoManager.getTextureInfoFunc_ == nullptr) {
        IMAGE_LOGE("[ImageSource] SUT dec so dlopen failed or getTextureInfoFunc_ is nullptr!");
        return false;
    }
    uint32_t blockXY;
    uint32_t width;
    uint32_t height;
    if (g_sutDecSoManager.getTextureInfoFunc_(fileData, fileSize,
        width, height, blockXY)) {
        astcInfo.size.width = width;
        astcInfo.size.height = height;
        astcInfo.blockFootprint.width = blockXY;
        astcInfo.blockFootprint.height = blockXY;
        return true;
    }
#endif
    return false;
}

bool ImageSource::IsSupportGenAstc()
{
    return ImageSystemProperties::GetMediaLibraryAstcEnabled();
}

bool ImageSource::CompressToAstcFromPixelmap(const DecodeOptions &opts, unique_ptr<PixelMap> &rgbaPixelmap,
    unique_ptr<AbsMemory> &dstMemory)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    ImageInfo rgbaInfo;
    rgbaPixelmap->GetImageInfo(rgbaInfo);
    rgbaInfo.pixelFormat = PixelFormat::ASTC_4x4;
    size_t allocMemSize = ImageUtils::GetAstcBytesCount(rgbaInfo) + ASTC_TLV_SIZE;

    OHOS::Media::ImagePacker imagePacker;
    OHOS::Media::PackOption option;
    option.format = "image/sdr_astc_4x4";
    option.quality = ASTC_OPTION_QUALITY;

    Size desiredSize = {allocMemSize, 1};
    MemoryData memoryData = {nullptr, allocMemSize, "CompressToAstcFromPixelmap Data", desiredSize,
        opts.desiredPixelFormat};
    AllocatorType allocatorType = CalculateAllocatorType(opts.allocatorType, rgbaInfo.size, memoryData.usage);
    dstMemory = MemoryManager::CreateMemory(allocatorType, memoryData);
    bool cond = (dstMemory == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "CompressToAstcFromPixelmap CreateMemory failed");

    uint32_t ret = imagePacker.StartPacking(reinterpret_cast<uint8_t *>(dstMemory->data.data), allocMemSize, option);
    if (ret != 0) {
        IMAGE_LOGE("CompressToAstcFromPixelmap failed to start packing");
        dstMemory->Release();
        dstMemory = nullptr;
        return false;
    }
    ret = imagePacker.AddImage(*(rgbaPixelmap.get()));
    if (ret != 0) {
        IMAGE_LOGE("CompressToAstcFromPixelmap failed to add image");
        dstMemory->Release();
        dstMemory = nullptr;
        return false;
    }
    int64_t packedSize = 0;
    ret = imagePacker.FinalizePacking(packedSize);
    if (ret != 0) {
        IMAGE_LOGE("CompressToAstcFromPixelmap failed to finalize packing");
        dstMemory->Release();
        dstMemory = nullptr;
        return false;
    }
    return true;
#else
    return false;
#endif
}

unique_ptr<PixelMap> ImageSource::CreatePixelAstcFromImageFile(uint32_t index, const DecodeOptions &opts,
    uint32_t &errorCode)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    ImageInfo originInfo;
    uint32_t ret = GetImageInfo(originInfo);
    bool cond = (ret != SUCCESS);
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "CreatePixelAstcFromImageFile GetImageInfo failed");
    cond = ((originInfo.size.width > ASTC_MAX_SIZE || originInfo.size.height > ASTC_MAX_SIZE) ||
        (opts.desiredSize.width > ASTC_MAX_SIZE || opts.desiredSize.height > ASTC_MAX_SIZE));
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "CreatePixelAstcFromImageFile imageInfo size is too large");
    DecodeOptions modifiableOpts = opts;
    modifiableOpts.desiredPixelFormat = PixelFormat::RGBA_8888;
    unique_ptr<PixelMap> rgbaPixelmap = CreatePixelMap(index, modifiableOpts, errorCode);
    cond = (rgbaPixelmap == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "CreatePixelAstcFromImageFile pixelMap is nullptr");
    unique_ptr<AbsMemory> dstMemory = nullptr;
    cond = CompressToAstcFromPixelmap(opts, rgbaPixelmap, dstMemory);
    CHECK_ERROR_RETURN_RET_LOG(!cond, nullptr, "CreatePixelAstcFromImageFile CompressToAstcFromPixelmap failed");
    unique_ptr<PixelAstc> dstPixelAstc = make_unique<PixelAstc>();
    ImageInfo info;
    cond = GetImageInfoForASTC(info, reinterpret_cast<uint8_t *>(dstMemory->data.data));
    // Additional fix (not migrated code): release dstMemory before early return. The AbsMemory
    // destructor does not call Release(), so without this the compressed ASTC buffer and its
    // ashmem fd / SurfaceBuffer reference leak on this error path.
    if (!cond) {
        IMAGE_LOGE("CreatePixelAstcFromImageFile get astc image info failed.");
        dstMemory->Release();
        return nullptr;
    }
    ret = dstPixelAstc->SetImageInfo(info);
    dstPixelAstc->SetAstcRealSize(info.size);
    // Additional fix (not migrated code): same as above, release dstMemory before early return.
    if (ret != SUCCESS) {
        IMAGE_LOGE("CreatePixelAstcFromImageFile update pixelmap info error ret:%{public}u.", ret);
        dstMemory->Release();
        return nullptr;
    }
    dstPixelAstc->SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data, dstMemory->data.size,
        dstMemory->GetType(), nullptr);
    dstPixelAstc->SetAstc(true);
    dstPixelAstc->SetEditable(false);

    size_t realSize = ImageUtils::GetAstcBytesCount(info);
    Size desiredSize = {realSize, 1};
    MemoryData memoryData = {nullptr, realSize, "CompressToAstcFromPixelmap Data", desiredSize,
        dstPixelAstc->GetPixelFormat()};
    dstMemory = MemoryManager::CreateMemory(dstMemory->GetType(), memoryData);
    CHECK_ERROR_RETURN_RET_LOG(dstMemory == nullptr, nullptr, "CompressToAstcFromPixelmap Dst Memory Create failed");
    if (memcpy_s(dstMemory->data.data, realSize, dstPixelAstc->GetPixels(), realSize) != 0) {
        IMAGE_LOGE("CreatePixelAstcFromImageFile copy memory fail, size %{public}zu", realSize);
        dstMemory->Release();
        return nullptr;
    }
    dstPixelAstc->SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data, dstMemory->data.size,
        dstMemory->GetType(), nullptr);

    ImageUtils::FlushSurfaceBuffer(dstPixelAstc.get());
    return dstPixelAstc;
#else
    return nullptr;
#endif
}
} // namespace Media
} // namespace OHOS
