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

#include <charconv>
#include <dlfcn.h>
#ifdef USE_M133_SKIA
#include <unistd.h>
#endif

#include "astc_codec.h"
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
#include "image_compressor.h"
#endif
#include "image_log.h"
#include "image_trace.h"
#include "image_system_properties.h"
#include "image_trace.h"
#include "securec.h"
#include "media_errors.h"
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "v1_0/buffer_handle_meta_key_type.h"
#include "vpe_utils.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "AstcCodec"

namespace OHOS {
namespace ImagePlugin {
using namespace Media;
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;
#endif
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
using namespace AstcEncBasedCl;
#endif
constexpr uint8_t TEXTURE_HEAD_BYTES = 16;
constexpr uint8_t ASTC_MASK = 0xFF;
constexpr uint8_t ASTC_NUM_4 = 4;   // represents ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH
constexpr uint8_t ASTC_NUM_8 = 8;
constexpr uint8_t ASTC_HEADER_SIZE = 16;
constexpr uint8_t ASTC_NUM_24 = 24;
static const uint32_t ASTC_MAGIC_ID = 0x5CA1AB13;
constexpr uint8_t DEFAULT_DIM = 4;
constexpr uint8_t MAX_DIM = 12;
constexpr uint8_t HIGH_SPEED_PROFILE_MAP_QUALITY = 20; // quality level is 20 for thumbnail
constexpr uint8_t RGBA_BYTES_PIXEL_LOG2 = 2;
constexpr uint8_t MASKBITS_FOR_8BITS = 255;
constexpr uint8_t UINT32_1TH_BYTES = 8;
constexpr uint8_t UINT32_2TH_BYTES = 16;
constexpr uint8_t UINT32_3TH_BYTES = 24;
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
constexpr int32_t WIDTH_CL_THRESHOLD = 256;
constexpr int32_t HEIGHT_CL_THRESHOLD = 256;
#endif
constexpr int32_t WIDTH_MAX_ASTC = 8192;
constexpr int32_t HEIGHT_MAX_ASTC = 8192;

#ifdef SUT_ENCODE_ENABLE
static bool CheckClBinIsExist(const std::string &name)
{
    return (access(name.c_str(), F_OK) != -1); // -1 means that the file is  not exist
}
#endif
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
static bool CheckClBinIsExistWithLock(const std::string &name)
{
    std::lock_guard<std::mutex> lock(checkClBinPathMutex);
    return (access(name.c_str(), F_OK) != -1); // -1 means that the file is  not exist
}
#endif

struct AstcEncCheckInfo {
    uint32_t pixmapInSize = 0;
    uint32_t astcBufferSize = 0;
    uint32_t extendInfoSize = 0;
    uint32_t extendBufferSize = 0;
    PixelFormat pixmapFormat = PixelFormat::UNKNOWN;
};

#ifdef SUT_ENCODE_ENABLE
constexpr uint8_t EXPAND_ASTC_INFO_MAX_ENC = 16;
constexpr int32_t EXPAND_SIZE_BYTES_ENC = 4;

struct AstcInInfo {
    const uint8_t* astcBuf;
    int32_t astcBytes;
    uint8_t expandNums;
    uint8_t expandInfoType[EXPAND_ASTC_INFO_MAX_ENC];
    int32_t expandInfoBytes[EXPAND_ASTC_INFO_MAX_ENC];
    uint8_t* expandInfoBuf[EXPAND_ASTC_INFO_MAX_ENC];
};
struct SutOutInfo {
    uint8_t* sutBuf;
    int32_t sutCapacity;
    int32_t sutBytes;
};
#ifdef SUT_PATH_X64
static const std::string g_textureSuperEncSo = "/system/lib64/module/hms/graphic/libtextureSuperCompress.z.so";
#else
static const std::string g_textureSuperEncSo = "/system/lib/module/hms/graphic/libtextureSuperCompress.z.so";
#endif
using SuperCompressTexture = bool (*)(const AstcInInfo&, SutOutInfo&, uint32_t);
class SutEncSoManager {
public:
    SutEncSoManager();
    ~SutEncSoManager();
    bool LoadSutEncSo();
    SuperCompressTexture sutEncSoEncFunc_;
private:
    bool sutEncSoOpened_;
    void *textureEncSoHandle_;
    std::mutex sutEncSoMutex_ = {};
};

static SutEncSoManager g_sutEncSoManager;

SutEncSoManager::SutEncSoManager()
{
    sutEncSoOpened_ = false;
    textureEncSoHandle_ = nullptr;
    sutEncSoEncFunc_ = nullptr;
}

SutEncSoManager::~SutEncSoManager()
{
    bool sutEncHasBeenOpen = sutEncSoOpened_ && (textureEncSoHandle_ != nullptr);
    if (sutEncHasBeenOpen) {
        int ret = dlclose(textureEncSoHandle_);
        IMAGE_LOGD("astcenc dlcose ret: %{public}d %{public}s!", ret, g_textureSuperEncSo.c_str());
    }
}

bool SutEncSoManager::LoadSutEncSo()
{
    std::lock_guard<std::mutex> lock(sutEncSoMutex_);
    if (!sutEncSoOpened_) {
        if (!CheckClBinIsExist(g_textureSuperEncSo)) {
            IMAGE_LOGE("sut %{public}s! is not found", g_textureSuperEncSo.c_str());
            return false;
        }
        textureEncSoHandle_ = dlopen(g_textureSuperEncSo.c_str(), 1);
        if (textureEncSoHandle_ == nullptr) {
            IMAGE_LOGE("sut libtextureSuperCompress dlopen failed!");
            return false;
        }
        sutEncSoEncFunc_ =
            reinterpret_cast<SuperCompressTexture>(dlsym(textureEncSoHandle_, "SuperCompressTextureTlv"));
        if (sutEncSoEncFunc_ == nullptr) {
            IMAGE_LOGE("sut libtextureSuperCompress dlsym failed!");
            dlclose(textureEncSoHandle_);
            textureEncSoHandle_ = nullptr;
            return false;
        }
        IMAGE_LOGD("astcenc dlopen success: %{public}s!", g_textureSuperEncSo.c_str());
        sutEncSoOpened_ = true;
    }
    return true;
}
#endif

uint32_t AstcCodec::SetAstcEncode(OutputDataStream* outputStream, PlEncodeOptions &option, Media::PixelMap* pixelMap)
{
    if (outputStream == nullptr || pixelMap == nullptr) {
        IMAGE_LOGE("input data is nullptr.");
        return ERROR;
    }
    astcOutput_ = outputStream;
    astcOpts_ = option;
    astcPixelMap_ = pixelMap;
    return SUCCESS;
}

// test ASTCEncoder
uint32_t GenAstcHeader(uint8_t *header, astcenc_image img, TextureEncodeOptions &encodeParams)
{
    uint8_t *tmp = header;
    *tmp++ = ASTC_MAGIC_ID & ASTC_MASK;
    *tmp++ = (ASTC_MAGIC_ID >> ASTC_NUM_8) & ASTC_MASK;
    *tmp++ = (ASTC_MAGIC_ID >> ASTC_HEADER_SIZE) & ASTC_MASK;
    *tmp++ = (ASTC_MAGIC_ID >> ASTC_NUM_24) & ASTC_MASK;
    *tmp++ = static_cast<uint8_t>(encodeParams.blockX_);
    *tmp++ = static_cast<uint8_t>(encodeParams.blockY_);
    *tmp++ = 1;
    *tmp++ = img.dim_x & ASTC_MASK;
    *tmp++ = (img.dim_x >> ASTC_NUM_8) & ASTC_MASK;
    *tmp++ = (img.dim_x >> ASTC_HEADER_SIZE) & ASTC_MASK;
    *tmp++ = img.dim_y & ASTC_MASK;
    *tmp++ = (img.dim_y >> ASTC_NUM_8) & ASTC_MASK;
    *tmp++ = (img.dim_y >> ASTC_HEADER_SIZE) & ASTC_MASK;
    *tmp++ = img.dim_z & ASTC_MASK;
    *tmp++ = (img.dim_z >> ASTC_NUM_8) & ASTC_MASK;
    *tmp++ = (img.dim_z >> ASTC_HEADER_SIZE) & ASTC_MASK;
    return SUCCESS;
}

uint32_t InitAstcencConfig(AstcEncoder* work, TextureEncodeOptions* option)
{
    bool invaildInput = (work == nullptr) || (option == nullptr);
    if (invaildInput) {
        IMAGE_LOGE("astc input work or option is nullptr.");
        return ERROR;
    }
    unsigned int blockX = option->blockX_;
    unsigned int blockY = option->blockY_;
    unsigned int blockZ = 1;

    float quality = ASTCENC_PRE_FAST;
    unsigned int flags = ASTCENC_FLG_SELF_DECOMPRESS_ONLY;
    astcenc_error status = astcenc_config_init(work->profile, blockX, blockY,
        blockZ, quality, flags, &work->config);
    if (status != ASTCENC_SUCCESS) {
        IMAGE_LOGE("ERROR: astcenc_config_init failed, status %{public}d", status);
        return ERROR;
    }
    work->config.privateProfile = option->privateProfile_;
    if (work->config.privateProfile == HIGH_SPEED_PROFILE) {
        work->config.tune_refinement_limit = 1;
        work->config.tune_candidate_limit = 1;
        work->config.tune_partition_count_limit = 1;
    }
    if (astcenc_context_alloc(&work->config, 1, &work->codec_context) != ASTCENC_SUCCESS) {
        return ERROR;
    }
    return SUCCESS;
}

void extractDimensions(std::string &format, TextureEncodeOptions &param)
{
    param.blockX_ = DEFAULT_DIM;
    param.blockY_ = DEFAULT_DIM;
    std::size_t slashPos = format.rfind('/');
    if (slashPos != std::string::npos) {
        std::string dimensions = format.substr(slashPos + 1);
        std::size_t starPos = dimensions.find('*');
        if (starPos != std::string::npos) {
            std::string widthStr = dimensions.substr(0, starPos);
            std::string heightStr = dimensions.substr(starPos + 1);

            auto ret_x = std::from_chars(widthStr.data(), widthStr.data() + widthStr.size(), param.blockX_);
            auto ret_y = std::from_chars(heightStr.data(), heightStr.data() + heightStr.size(), param.blockY_);
            if (!(ret_x.ec == std::errc() && ret_y.ec == std::errc())) {
                IMAGE_LOGE("Failed to convert string to number");
            }
        }
    }
}

#if defined(QUALITY_CONTROL) && (QUALITY_CONTROL == 1)
constexpr double MAX_PSNR = 99.9;
constexpr double MAX_VALUE = 255;
constexpr double THRESHOLD_R = 30.0;
constexpr double THRESHOLD_G = 30.0;
constexpr double THRESHOLD_B = 30.0;
constexpr double THRESHOLD_A = 30.0;
constexpr double THRESHOLD_RGB = 30.0;
constexpr double LOG_BASE = 10.0;
bool CheckQuality(int32_t *mseIn[RGBA_COM], int blockNum, int blockXYZ)
{
    double psnr[RGBA_COM + 1];
    const double threshold[RGBA_COM + 1] = {THRESHOLD_R, THRESHOLD_G, THRESHOLD_B, THRESHOLD_A, THRESHOLD_RGB};
    uint64_t mseTotal[RGBA_COM + 1] = {0, 0, 0, 0, 0};
    for (int i = R_COM; i < RGBA_COM; i++) {
        int32_t *mse = mseIn[i];
        if (!mse) {
            return false;
        }
        for (int j = 0; j < blockNum; j++) {
            mseTotal[i] += *mse;
            if (i != A_COM) mseTotal[RGBA_COM] += *mse;
            mse++;
        }
    }
    for (int i = R_COM; i < RGBA_COM; i++) {
        if (mseTotal[i] == 0) {
            psnr[i] = MAX_PSNR;
            continue;
        }
        double mseRgb = static_cast<double>(mseTotal[i] / static_cast<uint64_t>((blockNum * blockXYZ)));
        psnr[i] = LOG_BASE * log(static_cast<double>(MAX_VALUE * MAX_VALUE) / mseRgb) / log(LOG_BASE);
    }
    if (mseTotal[RGBA_COM] == 0) {
        psnr[RGBA_COM] = MAX_PSNR;
    } else {
        double mseRgb = static_cast<double>(
            mseTotal[RGBA_COM] / static_cast<uint64_t>((blockNum * blockXYZ * (RGBA_COM - 1))));
        psnr[RGBA_COM] = LOG_BASE * log(static_cast<double>(MAX_VALUE * MAX_VALUE) / mseRgb) / log(LOG_BASE);
    }
    IMAGE_LOGD("astc psnr r%{public}f g%{public}f b%{public}f a%{public}f rgb%{public}f",
        psnr[R_COM], psnr[G_COM], psnr[B_COM], psnr[A_COM],
        psnr[RGBA_COM]);
    return (psnr[R_COM] > threshold[R_COM]) && (psnr[G_COM] > threshold[G_COM])
        && (psnr[B_COM] > threshold[B_COM]) && (psnr[A_COM] > threshold[A_COM])
        && (psnr[RGBA_COM] > threshold[RGBA_COM]);
}
#endif

static void FreeMem(AstcEncoder *work)
{
    if (!work) {
        return;
    }
#if defined(QUALITY_CONTROL) && (QUALITY_CONTROL == 1)
    if (work->calQualityEnable) {
        for (int i = R_COM; i < RGBA_COM; i++) {
            if (work->mse[i]) {
                free(work->mse[i]);
                work->mse[i] = nullptr;
            }
        }
    }
#endif
    if (work->image_.data) {
        free(work->image_.data);
        work->image_.data = nullptr;
    }
    if (work->codec_context != nullptr) {
        astcenc_context_free(work->codec_context);
        work->codec_context = nullptr;
    }
    work->data_out_ = nullptr;
}

static bool InitMem(AstcEncoder *work, TextureEncodeOptions param)
{
    if (!work) {
        return false;
    }
    work->swizzle_ = {ASTCENC_SWZ_R, ASTCENC_SWZ_G, ASTCENC_SWZ_B, ASTCENC_SWZ_A};
    work->image_.dim_x = static_cast<unsigned int>(param.width_);
    work->image_.dim_y = static_cast<unsigned int>(param.height_);
    work->image_.dim_z = 1;
    if (param.privateProfile_ == HIGH_SPEED_PROFILE_HIGHBITS) {
        work->image_.data_type = ASTCENC_TYPE_RGBA1010102;
    } else {
        work->image_.data_type = ASTCENC_TYPE_U8;
    }
    work->image_.dim_stride = static_cast<unsigned int>(param.stride_);
    work->codec_context = nullptr;
    work->image_.data = nullptr;
    work->profile = ASTCENC_PRF_LDR_SRGB;
#if defined(QUALITY_CONTROL) && (QUALITY_CONTROL == 1)
    work->mse[R_COM] = work->mse[G_COM] = work->mse[B_COM] = work->mse[A_COM] = nullptr;
    work->calQualityEnable = param.enableQualityCheck;
    if (param.blocksNum <= 0) {
        IMAGE_LOGE("[AstcCodec] InitMem blocksNum is invalid");
        return false;
    }
    if (work->calQualityEnable) {
        for (int i = R_COM; i < RGBA_COM; i++) {
            work->mse[i] = static_cast<int32_t *>(calloc(param.blocksNum, sizeof(int32_t)));
            if (!work->mse[i]) {
                IMAGE_LOGE("quality control calloc failed");
                return false;
            }
        }
    }
#endif
    work->image_.data = static_cast<void **>(malloc(sizeof(void*) * work->image_.dim_z));
    if (!work->image_.data) {
        return false;
    }
    return true;
}

bool AstcCodec::AstcSoftwareEncodeCore(TextureEncodeOptions &param, uint8_t *pixmapIn, uint8_t *astcBuffer)
{
    if ((pixmapIn == nullptr) || (astcBuffer == nullptr)) {
        IMAGE_LOGE("pixmapIn or astcBuffer is nullptr");
        return false;
    }
    AstcEncoder work;
    if (!InitMem(&work, param)) {
        FreeMem(&work);
        return false;
    }
    if (InitAstcencConfig(&work, &param) != SUCCESS) {
        IMAGE_LOGE("astc InitAstcencConfig failed");
        FreeMem(&work);
        return false;
    }
    work.image_.data[0] = pixmapIn;
    work.data_out_ = astcBuffer;
    if (GenAstcHeader(work.data_out_, work.image_, param) != SUCCESS) {
        IMAGE_LOGE("astc GenAstcHeader failed");
        FreeMem(&work);
        return false;
    }
    work.error_ = astcenc_compress_image(work.codec_context, &work.image_, &work.swizzle_,
        work.data_out_ + TEXTURE_HEAD_BYTES, param.astcBytes - TEXTURE_HEAD_BYTES,
#if defined(QUALITY_CONTROL) && (QUALITY_CONTROL == 1)
        work.calQualityEnable, work.mse,
#endif
        0);
#if defined(QUALITY_CONTROL) && (QUALITY_CONTROL == 1)
    if ((ASTCENC_SUCCESS != work.error_) ||
        (work.calQualityEnable && !CheckQuality(work.mse, param.blocksNum, param.blockX_ * param.blockY_))) {
#else
    if (ASTCENC_SUCCESS != work.error_) {
#endif
        IMAGE_LOGE("astc compress failed");
        FreeMem(&work);
        return false;
    }
    FreeMem(&work);
    return true;
}

static QualityProfile GetAstcQuality(int32_t quality)
{
    QualityProfile privateProfile;
    switch (quality) {
        case HIGH_SPEED_PROFILE_MAP_QUALITY:
            privateProfile = HIGH_SPEED_PROFILE;
            break;
        default:
            privateProfile = HIGH_QUALITY_PROFILE;
            break;
    }
    return privateProfile;
}

#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
bool AstcCodec::TryAstcEncBasedOnCl(TextureEncodeOptions &param, uint8_t *inData,
    uint8_t *buffer, const std::string &clBinPath)
{
    ClAstcHandle *astcClEncoder = nullptr;
    bool invalidPara = (inData == nullptr) || (buffer == nullptr);
    if (invalidPara) {
        IMAGE_LOGE("astc Please check TryAstcEncBasedOnCl input!");
        return false;
    }
    if (AstcClCreate(&astcClEncoder, clBinPath) != CL_ASTC_ENC_SUCCESS) {
        IMAGE_LOGE("astc AstcClCreate failed!");
        return false;
    }
    ClAstcImageOption imageIn;
    if (AstcClFillImage(&imageIn, inData, param.stride_, param.width_, param.height_) != CL_ASTC_ENC_SUCCESS) {
        IMAGE_LOGE("astc AstcClFillImage failed!");
        AstcClClose(astcClEncoder);
        return false;
    }
    if (AstcClEncImage(astcClEncoder, &imageIn, buffer) != CL_ASTC_ENC_SUCCESS) {
        IMAGE_LOGE("astc AstcClEncImage failed!");
        AstcClClose(astcClEncoder);
        return false;
    }
    if (AstcClClose(astcClEncoder) != CL_ASTC_ENC_SUCCESS) {
        IMAGE_LOGE("astc AstcClClose failed!");
        return false;
    }
    return true;
}
#endif

#ifdef SUT_ENCODE_ENABLE
static bool FillAstcSutInfo(AstcInInfo &astcInfo, SutOutInfo &sutInfo, TextureEncodeOptions &param,
    uint8_t *astcBuffer)
{
    astcInfo.astcBuf = astcBuffer;
    astcInfo.astcBytes = param.astcBytes;
    astcInfo.expandNums = param.expandNums;
    int32_t expandTotalBytes = 0;
    for (uint8_t idx = 0; idx < astcInfo.expandNums; idx++) {
        astcInfo.expandInfoType[idx] = idx;
        astcInfo.expandInfoBytes[idx] = param.extInfoBytes;
        astcInfo.expandInfoBuf[idx] = param.extInfoBuf;
        expandTotalBytes += sizeof(uint8_t) + sizeof(int32_t) + param.extInfoBytes;
    }
    sutInfo.sutCapacity = astcInfo.astcBytes + EXPAND_SIZE_BYTES_ENC + expandTotalBytes;
    sutInfo.sutBuf = static_cast<uint8_t *>(malloc(sutInfo.sutCapacity));
    if (sutInfo.sutBuf == nullptr) {
        IMAGE_LOGD("astcenc sutInfo.sutBuf malloc failed!");
        return false;
    }
    return true;
}

static bool SutEncode(TextureEncodeOptions &param, uint8_t *astcBuffer)
{
    bool invalidSutEnc = !g_sutEncSoManager.LoadSutEncSo() || g_sutEncSoManager.sutEncSoEncFunc_ == nullptr;
    if (invalidSutEnc) {
        IMAGE_LOGE("sut enc so dlopen failed or sutEncSoEncFunc_ is nullptr!");
        param.sutProfile = SutProfile::SKIP_SUT;
        return true;
    }
    AstcInInfo astcInfo = {0};
    SutOutInfo sutInfo = {0};
    int32_t ret = memset_s(&astcInfo, sizeof(AstcInInfo), 0, sizeof(AstcInInfo));
    if (ret != 0) {
        IMAGE_LOGE("AstcInInfo memset failed!");
        return false;
    }
    ret = memset_s(&sutInfo, sizeof(SutOutInfo), 0, sizeof(SutOutInfo));
    if (ret != 0) {
        IMAGE_LOGE("SutOutInfo memset failed!");
        return false;
    }
    
    if (!FillAstcSutInfo(astcInfo, sutInfo, param, astcBuffer)) {
        IMAGE_LOGE("FillAstcSutInfo fail");
        return false;
    }
    if (!g_sutEncSoManager.sutEncSoEncFunc_(astcInfo, sutInfo,
        static_cast<uint32_t>(param.sutProfile))) {
        IMAGE_LOGE("astc g_sutEncSoEncFunc failed!");
        free(sutInfo.sutBuf);
        return false;
    }
    if (memcpy_s(astcBuffer, param.astcBytes, sutInfo.sutBuf, sutInfo.sutBytes) < 0) {
        IMAGE_LOGE("sut sutbuffer is failed to be copied to astcBuffer!");
        free(sutInfo.sutBuf);
        return false;
    }
    free(sutInfo.sutBuf);
    param.outIsSut = true;
    param.astcBytes = sutInfo.sutBytes;
    param.sutBytes = param.astcBytes;
    return true;
}

bool AstcCodec::TryTextureSuperCompress(TextureEncodeOptions &param, uint8_t *astcBuffer)
{
    bool skipSutEnc = (param.sutProfile == SutProfile::SKIP_SUT) ||
        ((!param.hardwareFlag) && (param.privateProfile_ != HIGH_SPEED_PROFILE)) ||
        (param.blockX_ != DEFAULT_DIM && param.blockY_ != DEFAULT_DIM);
    switch (param.textureEncodeType) {
        case TextureEncodeType::HDR_ASTC_4X4:
        case TextureEncodeType::SDR_ASTC_4X4:
            param.sutProfile = SutProfile::SKIP_SUT;
            IMAGE_LOGD("sdr_astc_4x4 is not suit to be compressed to sut!");
            return true;
        case TextureEncodeType::ASTC:
            if (skipSutEnc) {
                IMAGE_LOGD("astc is not suit to be compressed to sut!");
                param.sutProfile = SutProfile::SKIP_SUT;
                return true;
            }
            break;
        case TextureEncodeType::SDR_SUT_SUPERFAST_4X4:
            break;
        default:
            IMAGE_LOGE("TextureEncodeType is failed");
            return false;
    }

    return SutEncode(param, astcBuffer);
}
#endif

static bool GetSutSdrProfile(PlEncodeOptions &astcOpts,
    SutProfile &sutProfile, QualityProfile &privateProfile)
{
    auto sutNode = SUT_FORMAT_MAP.find(astcOpts.format);
    if (sutNode != SUT_FORMAT_MAP.end()) {
        auto [sutQ, sutP, astcP] = sutNode->second;
        if (sutQ != astcOpts.quality) {
            IMAGE_LOGE("GetSutSdrProfile failed %{public}d is invalid!", astcOpts.quality);
            return false;
        }
        sutProfile = sutP;
        privateProfile = astcP;
        return true;
    }
    return false;
}

static bool GetAstcProfile(PlEncodeOptions &astcOpts, QualityProfile &privateProfile)
{
    auto astcNode = ASTC_FORMAT_MAP.find(astcOpts.format);
    if (astcNode != ASTC_FORMAT_MAP.end()) {
        const auto &qualityMap = astcNode->second;
        auto qualityNode = qualityMap.find(astcOpts.quality);
        if (qualityNode != qualityMap.end()) {
            privateProfile = qualityNode->second;
            return true;
        }
        IMAGE_LOGE("GetAstcProfile failed %{public}d is invalid!", astcOpts.quality);
        return false;
    }
    return false;
}

bool CheckParamBlockSize(TextureEncodeOptions &param)
{
    if ((param.width_ <= 0) || (param.height_ <= 0)) {
        IMAGE_LOGE("CheckAstcEncInput width <= 0 or height <= 0 !");
        return false;
    }
    if ((param.width_ > WIDTH_MAX_ASTC) || (param.height_ > HEIGHT_MAX_ASTC)) {
        IMAGE_LOGE("CheckAstcEncInput width %{public}d height %{public}d out of range %{public}d x %{public}d!",
                   param.width_, param.height_, WIDTH_MAX_ASTC, HEIGHT_MAX_ASTC);
        return false;
    }
    if ((param.blockX_ < DEFAULT_DIM) || (param.blockY_ < DEFAULT_DIM)) {
        IMAGE_LOGE("CheckAstcEncInput block %{public}d x %{public}d < 4 x 4!", param.blockX_, param.blockY_);
        return false;
    }
    if ((param.blockX_ > MAX_DIM) || (param.blockY_ > MAX_DIM)) {
        IMAGE_LOGE("CheckAstcEncInput block %{public}d x %{public}d > 12 x 12!", param.blockX_, param.blockY_);
        return false;
    }
    return true;
}

static bool InitAstcEncPara(TextureEncodeOptions &param,
    int32_t width, int32_t height, int32_t stride, PlEncodeOptions &astcOpts)
{
    SutProfile sutProfile;
    QualityProfile qualityProfile;
    if (astcOpts.format == "image/sdr_sut_superfast_4x4") { // sut sdr encode
        if (!GetSutSdrProfile(astcOpts, sutProfile, qualityProfile)) {
            IMAGE_LOGE("InitAstcEncPara GetSutSdrProfile failed");
            return false;
        }
        param.textureEncodeType = TextureEncodeType::SDR_SUT_SUPERFAST_4X4;
    } else if (astcOpts.format == "image/sdr_astc_4x4") { // astc sdr encode
        if (!GetAstcProfile(astcOpts, qualityProfile)) {
            IMAGE_LOGE("InitAstcEncPara GetAstcProfile failed");
            return false;
        }
        sutProfile = SutProfile::SKIP_SUT;
        param.textureEncodeType = TextureEncodeType::SDR_ASTC_4X4;
    } else if (astcOpts.format == "image/hdr_astc_4x4") { // astc hdr encode
        if (!GetAstcProfile(astcOpts, qualityProfile)) {
            IMAGE_LOGE("InitAstcEncPara GetAstcProfile failed");
            return false;
        }
        sutProfile = SutProfile::SKIP_SUT;
        param.textureEncodeType = TextureEncodeType::HDR_ASTC_4X4;
    } else if (astcOpts.format.find("image/astc") == 0) { // old astc encode
        qualityProfile = GetAstcQuality(astcOpts.quality);
        sutProfile = SutProfile::SKIP_SUT;
        param.textureEncodeType = TextureEncodeType::ASTC;
    } else {
        IMAGE_LOGE("InitAstcEncPara format invalidation:%{public}s", astcOpts.format.c_str());
        return false;
    }
    param.enableQualityCheck = false;
    param.hardwareFlag = false;
    param.sutProfile = sutProfile;
    param.width_ = width;
    param.height_ = height;
    param.stride_ = stride;
    param.privateProfile_ = qualityProfile;
    param.outIsSut = false;
    extractDimensions(astcOpts.format, param);
    if (!CheckParamBlockSize(param)) { // DEFAULT_DIM = 4
        IMAGE_LOGE("InitAstcEncPara failed %{public}dx%{public}d is invalid!", param.blockX_, param.blockY_);
        return false;
    }
    param.blocksNum = ((param.width_ + param.blockX_ - 1) / param.blockX_) *
        ((param.height_ + param.blockY_ - 1) / param.blockY_);
    param.astcBytes = param.blocksNum * TEXTURE_HEAD_BYTES + TEXTURE_HEAD_BYTES;
    return true;
}

static void FillAstcEncCheckInfo(AstcEncCheckInfo &checkInfo, Media::PixelMap* astcPixelMap, uint32_t astcBufferSize,
                                 uint32_t extendInfoSize, uint32_t extendBufferSize)
{
    checkInfo.pixmapInSize = astcPixelMap->GetAllocationByteCount();
    checkInfo.pixmapFormat = astcPixelMap->GetPixelFormat();
    checkInfo.astcBufferSize = astcBufferSize;
    checkInfo.extendInfoSize = extendInfoSize;
    checkInfo.extendBufferSize = extendBufferSize;
}

static bool CheckAstcEncInput(TextureEncodeOptions &param, AstcEncCheckInfo checkInfo)
{
    uint32_t pixmapStride = static_cast<uint32_t>(param.stride_) << RGBA_BYTES_PIXEL_LOG2;
    if ((param.width_ <= 0) || (param.height_ <= 0) || (param.stride_ < param.width_)) {
        IMAGE_LOGE("CheckAstcEncInput width <= 0 or height <= 0 or stride < width!");
        return false;
    }
    if ((param.width_ > WIDTH_MAX_ASTC) || (param.height_ > HEIGHT_MAX_ASTC)) {
        IMAGE_LOGE("CheckAstcEncInput width %{public}d height %{public}d out of range %{public}d x %{public}d!",
                   param.width_, param.height_, WIDTH_MAX_ASTC, HEIGHT_MAX_ASTC);
        return false;
    }
    uint64_t allocByteCount = static_cast<uint32_t>(param.height_) * pixmapStride;
    if (allocByteCount > std::numeric_limits<uint32_t>::max()) {
        IMAGE_LOGE("CheckAstcEncInput height %{public}d stride %{public}d overflow!",
                    param.height_, pixmapStride);
        return false;
    }
    if (checkInfo.pixmapInSize < static_cast<uint32_t>(allocByteCount)) {
        IMAGE_LOGE("CheckAstcEncInput pixmapInSize %{public}d not enough for height %{public}d stride %{public}d!",
                   checkInfo.pixmapInSize, param.height_, pixmapStride);
        return false;
    }
    if ((param.blockX_ < DEFAULT_DIM) || (param.blockY_ < DEFAULT_DIM)) {
        IMAGE_LOGE("CheckAstcEncInput block %{public}d x %{public}d < 4 x 4!", param.blockX_, param.blockY_);
        return false;
    }
    if ((param.blockX_ > MAX_DIM) || (param.blockY_ > MAX_DIM)) {
        IMAGE_LOGE("CheckAstcEncInput block %{public}d x %{public}d > 12 x 12!", param.blockX_, param.blockY_);
        return false;
    }
    const bool isAstcHdr = (param.textureEncodeType == TextureEncodeType::HDR_ASTC_4X4);
    const PixelFormat expectedFormat = isAstcHdr ? PixelFormat::RGBA_1010102 : PixelFormat::RGBA_8888;
    if (checkInfo.pixmapFormat != expectedFormat) {
        IMAGE_LOGE("CheckAstcEncInput textureEncodeType: %{public}d, pixelFormat %{public}d must be RGBA!",
            param.textureEncodeType, checkInfo.pixmapFormat);
        return false;
    }
    uint32_t packSize = static_cast<uint32_t>(param.astcBytes) + checkInfo.extendInfoSize + checkInfo.extendBufferSize;
    if (checkInfo.astcBufferSize < packSize) {
        IMAGE_LOGE("CheckAstcEncInput astcBufferSize %{public}d not enough for %{public}d!",
                   checkInfo.astcBufferSize, packSize);
        return false;
    }
    return true;
}

uint32_t AstcCodec::AstcSoftwareEncode(TextureEncodeOptions &param, bool enableQualityCheck,
    int32_t blocksNum, uint8_t *outBuffer, int32_t outSize)
{
    ImageInfo imageInfo;
    astcPixelMap_->GetImageInfo(imageInfo);
    uint8_t *pixmapIn = static_cast<uint8_t *>(astcPixelMap_->GetWritablePixels());
    uint32_t stride = static_cast<uint32_t>(astcPixelMap_->GetRowStride()) >> RGBA_BYTES_PIXEL_LOG2;
    if (!InitAstcEncPara(param, imageInfo.size.width, imageInfo.size.height, static_cast<int32_t>(stride), astcOpts_)) {
        IMAGE_LOGE("InitAstcEncPara failed");
        return ERROR;
    }
    param.enableQualityCheck = enableQualityCheck;
    AstcEncCheckInfo checkInfo;
    FillAstcEncCheckInfo(checkInfo, astcPixelMap_, param.astcBytes, 0, 0);
    if (!CheckAstcEncInput(param, checkInfo)) {
        IMAGE_LOGE("CheckAstcEncInput failed");
        return ERROR;
    }
    if (!AstcSoftwareEncodeCore(param, pixmapIn, outBuffer)) {
        IMAGE_LOGE("AstcSoftwareEncodeCore failed");
        return ERROR;
    }
    return SUCCESS;
}

static bool AstcEncProcess(TextureEncodeOptions &param, uint8_t *pixmapIn, uint8_t *astcBuffer,
                           AstcEncCheckInfo checkInfo)
{
    if (!CheckAstcEncInput(param, checkInfo)) {
        IMAGE_LOGE("CheckAstcEncInput failed");
        return false;
    }
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
    bool openClEnc = param.width_ >= WIDTH_CL_THRESHOLD && param.height_ >= HEIGHT_CL_THRESHOLD &&
        param.privateProfile_ == QualityProfile::HIGH_SPEED_PROFILE;
    bool enableClEnc = openClEnc && ImageSystemProperties::GetGenThumbWithGpu() &&
        (param.blockX_ == DEFAULT_DIM) && (param.blockY_ == DEFAULT_DIM); // HardWare only support 4x4 now
    if (enableClEnc) {
        IMAGE_LOGI("astc hardware encode begin");
        std::string clBinPath = "/sys_prod/etc/graphic/AstcEncShader_ALN-AL00.bin";
        if (!CheckClBinIsExistWithLock(clBinPath)) {
            clBinPath = "/data/storage/el1/base/AstcEncShader.bin";
        }
        IMAGE_LOGI("AstcEncProcess size: %{public}d, %{public}d, block: %{public}d, %{public}d, stride: %{public}d,"\
            "privateProfile: %{public}d, blocksNum: %{public}d, astcBytes: %{public}d",
            param.width_, param.height_,  param.blockX_, param.blockY_, param.stride_, param.privateProfile_,
            param.blocksNum, param.astcBytes);
        param.hardwareFlag = AstcCodec::TryAstcEncBasedOnCl(param, pixmapIn, astcBuffer, clBinPath);
        IMAGE_LOGI("AstcEncProcess hardwareFlag: %{public}d", param.hardwareFlag);
    }
#endif
    if (!param.hardwareFlag) {
        if (!AstcCodec::AstcSoftwareEncodeCore(param, pixmapIn, astcBuffer)) {
            IMAGE_LOGE("AstcSoftwareEncodeCore failed");
            return false;
        }
        IMAGE_LOGD("astc software encode success!");
    }
    return true;
}

void AstcCodec::InitTextureEncodeOptions(TextureEncodeOptions &param, uint8_t &colorData)
{
    param.expandNums = 1;
    param.extInfoBytes = 1;
#ifdef IMAGE_COLORSPACE_FLAG
    colorData = static_cast<uint8_t>(astcPixelMap_->InnerGetGrColorSpace().GetColorSpaceName());
#else
    colorData = 0;
#endif
}

bool AstcCodec::IsAstcEnc(Media::ImageInfo &info, uint8_t* pixelmapIn, TextureEncodeOptions &param,
    AstcExtendInfo &extendInfo)
{
    int32_t bufferSize = astcPixelMap_->GetCapacity();
    if (bufferSize <= 0) {
        IMAGE_LOGE("buffer size is less and equal than zero in packing");
        return false;
    }
    if (pixelmapIn == nullptr) {
        IMAGE_LOGE("pixelmap data is nullptr in packing");
        return false;
    }
    if (info.pixelFormat == PixelFormat::ASTC_4x4 && astcOpts_.format == "image/sdr_astc_4x4") {
        if (!astcOutput_->Write(pixelmapIn, bufferSize)) {
            IMAGE_LOGE("fail to write to astcout");
            return false;
        }
        return true;
    }
    if (info.pixelFormat == PixelFormat::ASTC_4x4 && astcOpts_.format == "image/sdr_sut_superfast_4x4") {
        uint8_t *astcBuffer = static_cast<uint8_t *>(malloc(bufferSize));
        if (astcBuffer == nullptr) {
            IMAGE_LOGE("Buffer malloc failed in packing");
            return false;
        }
        if (memcpy_s(astcBuffer, bufferSize, pixelmapIn, bufferSize) < 0) {
            IMAGE_LOGE("Copy data failed in packing");
            free(astcBuffer);
            return false;
        }
        if (!TryEncSUT(param, astcBuffer, extendInfo)) {
            IMAGE_LOGE("Astc encode sut failed in packing");
            return false;
        }
        bufferSize = static_cast<uint32_t>(param.sutBytes);
        if (!astcOutput_->Write(astcBuffer, bufferSize)) {
            IMAGE_LOGE("Write to astcout failed in packing");
            free(astcBuffer);
            return false;
        }
        free(astcBuffer);
        return true;
    }
    IMAGE_LOGE("Does not support packing format");
    return false;
}

bool AstcCodec::InitBeforeAstcEncode(ImageInfo &imageInfo, TextureEncodeOptions &param, uint8_t &colorData,
    uint8_t **pixmapIn, uint32_t &stride)
{
    if (astcPixelMap_ == nullptr || astcOutput_ == nullptr) {
        return false;
    }
    astcPixelMap_->GetImageInfo(imageInfo);
    InitTextureEncodeOptions(param, colorData);
    param.extInfoBuf = &colorData;
    *pixmapIn = const_cast<uint8_t *>(astcPixelMap_->GetPixels());
    stride = static_cast<uint32_t>(astcPixelMap_->GetRowStride()) >> RGBA_BYTES_PIXEL_LOG2;
    if (!InitAstcEncPara(param, imageInfo.size.width, imageInfo.size.height, static_cast<int32_t>(stride), astcOpts_)) {
        IMAGE_LOGE("InitAstcEncPara failed");
        return false;
    }
    return true;
}

bool AstcCodec::TryEncSUT(TextureEncodeOptions &param, uint8_t* astcBuffer, AstcExtendInfo &extendInfo)
{
#ifdef SUT_ENCODE_ENABLE
    if (!TryTextureSuperCompress(param, astcBuffer)) {
        IMAGE_LOGE("astc TryTextureSuperCompress failed!");
        ReleaseExtendInfoMemory(extendInfo);
        free(astcBuffer);
        return false;
    }
    return true;
#else
    return true;
#endif
}

uint32_t AstcCodec::ASTCEncode() __attribute__((no_sanitize("cfi")))
{
    ImageInfo imageInfo;
    TextureEncodeOptions param;
    uint8_t colorData;
    uint8_t *pixmapIn = nullptr;
    uint32_t stride = 0;
    if (!InitBeforeAstcEncode(imageInfo, param, colorData, &pixmapIn, stride)) {
        return ERROR;
    }
    ImageTrace("[AstcCodec] ASTCEncode Size: %d, %d", imageInfo.size.width, imageInfo.size.height);
    AstcExtendInfo extendInfo = {0};
    if (!InitAstcExtendInfo(extendInfo)) {
        return ERROR;
    }
    uint32_t packSize = static_cast<uint32_t>(param.astcBytes) + extendInfo.extendBufferSumBytes + ASTC_NUM_4;
    if (astcPixelMap_->IsAstc()) {
        if (!IsAstcEnc(imageInfo, pixmapIn, param, extendInfo)) {
            return ERROR;
        }
        return SUCCESS;
    }
    uint8_t *astcBuffer = static_cast<uint8_t *>(malloc(packSize));
    if (astcBuffer == nullptr) {
        ReleaseExtendInfoMemory(extendInfo);
        return ERROR;
    }
    AstcEncCheckInfo checkInfo;
    FillAstcEncCheckInfo(checkInfo, astcPixelMap_, packSize, ASTC_NUM_4, extendInfo.extendBufferSumBytes);
    if (!AstcEncProcess(param, pixmapIn, astcBuffer, checkInfo)) {
        IMAGE_LOGE("astc AstcEncProcess failed!");
        ReleaseExtendInfoMemory(extendInfo);
        free(astcBuffer);
        return ERROR;
    }
    if (!TryEncSUT(param, astcBuffer, extendInfo)) {
        return ERROR;
    }
    if (!param.outIsSut) { // only support astc for color space
        WriteAstcExtendInfo(astcBuffer, static_cast<uint32_t>(param.astcBytes), extendInfo);
    } else {
        packSize = static_cast<uint32_t>(param.sutBytes);
    }
    ReleaseExtendInfoMemory(extendInfo);
    if (!astcOutput_->Write(astcBuffer, packSize)) {
        free(astcBuffer);
        return ERROR;
    }
    free(astcBuffer);
    IMAGE_LOGD("astcenc end: %{public}dx%{public}d, GpuFlag %{public}d, sut%{public}d",
        imageInfo.size.width, imageInfo.size.height, param.hardwareFlag, param.sutProfile);
    astcOutput_->SetOffset(packSize);
    return SUCCESS;
}

bool AllocMemForExtInfo(AstcExtendInfo &extendInfo, uint8_t idx)
{
    auto AllocAndCopy = [&](size_t dataSize, const void* srcData, const char* logTag) -> bool {
        extendInfo.extendInfoLength[idx] = static_cast<uint32_t>(dataSize);
        extendInfo.extendBufferSumBytes += ASTC_EXTEND_INFO_TYPE_LENGTH +
                                          ASTC_EXTEND_INFO_LENGTH_LENGTH +
                                          extendInfo.extendInfoLength[idx];
        if (dataSize <= 0) {
            return false;
        }
        extendInfo.extendInfoValue[idx] = static_cast<uint8_t*>(malloc(dataSize));
        if (extendInfo.extendInfoValue[idx] == nullptr) {
            IMAGE_LOGE("[AstcCodec] %s malloc failed!", logTag);
            return false;
        }
        if (srcData && memcpy_s(extendInfo.extendInfoValue[idx], dataSize,
                               srcData, dataSize) != 0) {
            IMAGE_LOGE("[AstcCodec] %s memcpy failed!", logTag);
            return false;
        }
        return true;
    };
    AstcExtendInfoType type = static_cast<AstcExtendInfoType>(idx);
    switch (type) {
        case AstcExtendInfoType::COLOR_SPACE:
        case AstcExtendInfoType::PIXEL_FORMAT:
            // These types only require memory allocation and do not require data initialization
            return AllocAndCopy(ASTC_EXTEND_INFO_COLOR_SPACE_VALUE_LENGTH,
                               nullptr, type == AstcExtendInfoType::COLOR_SPACE ?
                               "SetColorSpaceInfo" : "SetPixelFormatInfo");
        case AstcExtendInfoType::HDR_METADATA_TYPE:
            return AllocAndCopy(extendInfo.astcMetadata.hdrMetadataTypeVec.size(),
                               extendInfo.astcMetadata.hdrMetadataTypeVec.data(),
                               "SetHdrMetadataType");
        case AstcExtendInfoType::HDR_COLORSPACE_INFO:
            return AllocAndCopy(extendInfo.astcMetadata.colorSpaceInfoVec.size(),
                               extendInfo.astcMetadata.colorSpaceInfoVec.data(),
                               "SetHdrColorSpaceInfo");
        case AstcExtendInfoType::HDR_STATIC_DATA:
            return AllocAndCopy(extendInfo.astcMetadata.staticData.size(),
                               extendInfo.astcMetadata.staticData.data(),
                               "SetHdrStaticData");
        case AstcExtendInfoType::HDR_DYNAMIC_DATA:
            return AllocAndCopy(extendInfo.astcMetadata.dynamicData.size(),
                               extendInfo.astcMetadata.dynamicData.data(),
                               "SetHdrDynamicData");
        default:
            IMAGE_LOGE("[AstcCodec] Unknown extend info type: %d", static_cast<int>(type));
            return false;
    }
}

bool AstcCodec::FillMetaData(AstcExtendInfo &extendInfo, PixelMap *astcPixelMap)
{
    if (astcPixelMap == nullptr || astcPixelMap->GetFd() == nullptr ||
        astcPixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        IMAGE_LOGE("[AstcCodec] astcPixelMap is invalid!");
        return false;
    }
    if (!astcPixelMap->IsHdr()) {
        return false; // No need to fill metadata for SDR
    }
    sptr<SurfaceBuffer> source(reinterpret_cast<SurfaceBuffer *>(astcPixelMap->GetFd()));
    bool baseMetadataSuccess = true;
    bool vpeMetadataSuccess = true;  // Track static/dynamic metadata status separately

    auto CheckResult = [&](GSError status, const char* metadataName) {
        if (status != GSERROR_OK) {
            IMAGE_LOGE("[AstcCodec] GetMetadata %{public}s failed: %{public}d", metadataName, status);
            baseMetadataSuccess = false;
        }
    };
    CheckResult(source->GetMetadata(ATTRKEY_HDR_METADATA_TYPE,
               extendInfo.astcMetadata.hdrMetadataTypeVec), "ATTRKEY_HDR_METADATA_TYPE");
    CheckResult(source->GetMetadata(ATTRKEY_COLORSPACE_INFO,
               extendInfo.astcMetadata.colorSpaceInfoVec), "ATTRKEY_COLORSPACE_INFO");
    // Check if required metadata is filled
    if (!baseMetadataSuccess) {
        IMAGE_LOGE("[AstcCodec] Critical base metadata missing!");
        return false;
    }

    auto CheckVpeResult = [&](bool result, const char* metadataName, auto& dataVec) {
        if (!result || dataVec.empty()) {
            IMAGE_LOGE("[AstcCodec] %{public}s failed or empty", metadataName);
            vpeMetadataSuccess = false;  // Only marking failures does not affect the basic metadata status
        }
    };
    // Check static/dynamic metadata (non critical)
    CheckVpeResult(VpeUtils::GetSbStaticMetadata(source, extendInfo.astcMetadata.staticData),
                  "GetSbStaticMetadata", extendInfo.astcMetadata.staticData);
    CheckVpeResult(VpeUtils::GetSbDynamicMetadata(source, extendInfo.astcMetadata.dynamicData),
                  "GetSbDynamicMetadata", extendInfo.astcMetadata.dynamicData);

    // Dynamically set extendNums based on VP metadata results
    extendInfo.extendNums = vpeMetadataSuccess ? ASTC_EXTEND_INFO_TLV_NUM_6 : ASTC_EXTEND_INFO_TLV_NUM_4;

    IMAGE_LOGI("[AstcCodec] HDR metadata: base=%{public}s, VP=%{public}s, using extendNums=%{public}d",
               baseMetadataSuccess ? "success" : "fail",
               vpeMetadataSuccess ? "success" : "fail",
               extendInfo.extendNums);
    return true;
}

bool AstcCodec::InitAstcExtendInfo(AstcExtendInfo &extendInfo)
{
    if (memset_s(&extendInfo, sizeof(AstcExtendInfo), 0, sizeof(AstcExtendInfo)) != 0) {
        IMAGE_LOGE("[AstcCodec] memset extendInfo failed!");
        return false;
    }
    extendInfo.extendNums = astcPixelMap_->IsHdr() ? ASTC_EXTEND_INFO_TLV_NUM_6 : ASTC_EXTEND_INFO_TLV_NUM;
    extendInfo.extendBufferSumBytes = 0;
    if (astcPixelMap_->IsHdr()) {
        if (!FillMetaData(extendInfo, astcPixelMap_)) {
            IMAGE_LOGE("[AstcCodec] FillMetaData failed!");
            return false;
        }
    }
    for (uint8_t idx = 0; idx < extendInfo.extendNums; idx++) {
        if (!AllocMemForExtInfo(extendInfo, idx)) {
            ReleaseExtendInfoMemory(extendInfo);
            IMAGE_LOGE("[AstcCodec] AllocMemForExtInfo failed!");
            return false;
        }
    }
    return true;
}

void AstcCodec::ReleaseExtendInfoMemory(AstcExtendInfo &extendInfo)
{
    for (uint8_t idx = 0; idx < extendInfo.extendNums; idx++) {
        if (extendInfo.extendInfoValue[idx] != nullptr) {
            free(extendInfo.extendInfoValue[idx]);
            extendInfo.extendInfoValue[idx] = nullptr;
        }
    }
}

static void FillDataSize(uint8_t *buf, uint32_t bytes)
{
    *buf++ = (bytes) & MASKBITS_FOR_8BITS;
    *buf++ = (bytes >> UINT32_1TH_BYTES) & MASKBITS_FOR_8BITS;
    *buf++ = (bytes >> UINT32_2TH_BYTES) & MASKBITS_FOR_8BITS;
    *buf++ = (bytes >> UINT32_3TH_BYTES) & MASKBITS_FOR_8BITS;
}

void AstcCodec::WriteAstcExtendInfo(uint8_t *buffer, uint32_t offset, AstcExtendInfo &extendInfo)
{
    uint8_t* offsetBuffer = buffer + offset;
    FillDataSize(offsetBuffer, extendInfo.extendBufferSumBytes);
    offsetBuffer += ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH;
#ifdef IMAGE_COLORSPACE_FLAG
    ColorManager::ColorSpace colorspace = astcPixelMap_->InnerGetGrColorSpace();
    ColorManager::ColorSpaceName csName = colorspace.GetColorSpaceName();
#endif
    PixelFormat pixelFormat = astcPixelMap_->GetPixelFormat();
    for (uint8_t idx = 0; idx < extendInfo.extendNums; idx++) {
        *offsetBuffer++ = idx;
        FillDataSize(offsetBuffer, extendInfo.extendInfoLength[idx]);
        offsetBuffer += ASTC_EXTEND_INFO_LENGTH_LENGTH;
        AstcExtendInfoType type = static_cast<AstcExtendInfoType>(idx);
        switch (type) {
            case AstcExtendInfoType::COLOR_SPACE:
#ifdef IMAGE_COLORSPACE_FLAG
                *offsetBuffer = static_cast<uint8_t>(csName);
#else
                *offsetBuffer = 0;
#endif
                offsetBuffer += ASTC_EXTEND_INFO_COLOR_SPACE_VALUE_LENGTH;
                break;
            case AstcExtendInfoType::PIXEL_FORMAT:
                *offsetBuffer = static_cast<uint8_t>(pixelFormat);
                offsetBuffer += ASTC_EXTEND_INFO_PIXEL_FORMAT_VALUE_LENGTH;
                break;
            case AstcExtendInfoType::HDR_METADATA_TYPE:
            case AstcExtendInfoType::HDR_COLORSPACE_INFO:
            case AstcExtendInfoType::HDR_STATIC_DATA:
            case AstcExtendInfoType::HDR_DYNAMIC_DATA:
                if (extendInfo.extendInfoValue[idx] == nullptr||
                    extendInfo.extendInfoLength[idx] <= 0 ||
                    memcpy_s(offsetBuffer, extendInfo.extendInfoLength[idx],
                    extendInfo.extendInfoValue[idx], extendInfo.extendInfoLength[idx]) != 0) {
                    IMAGE_LOGE("[AstcCodec] WriteAstcExtendInfo memcpy failed!");
                    return;
                }
                offsetBuffer += extendInfo.extendInfoLength[idx];
                break;
            default:
                return;
        }
    }
}
} // namespace ImagePlugin
} // namespace OHOS
