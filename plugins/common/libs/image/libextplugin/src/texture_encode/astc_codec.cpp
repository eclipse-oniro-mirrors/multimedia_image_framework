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

#include "astc_codec.h"
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
#include "image_compressor.h"
#endif
#include "image_log.h"
#include "image_system_properties.h"
#include "securec.h"
#include "media_errors.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "AstcCodec"

namespace OHOS {
namespace ImagePlugin {
using namespace Media;
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
using namespace AstcEncBasedCl;
#endif
constexpr uint8_t TEXTURE_HEAD_BYTES = 16;
constexpr uint8_t ASTC_MASK = 0xFF;
constexpr uint8_t ASTC_NUM_8 = 8;
constexpr uint8_t ASTC_HEADER_SIZE = 16;
constexpr uint8_t ASTC_NUM_24 = 24;
static const uint32_t ASTC_MAGIC_ID = 0x5CA1AB13;
constexpr uint8_t DEFAULT_DIM = 4;
constexpr uint8_t RGBA_BYTES_PIXEL_LOG2 = 2;
constexpr uint8_t MASKBITS_FOR_8BITS = 255;
constexpr uint8_t UINT32_1TH_BYTES = 8;
constexpr uint8_t UINT32_2TH_BYTES = 16;
constexpr uint8_t UINT32_3TH_BYTES = 24;
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
constexpr int32_t WIDTH_CL_THRESHOLD = 256;
constexpr int32_t HEIGHT_CL_THRESHOLD = 256;
#endif

#if (defined SUT_ENCODE_ENABLE) || (defined ENABLE_ASTC_ENCODE_BASED_GPU)
static bool CheckClBinIsExist(const std::string &name)
{
    return (access(name.c_str(), F_OK) != -1); // -1 means that the file is  not exist
}
#endif

enum class AstcQuality : uint8_t {
    ASTC_HIGH_SPEED_PROFILE = 20, // quality level is 20 for thumbnail
    ASTC_BALANCE_PROFILE = 30,
    ASTC_HIGH_QUALITY_PROFILE = 100,
};

enum class SutQuality : uint8_t {
    SUT_EXTREME_SPEED_PROFILE = 20,
    SUT_BALANCE_PROFILE = 30,
    SUT_HIGH_QUILITY_PROFILE = 90,
};

static const std::map<QualityProfile, float> ASTC_PRIFLE_QULITY = {
    {HIGH_SPEED_PROFILE, ASTCENC_PRE_FAST},
    {CUSTOMIZED_PROFILE, ASTCENC_PRE_THOROUGH},
    {HIGH_QUALITY_PROFILE, ASTCENC_PRE_THOROUGH}
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
static const std::string g_textureSuperEncSo = "/system/lib64/module/hms/graphic/libtextureSuperCompress.z.so";
using SuperCompressTexture = bool (*)(const AstcInInfo&, SutOutInfo&, uint32_t);
class SutEncSoManager {
public:
    SutEncSoManager();
    ~SutEncSoManager();
    SuperCompressTexture sutEncSoEncFunc_;
private:
    void *textureEncSoHandle_;
    void LoadSutEncSo();
};

static SutEncSoManager g_sutEncSoManager;

SutEncSoManager::SutEncSoManager()
{
    textureEncSoHandle_ = nullptr;
    sutEncSoEncFunc_ = nullptr;
    LoadSutEncSo();
}

SutEncSoManager::~SutEncSoManager()
{
    if (textureEncSoHandle_ != nullptr) {
        int ret = dlclose(textureEncSoHandle_);
        IMAGE_LOGD("sutenc dlclose ret = %{public}d!", ret);
    }
}

void SutEncSoManager::LoadSutEncSo()
{
    if (!CheckClBinIsExist(g_textureSuperEncSo)) {
        IMAGE_LOGE("sut %{public}s! is not found", g_textureSuperEncSo.c_str());
        return;
    }
    textureEncSoHandle_ = dlopen(g_textureSuperEncSo.c_str(), 1);
    if (textureEncSoHandle_ == nullptr) {
        IMAGE_LOGE("sut libtextureSuperCompress dlopen failed!");
        return;
    }
    sutEncSoEncFunc_ =
        reinterpret_cast<SuperCompressTexture>(dlsym(textureEncSoHandle_, "SuperCompressTextureTlv"));
    if (sutEncSoEncFunc_ == nullptr) {
        IMAGE_LOGE("sut libtextureSuperCompress dlsym failed!");
        dlclose(textureEncSoHandle_);
        textureEncSoHandle_ = nullptr;
        return;
    }
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
    auto node = ASTC_PRIFLE_QULITY.find(option->privateProfile_);
    if (node != ASTC_PRIFLE_QULITY.end()) {
        quality = node->second;
    }
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
    work->image_.data_type = ASTCENC_TYPE_U8;
    work->image_.dim_stride = static_cast<unsigned int>(param.stride_);
    work->codec_context = nullptr;
    work->image_.data = nullptr;
    work->profile = ASTCENC_PRF_LDR_SRGB;
#if defined(QUALITY_CONTROL) && (QUALITY_CONTROL == 1)
    work->mse[R_COM] = work->mse[G_COM] = work->mse[B_COM] = work->mse[RGBA_COM] = nullptr;
    work->calQualityEnable = param.enableQualityCheck;
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

static bool GetAstcProfile(uint8_t quality, QualityProfile &privateProfile)
{
    switch (quality) {
        case static_cast<uint8_t>(AstcQuality::ASTC_HIGH_SPEED_PROFILE):
            privateProfile = HIGH_SPEED_PROFILE;
            break;
        case static_cast<uint8_t>(AstcQuality::ASTC_BALANCE_PROFILE):
            privateProfile = CUSTOMIZED_PROFILE;
            break;
        case static_cast<uint8_t>(AstcQuality::ASTC_HIGH_QUALITY_PROFILE):
            privateProfile = HIGH_QUALITY_PROFILE;
            break;
        default:
            return false;
    }
    return true;
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

bool CheckPrivateProfile(QualityProfile privateProfile)
{
    return !ASTC_PRIFLE_QULITY.empty() &&
        ASTC_PRIFLE_QULITY.find(privateProfile) != ASTC_PRIFLE_QULITY.end();
}

bool AstcCodec::TryTextureSuperCompress(TextureEncodeOptions &param, uint8_t *astcBuffer)
{
    bool skipSutEnc = (param.sutProfile == SutProfile::SKIP_SUT) ||
        ((!param.hardwareFlag) && !CheckPrivateProfile(param.privateProfile_)) ||
        (param.blockX_ != DEFAULT_DIM && param.blockY_ != DEFAULT_DIM);
    if (skipSutEnc) {
        IMAGE_LOGD("astc is not suit to be compressed to sut!");
        param.sutProfile = SutProfile::SKIP_SUT;
        return true;
    }
    if (g_sutEncSoManager.sutEncSoEncFunc_ == nullptr) {
        IMAGE_LOGD("astcenc sut enc sutEncSoEncFunc_ is nullptr!");
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
#endif

static bool IsSUT(const std::string &format)
{
    return format.find("image/sut") == 0;
}

static bool GetSutQualityAndProfile(uint8_t &quality, SutProfile &profile)
{
    switch (quality) {
        case static_cast<uint8_t>(SutQuality::SUT_EXTREME_SPEED_PROFILE):
            profile = SutProfile::EXTREME_SPEED_A;
            break;
        case static_cast<uint8_t>(SutQuality::SUT_BALANCE_PROFILE):
            profile = SutProfile::HIGH_CR_LEVEL1;
            break;
        case static_cast<uint8_t>(SutQuality::SUT_HIGH_QUILITY_PROFILE):
            profile = SutProfile::HIGH_CR_LEVEL1;
            quality = static_cast<uint8_t>(AstcQuality::ASTC_HIGH_QUALITY_PROFILE);
            break;
        default:
            profile = SutProfile::SKIP_SUT;
            return false;
    }
    return true;
}

static bool InitAstcEncPara(TextureEncodeOptions &param,
    int32_t width, int32_t height, int32_t stride, PlEncodeOptions &astcOpts)
{
    SutProfile sutProfile;
    QualityProfile qualityProfile;
    uint8_t quality = astcOpts.quality;
    if (IsSUT(astcOpts.format) && !GetSutQualityAndProfile(quality, sutProfile)) {
        IMAGE_LOGE("GetSutQualityAndProfile failed %{public}d is invalid!", astcOpts.quality);
        return false;
    }
    if (!GetAstcProfile(quality, qualityProfile)) {
        IMAGE_LOGE("GetAstcQuality failed %{public}d is invalid!", quality);
        return false;
    }
    param.enableQualityCheck = false;
    param.hardwareFlag = false;
    param.sutProfile =
        (ImageSystemProperties::GetSutEncodeEnabled() && IsSUT(astcOpts.format)) ?
        sutProfile : SutProfile::SKIP_SUT;
    param.width_ = width;
    param.height_ = height;
    param.stride_ = stride;
    param.privateProfile_ = qualityProfile;
    param.outIsSut = false;
    extractDimensions(astcOpts.format, param);
    if ((param.blockX_ < DEFAULT_DIM) || (param.blockY_ < DEFAULT_DIM)) { // DEFAULT_DIM = 4
        IMAGE_LOGE("InitAstcEncPara failed %{public}dx%{public}d is invalid!", param.blockX_, param.blockY_);
        return false;
    }
    param.blocksNum = ((param.width_ + param.blockX_ - 1) / param.blockX_) *
        ((param.height_ + param.blockY_ - 1) / param.blockY_);
    param.astcBytes = param.blocksNum * TEXTURE_HEAD_BYTES + TEXTURE_HEAD_BYTES;
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
    if (!AstcSoftwareEncodeCore(param, pixmapIn, outBuffer)) {
        IMAGE_LOGE("AstcSoftwareEncodeCore failed");
        return ERROR;
    }
    return SUCCESS;
}

static bool AstcEncProcess(TextureEncodeOptions &param, uint8_t *pixmapIn, uint8_t *astcBuffer)
{
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
    bool openClEnc = param.width_ >= WIDTH_CL_THRESHOLD && param.height_ >= HEIGHT_CL_THRESHOLD &&
        param.privateProfile_ == QualityProfile::HIGH_SPEED_PROFILE;
    bool enableClEnc = openClEnc && ImageSystemProperties::GetAstcHardWareEncodeEnabled() &&
        (param.blockX_ == DEFAULT_DIM) && (param.blockY_ == DEFAULT_DIM); // HardWare only support 4x4 now
    if (enableClEnc) {
        IMAGE_LOGI("astc hardware encode begin");
        std::string clBinPath = "/sys_prod/etc/graphic/AstcEncShader_ALN-AL00.bin";
        param.hardwareFlag = CheckClBinIsExist(clBinPath) &&
            AstcCodec::TryAstcEncBasedOnCl(param, pixmapIn, astcBuffer, clBinPath);
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
    astcPixelMap_->GetImageInfo(imageInfo);
    TextureEncodeOptions param;
    uint8_t colorData;
    InitTextureEncodeOptions(param, colorData);
    param.extInfoBuf = &colorData;
    uint8_t *pixmapIn = static_cast<uint8_t *>(astcPixelMap_->GetWritablePixels());
    uint32_t stride = static_cast<uint32_t>(astcPixelMap_->GetRowStride()) >> RGBA_BYTES_PIXEL_LOG2;
    if (!InitAstcEncPara(param, imageInfo.size.width, imageInfo.size.height, static_cast<int32_t>(stride), astcOpts_)) {
        IMAGE_LOGE("InitAstcEncPara failed");
        return ERROR;
    }
    AstcExtendInfo extendInfo = {0};
    if (!InitAstcExtendInfo(extendInfo)) {
        IMAGE_LOGE("InitAstcExtendInfo failed");
        return ERROR;
    }
    uint32_t packSize = static_cast<uint32_t>(param.astcBytes) +
        extendInfo.extendBufferSumBytes + ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH;
    uint8_t *astcBuffer = static_cast<uint8_t *>(malloc(packSize));
    if (astcBuffer == nullptr) {
        IMAGE_LOGE("astc astcBuffer malloc failed!");
        ReleaseExtendInfoMemory(extendInfo);
        return ERROR;
    }
    if (!AstcEncProcess(param, pixmapIn, astcBuffer)) {
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
    astcOutput_->Write(astcBuffer, packSize);
    free(astcBuffer);
    IMAGE_LOGD("astcenc end: %{public}dx%{public}d, GpuFlag %{public}d, sut%{public}d",
        imageInfo.size.width, imageInfo.size.height, param.hardwareFlag, param.sutProfile);
    astcOutput_->SetOffset(packSize);
    return SUCCESS;
}

bool AllocMemForExtInfo(AstcExtendInfo &extendInfo, uint8_t idx)
{
    AstcExtendInfoType type = static_cast<AstcExtendInfoType>(idx);
    switch (type) {
        case AstcExtendInfoType::COLOR_SPACE:
            extendInfo.extendInfoLength[idx] = ASTC_EXTEND_INFO_COLOR_SPACE_VALUE_LENGTH;
            extendInfo.extendBufferSumBytes += ASTC_EXTEND_INFO_TYPE_LENGTH +
                ASTC_EXTEND_INFO_LENGTH_LENGTH + ASTC_EXTEND_INFO_COLOR_SPACE_VALUE_LENGTH;
            extendInfo.extendInfoValue[idx] = static_cast<uint8_t*>(malloc(extendInfo.extendInfoLength[idx]));
            if (extendInfo.extendInfoValue[idx] == nullptr) {
                IMAGE_LOGE("[AstcCodec] SetColorSpaceInfo malloc failed!");
                return false;
            }
            break;
        default:
            return false;
    }
    return true;
}

bool AstcCodec::InitAstcExtendInfo(AstcExtendInfo &extendInfo)
{
    if (memset_s(&extendInfo, sizeof(AstcExtendInfo), 0, sizeof(AstcExtendInfo)) != 0) {
        return false;
    }
    extendInfo.extendNums = ASTC_EXTEND_INFO_TLV_NUM;
    extendInfo.extendBufferSumBytes = 0;
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
                break;
            default:
                return;
        }
    }
}
} // namespace ImagePlugin
} // namespace OHOS
