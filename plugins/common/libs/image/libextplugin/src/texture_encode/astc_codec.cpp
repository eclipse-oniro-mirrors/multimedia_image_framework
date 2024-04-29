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

#include "astc_codec.h"
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
#include "image_compressor.h"
#endif
#include "image_log.h"
#include "image_system_properties.h"
#include "securec.h"
#include "media_errors.h"

#include <dlfcn.h>

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
constexpr uint8_t HIGH_SPEED_PROFILE_MAP_QUALITY = 20; // quality level is 20 for thumbnail
constexpr uint8_t RGBA_BYTES_PIXEL_LOG2 = 2;
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

#ifdef SUT_ENCODE_ENABLE
static const std::string g_textureSuperEncSo = "/system/lib64/module/hms/graphic/libtextureSuperCompress.z.so";
using SuperCompressTexture = bool (*)(uint8_t*, int32_t, uint8_t*, int32_t&, uint32_t);

class SutEncSoManager {
public:
    SutEncSoManager();
    ~SutEncSoManager();
    bool LoadSutEncSo();
    SuperCompressTexture sutEncSoEncFunc_;
private:
    bool sutEncSoOpened_;
    void *textureEncSoHandle_;
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
    if (!sutEncSoOpened_ || textureEncSoHandle_ == nullptr) {
        IMAGE_LOGD("astcenc sut enc so is not be opened when dlclose!");
        return;
    }
    if (dlclose(textureEncSoHandle_) != 0) {
        IMAGE_LOGE("astcenc dlcose success: %{public}s!", g_textureSuperEncSo.c_str());
        return;
    } else {
        IMAGE_LOGD("astcenc dlcose failed: %{public}s!", g_textureSuperEncSo.c_str());
        return;
    }
}

bool SutEncSoManager::LoadSutEncSo()
{
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
            reinterpret_cast<SuperCompressTexture>(dlsym(textureEncSoHandle_, "SuperCompressTexture"));
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
    if (header == nullptr) {
        IMAGE_LOGE("header is nullptr");
        return ERROR;
    }
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
    if ((work == nullptr) || (option == nullptr)) {
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
    if (status == ASTCENC_ERR_BAD_BLOCK_SIZE) {
        IMAGE_LOGE("ERROR: block size is invalid");
        return ERROR;
    } else if (status == ASTCENC_ERR_BAD_CPU_FLOAT) {
        IMAGE_LOGE("ERROR: astcenc must not be compiled with fast-math");
        return ERROR;
    } else if (status != ASTCENC_SUCCESS) {
        IMAGE_LOGE("ERROR: config failed");
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

            param.blockX_ = static_cast<uint8_t>(std::stoi(widthStr));
            param.blockY_ = static_cast<uint8_t>(std::stoi(heightStr));
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
        double mseRgb = static_cast<double>(mseTotal[i] / (blockNum * blockXYZ));
        psnr[i] = LOG_BASE * log(static_cast<double>(MAX_VALUE * MAX_VALUE) / mseRgb) / log(LOG_BASE);
    }
    if (mseTotal[RGBA_COM] == 0) {
        psnr[RGBA_COM] = MAX_PSNR;
    } else {
        double mseRgb = static_cast<double>(mseTotal[RGBA_COM] / (blockNum * blockXYZ * (RGBA_COM - 1)));
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
    work->image_.dim_x = param.width_;
    work->image_.dim_y = param.height_;
    work->image_.dim_z = 1;
    work->image_.data_type = ASTCENC_TYPE_U8;
    work->image_.dim_stride = param.stride_;
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
static bool TryAstcEncBasedOnCl(TextureEncodeOptions &param, uint8_t *inData,
    uint8_t *buffer, const std::string &clBinPath)
{
    ClAstcHandle *astcClEncoder = nullptr;
    if ((inData == nullptr) || (buffer == nullptr)) {
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
static bool TryTextureSuperCompress(TextureEncodeOptions &param, uint8_t *astcBuffer)
{
    if ((param.sutProfile == SutProfile::SKIP_SUT) ||
        ((!param.hardwareFlag) && (param.privateProfile_ != HIGH_SPEED_PROFILE))) {
        IMAGE_LOGD("astc sutProfile %{public}d or the astc profile could not be superCompress!", param.sutProfile);
        param.sutProfile = SutProfile::SKIP_SUT;
        return true;
    }
    if (astcBuffer == nullptr) {
        IMAGE_LOGE("astc TryTextureSuperCompress: astcBuffer is nullptr!");
        return false;
    }
    uint8_t *dstMem = nullptr;
    int32_t dstSize = 0;
    switch (param.sutProfile) {
        case SutProfile::EXTREME_SPEED:
            break;
        default:
            IMAGE_LOGI("astc could not be supported for sutProfile%{public}d", param.sutProfile);
            return false;
    }
    if (!g_sutEncSoManager.LoadSutEncSo() || g_sutEncSoManager.sutEncSoEncFunc_ == nullptr) {
        IMAGE_LOGE("[ImageSource] SUT enc so dlopen failed or sutEncSoEncFunc_ is nullptr!");
        return false;
    }
    if (!g_sutEncSoManager.sutEncSoEncFunc_(astcBuffer,
        param.astcBytes, dstMem, dstSize, static_cast<uint32_t>(param.sutProfile))) {
        IMAGE_LOGE("astc g_sutEncSoEncFunc failed. notice: astc memory may be polluted!");
        return false;
    }
    param.astcBytes = dstSize;
    return true;
}
#endif

static bool InitAstcEncPara(TextureEncodeOptions &param,
    int32_t width, int32_t height, int32_t stride, PlEncodeOptions &astcOpts)
{
    param.enableQualityCheck = false;
    param.hardwareFlag = false;
    param.sutProfile =
        ImageSystemProperties::GetSutEncodeEnabled() ? SutProfile::EXTREME_SPEED : SutProfile::SKIP_SUT;
    param.width_ = width;
    param.height_ = height;
    param.stride_ = stride;
    param.privateProfile_ = GetAstcQuality(astcOpts.quality);
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
    int32_t stride = astcPixelMap_->GetRowStride() >> RGBA_BYTES_PIXEL_LOG2;
    if (!InitAstcEncPara(param, imageInfo.size.width, imageInfo.size.height, stride, astcOpts_)) {
        IMAGE_LOGE("InitAstcEncPara failed");
        return ERROR;
    }
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
    if (openClEnc && ImageSystemProperties::GetAstcHardWareEncodeEnabled() &&
        (param.blockX_ == DEFAULT_DIM) && (param.blockY_ == DEFAULT_DIM)) { // HardWare only support 4x4 now
        IMAGE_LOGI("astc hardware encode begin");
        std::string clBinPath = "/sys_prod/etc/graphic/AstcEncShader_ALN-AL00.bin";
        if (CheckClBinIsExist(clBinPath) && TryAstcEncBasedOnCl(param, pixmapIn, astcBuffer, clBinPath)) {
            param.hardwareFlag = true;
            IMAGE_LOGI("astc hardware encode success!");
        } else {
            IMAGE_LOGI("astc AstcEncShader binany file is not exist, otherwise hardware encode failed!");
        }
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

uint32_t AstcCodec::ASTCEncode()
{
    ImageInfo imageInfo;
    astcPixelMap_->GetImageInfo(imageInfo);
    TextureEncodeOptions param;
    uint8_t *pixmapIn = static_cast<uint8_t *>(astcPixelMap_->GetWritablePixels());
    int32_t stride = astcPixelMap_->GetRowStride() >> RGBA_BYTES_PIXEL_LOG2;
    if (!InitAstcEncPara(param, imageInfo.size.width, imageInfo.size.height, stride, astcOpts_)) {
        IMAGE_LOGE("InitAstcEncPara failed");
        return ERROR;
    }
    IMAGE_LOGD("astcenc start: %{public}dx%{public}d, enableQualityCheck %{public}d, astcProfile %{public}d",
        imageInfo.size.width, imageInfo.size.height, param.enableQualityCheck, param.privateProfile_);
    uint8_t *astcBuffer = static_cast<uint8_t *>(malloc(param.astcBytes));
    if (astcBuffer == nullptr) {
        IMAGE_LOGE("astc astcBuffer malloc failed!");
        return ERROR;
    }
    if (!AstcEncProcess(param, pixmapIn, astcBuffer)) {
        IMAGE_LOGE("astc AstcEncProcess failed!");
        free(astcBuffer);
        return ERROR;
    }
#ifdef SUT_ENCODE_ENABLE
    if (!TryTextureSuperCompress(param, astcBuffer)) {
        IMAGE_LOGE("astc TryTextureSuperCompress failed!");
        free(astcBuffer);
        return ERROR;
    }
#endif
    astcOutput_->Write(astcBuffer, param.astcBytes);
    free(astcBuffer);
    IMAGE_LOGD("astcenc end: %{public}dx%{public}d, GpuFlag %{public}d, sut%{public}d",
        imageInfo.size.width, imageInfo.size.height, param.hardwareFlag, param.sutProfile);
    astcOutput_->SetOffset(param.astcBytes);
    return SUCCESS;
}
} // namespace ImagePlugin
} // namespace OHOS
