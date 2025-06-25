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

#include "image_texture_encode_fuzz.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sys/time.h>
#include <unistd.h>

#include "astc_codec.h"
#include "buffer_packer_stream.h"
#include "image_log.h"
#include "image_system_properties.h"
#include "image_utils.h"
#include "media_errors.h"
#include "securec.h"


using namespace OHOS::Media;
using namespace OHOS::ImagePlugin;
namespace OHOS {
namespace Media {
constexpr int32_t DEFAULT_WIDTH = 1024;
constexpr int32_t DEFAULT_HEIGHT = 512;
constexpr int32_t HIGH_SPEED_PROFILE_MAP_QUALITY = 20;
constexpr uint8_t DEFAULT_DIM = 4;
constexpr uint8_t MAX_DIM = 12;

constexpr int32_t MAX_LENGTH_MODULO = 8449;
constexpr int32_t MAX_QUALITY_MODULO = 101;
constexpr uint8_t MAX_BLOCK_MODULO = 14;
constexpr int32_t MAX_RANDOM_BYTES = 8; // 2bytes width/height, 1 byte quality/blockX/blockY
constexpr uint8_t MOVE_ONE_BYTE = 8;
constexpr uint8_t NUM_TWO_BYTES = 2;

constexpr uint8_t ASTC_NUM_4 = 4;   // represents ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH
constexpr uint8_t TEXTURE_HEAD_BYTES = 16;
constexpr int32_t PIXEL_VALUE_MAX = 256;
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
constexpr int32_t WIDTH_CL_THRESHOLD = 256;
constexpr int32_t HEIGHT_CL_THRESHOLD = 256;
#endif
constexpr uint8_t RGBA_BYTES_PIXEL_LOG2 = 2;
constexpr int32_t BYTES_PER_PIXEL = 4;
constexpr int32_t WIDTH_MAX_ASTC = 8192;
constexpr int32_t HEIGHT_MAX_ASTC = 8192;

struct ParamRand {
    int32_t width = 0;
    int32_t height = 0;
    int32_t quality = 0;
    uint8_t blockX = 0;
    uint8_t blockY = 0;
    std::string format = "";
};

std::string formatArray[4] = {"image/sdr_sut_superfast_4x4", "image/sdr_astc_4x4", "image/hdr_astc_4x4",
    "image/astc/4*4"};

struct AstcEncCheckInfo {
    uint32_t pixmapInSize = 0;
    uint32_t astcBufferSize = 0;
    uint32_t extendInfoSize = 0;
    uint32_t extendBufferSize = 0;
    PixelFormat pixmapFormat = PixelFormat::UNKNOWN;
};


static bool DumpSingleInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        IMAGE_LOGE("invalid input !");
        return false;
    }
    const std::string inFilePath = "/data/local/tmp/fuzzImageTextureEncodeParamRand.bin";
    std::ofstream dumpInFile;
    dumpInFile.open(inFilePath, std::ios_base::binary | std::ios_base::trunc);
    if (!dumpInFile.is_open()) {
        IMAGE_LOGE("failed to open %{public}s", inFilePath.c_str());
        return false;
    }
    dumpInFile.write(reinterpret_cast<char *>(const_cast<uint8_t *>(data)), size);
    dumpInFile.close();
    return true;
}

static ParamRand GetParametersRandom(const uint8_t *data, size_t size)
{
    ParamRand paramRand;
    paramRand.width = DEFAULT_WIDTH;
    paramRand.height = DEFAULT_HEIGHT;
    paramRand.quality = HIGH_SPEED_PROFILE_MAP_QUALITY;
    paramRand.blockX = DEFAULT_DIM;
    paramRand.blockY = DEFAULT_DIM;
    // Fill param with data if any
    uint8_t *dataTmp = const_cast<uint8_t *>(data);
    if (size >= MAX_RANDOM_BYTES) {
        paramRand.width = static_cast<int32_t>(dataTmp[0]) |
            static_cast<int32_t>(dataTmp[1] << MOVE_ONE_BYTE);
        paramRand.width %= MAX_LENGTH_MODULO;
        dataTmp += NUM_TWO_BYTES;
        paramRand.height = static_cast<int32_t>(dataTmp[0]) |
            static_cast<int32_t>(dataTmp[1] << MOVE_ONE_BYTE);
        paramRand.height %= MAX_LENGTH_MODULO;
        dataTmp += NUM_TWO_BYTES;
        paramRand.quality = static_cast<int32_t>(*dataTmp++) % MAX_QUALITY_MODULO;
        paramRand.blockX = *dataTmp++ % MAX_BLOCK_MODULO;
        paramRand.blockY = *dataTmp++ % MAX_BLOCK_MODULO;
        paramRand.format = formatArray[*dataTmp++ % ASTC_NUM_4];
    }
    IMAGE_LOGI("GetParametersRandom success, width %{public}d height %{public}d quality %{public}d \
        blockX %{public}d blockY %{public}d",
        paramRand.width, paramRand.height, paramRand.quality,
        paramRand.blockX, paramRand.blockY);
    return paramRand;
}

static void FillPixelMap(uint8_t *pixmapIn, size_t pixelMapBytes)
{
    uint8_t *bufTmp = pixmapIn;
    for (size_t pixel = 0; pixel < pixelMapBytes; pixel++) {
        *bufTmp++ = static_cast<uint8_t>(pixel % PIXEL_VALUE_MAX);
    }
}

static void InitTextureEncodeOptions(TextureEncodeOptions &param, uint8_t &colorData)
{
    param.expandNums = 1;
    param.extInfoBytes = 1;
#ifdef IMAGE_COLORSPACE_FLAG
    colorData = static_cast<uint8_t>(astcPixelMap_->InnerGetGrColorSpace().GetColorSpaceName());
#else
    colorData = 0;
#endif
}

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

static bool InitAstcEncPara(TextureEncodeOptions &param, ParamRand paramRand, PlEncodeOptions astcOpts)
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
    param.enableQualityCheck = true;
    param.hardwareFlag = false;
    param.sutProfile = sutProfile;
    param.width_ = paramRand.width;
    param.height_ = paramRand.height;
    param.stride_ = paramRand.width;
    param.privateProfile_ = qualityProfile;
    param.outIsSut = false;
    param.blockX_ = paramRand.blockX;
    param.blockY_ = paramRand.blockY;
    if ((param.blockX_ < DEFAULT_DIM) || (param.blockY_ < DEFAULT_DIM)) { // DEFAULT_DIM = 4
        IMAGE_LOGE("InitAstcEncPara failed %{public}dx%{public}d is invalid!", param.blockX_, param.blockY_);
        return false;
    }
    param.blocksNum = ((param.width_ + param.blockX_ - 1) / param.blockX_) *
        ((param.height_ + param.blockY_ - 1) / param.blockY_);
    param.astcBytes = param.blocksNum * TEXTURE_HEAD_BYTES + TEXTURE_HEAD_BYTES;
    return true;
}

static bool AllocMemForExtInfo(AstcExtendInfo &extendInfo, uint8_t idx)
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

static void ReleaseExtendInfoMemory(AstcExtendInfo &extendInfo)
{
    for (uint8_t idx = 0; idx < extendInfo.extendNums; idx++) {
        if (extendInfo.extendInfoValue[idx] != nullptr) {
            free(extendInfo.extendInfoValue[idx]);
            extendInfo.extendInfoValue[idx] = nullptr;
        }
    }
}

static bool InitAstcExtendInfo(AstcExtendInfo &extendInfo)
{
    if (memset_s(&extendInfo, sizeof(AstcExtendInfo), 0, sizeof(AstcExtendInfo)) != 0) {
        IMAGE_LOGE("[AstcCodec] memset extendInfo failed!");
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

static void FillAstcEncCheckInfo(AstcEncCheckInfo &checkInfo, uint32_t pixmapInSize, uint32_t astcBufferSize,
                                 uint32_t extendInfoSize, uint32_t extendBufferSize)
{
    checkInfo.pixmapInSize = pixmapInSize;
    checkInfo.astcBufferSize = astcBufferSize;
    checkInfo.extendInfoSize = extendInfoSize;
    checkInfo.extendBufferSize = extendBufferSize;
}

static bool CheckAstcEncInput(TextureEncodeOptions &param, AstcEncCheckInfo checkInfo)
{
    int32_t pixmapStride = param.stride_ << RGBA_BYTES_PIXEL_LOG2;
    if ((param.width_ <= 0) || (param.height_ <= 0) || (pixmapStride < param.width_)) {
        IMAGE_LOGE("CheckAstcEncInput width <= 0 or height <= 0 or stride < width!");
        return false;
    }
    if ((param.width_ > WIDTH_MAX_ASTC) || (param.height_ > HEIGHT_MAX_ASTC)) {
        IMAGE_LOGE("CheckAstcEncInput width %{public}d height %{public}d out of range %{public}d x %{public}d!",
                   param.width_, param.height_, WIDTH_MAX_ASTC, HEIGHT_MAX_ASTC);
        return false;
    }
    if (checkInfo.pixmapInSize < (param.height_ * pixmapStride)) {
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
        IMAGE_LOGE("CheckAstcEncInput pixmapFormat %{public}d must be RGBA!", checkInfo.pixmapFormat);
        return false;
    }
    uint32_t packSize = param.astcBytes + checkInfo.extendInfoSize + checkInfo.extendBufferSize;
    if (checkInfo.astcBufferSize < packSize) {
        IMAGE_LOGE("CheckAstcEncInput astcBufferSize %{public}d not enough for %{public}d!",
                   checkInfo.astcBufferSize, packSize);
        return false;
    }
    return true;
}

static bool AstcEncProcess(TextureEncodeOptions &param, uint8_t *pixmapIn, uint8_t *astcBuffer,
                           AstcEncCheckInfo checkInfo)
{
    if (!CheckAstcEncInput(param, checkInfo)) {
        IMAGE_LOGE("CheckAstcEncInput failed");
        return false;
    }
    bool ret = false;
    // GPU encode only support size>=256x256, block=4x4 now
#ifdef ENABLE_ASTC_ENCODE_BASED_GPU
    bool openClEnc = param.width_ >= WIDTH_CL_THRESHOLD && param.height_ >= HEIGHT_CL_THRESHOLD &&
        param.privateProfile_ == QualityProfile::HIGH_SPEED_PROFILE;
    bool enableClEnc = openClEnc && (param.blockX_ == DEFAULT_DIM) && (param.blockY_ == DEFAULT_DIM);
    if (enableClEnc) {
        IMAGE_LOGI("GPU astc encode begin...");
        std::string clBinPath = "/data/local/tmp/AstcEncShader.bin";
        ret = AstcCodec::TryAstcEncBasedOnCl(param, pixmapIn, astcBuffer, clBinPath);
        if (!ret) {
            IMAGE_LOGE("GPU astc encode failed!");
        }
    }
#endif
    // Software encode
    IMAGE_LOGI("software astc encode begin...");
    ret = AstcCodec::AstcSoftwareEncodeCore(param, pixmapIn, astcBuffer);
    if (!ret) {
        IMAGE_LOGE("software astc encode failed!");
    }
    return ret;
}

bool TextureEncMainFuzzTest(const uint8_t *data, size_t size)
{
    ParamRand paramRand = GetParametersRandom(data, size);
    // Create pixelMap
    size_t pixelMapBytes = paramRand.width * paramRand.height * BYTES_PER_PIXEL;
    uint8_t *pixmapIn = static_cast<uint8_t *>(malloc(pixelMapBytes));
    if (pixmapIn == nullptr) {
        IMAGE_LOGE("TextureEncMainFuzzTest pixmapIn invalid!");
        return ERROR;
    }
    FillPixelMap(pixmapIn, pixelMapBytes);
    // Initialize params
    TextureEncodeOptions param;
    uint8_t colorData;
    InitTextureEncodeOptions(param, colorData);
    param.extInfoBuf = &colorData;
    PlEncodeOptions astcOpts = { paramRand.format, paramRand.quality, 1 };
    if (!InitAstcEncPara(param, paramRand, astcOpts)) {
        IMAGE_LOGE("TextureEncMainFuzzTest InitAstcEncPara failed!");
        free(pixmapIn);
        return ERROR;
    }
    // Create astcBuffer
    AstcExtendInfo extendInfo = {0};
    if (!InitAstcExtendInfo(extendInfo)) {
        IMAGE_LOGE("TextureEncMainFuzzTest InitAstcExtendInfo failed!");
        free(pixmapIn);
        return ERROR;
    }
    uint32_t packSize = static_cast<uint32_t>(param.astcBytes) + extendInfo.extendBufferSumBytes + ASTC_NUM_4;
    uint8_t *astcBuffer = static_cast<uint8_t *>(malloc(packSize));
    if (astcBuffer == nullptr) {
        IMAGE_LOGE("TextureEncMainFuzzTest astcBuffer invalid!");
        free(pixmapIn);
        ReleaseExtendInfoMemory(extendInfo);
        return ERROR;
    }
    // Fill checkInfo
    AstcEncCheckInfo checkInfo;
    FillAstcEncCheckInfo(checkInfo, pixelMapBytes, packSize, ASTC_NUM_4, extendInfo.extendBufferSumBytes);
    if (param.privateProfile_ == HIGH_SPEED_PROFILE_HIGHBITS) {
        checkInfo.pixmapFormat = PixelFormat::RGBA_1010102;
    } else {
        checkInfo.pixmapFormat = PixelFormat::RGBA_8888;
    }
    // GPU & Software astc encode process
    AstcEncProcess(param, pixmapIn, astcBuffer, checkInfo);

    free(pixmapIn);
    free(astcBuffer);
    ReleaseExtendInfoMemory(extendInfo);
    return true;
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::DumpSingleInput(data, size);
    OHOS::Media::TextureEncMainFuzzTest(data, size);
    return 0;
}