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
#include "securec.h"
#include "texture_type.h"
#include "media_errors.h"
#include "hilog/log.h"
#include "log_tags.h"

namespace OHOS {
namespace ImagePlugin {
using namespace OHOS::HiviewDFX;
using namespace Media;
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_TAG_DOMAIN_ID_PLUGIN, "AstcCodec"};
}

constexpr uint8_t TEXTURE_HEAD_BYTES = 16;
constexpr uint8_t ASTC_MASK = 0xFF;
constexpr uint8_t ASTC_NUM_1 = 1;
constexpr uint8_t ASTC_NUM_2 = 2;
constexpr uint8_t ASTC_NUM_3 = 3;
constexpr uint8_t ASTC_NUM_8 = 8;
constexpr uint8_t ASTC_NUM_16 = 16;
constexpr uint8_t ASTC_NUM_24 = 24;
static const uint32_t ASTC_MAGIC_ID = 0x5CA1AB13;

uint32_t AstcCodec::SetAstcEncode(OutputDataStream* outputStream, PlEncodeOptions &option, Media::PixelMap* pixelMap)
{
    if (outputStream == nullptr || pixelMap == nullptr) {
        HiLog::Error(LABEL, "input data is nullptr.");
        return ERROR;
    }
    astcOutput_ = outputStream;
    astcOpts_ = option;
    astcPixelMap_ = pixelMap;
    return SUCCESS;
}

// test ASTCEncoder
uint32_t GenAstcHeader(astc_header &hdr, astcenc_image img, TextureEncodeOptions *encodeParams)
{
    if (encodeParams == nullptr) {
        HiLog::Error(LABEL, "input data is nullptr.");
        return ERROR;
    }
    hdr.magic[0] = ASTC_MAGIC_ID & ASTC_MASK;
    hdr.magic[ASTC_NUM_1] = (ASTC_MAGIC_ID >> ASTC_NUM_8) & ASTC_MASK;
    hdr.magic[ASTC_NUM_2] = (ASTC_MAGIC_ID >> ASTC_NUM_16) & ASTC_MASK;
    hdr.magic[ASTC_NUM_3] = (ASTC_MAGIC_ID >> ASTC_NUM_24) & ASTC_MASK;

    hdr.block_x = static_cast<uint8_t>(encodeParams->blockX_);
    hdr.block_y = static_cast<uint8_t>(encodeParams->blockY_);
    hdr.block_z = ASTC_NUM_1;

    hdr.dim_x[0] = img.dim_x & ASTC_MASK;
    hdr.dim_x[ASTC_NUM_1] = (img.dim_x >> ASTC_NUM_8) & ASTC_MASK;
    hdr.dim_x[ASTC_NUM_2] = (img.dim_x >> ASTC_NUM_16) & ASTC_MASK;

    hdr.dim_y[0] = img.dim_x & ASTC_MASK;
    hdr.dim_y[ASTC_NUM_1] = (img.dim_x >> ASTC_NUM_8) & ASTC_MASK;
    hdr.dim_y[ASTC_NUM_2] = (img.dim_x >> ASTC_NUM_16) & ASTC_MASK;

    hdr.dim_z[0] = img.dim_x & ASTC_MASK;
    hdr.dim_z[ASTC_NUM_1] = (img.dim_x >> ASTC_NUM_8) & ASTC_MASK;
    hdr.dim_z[ASTC_NUM_2] = (img.dim_x >> ASTC_NUM_16) & ASTC_MASK;
    return SUCCESS;
}

uint32_t InitAstcencConfig(astcenc_profile profile, TextureEncodeOptions *option, astcenc_config& config)
{
    if (option == nullptr) {
        HiLog::Error(LABEL, "input data is nullptr.");
        return ERROR;
    }
    unsigned int blockX = option->blockX_;
    unsigned int blockY = option->blockY_;
    unsigned int blockZ = 1;

    float quality = ASTCENC_PRE_FAST;
    unsigned int flags = 0;
    astcenc_error status = astcenc_config_init(profile, blockX, blockY,
        blockZ, quality, flags, &config);
    if (status == ASTCENC_ERR_BAD_BLOCK_SIZE) {
        HiLog::Error(LABEL, "ERROR: block size is invalid");
        return ERROR;
    } else if (status == ASTCENC_ERR_BAD_CPU_FLOAT) {
        HiLog::Error(LABEL, "ERROR: astcenc must not be compiled with fast-math");
        return ERROR;
    } else if (status != ASTCENC_SUCCESS) {
        HiLog::Error(LABEL, "ERROR: config failed");
        return ERROR;
    }
    return SUCCESS;
}

void extractDimensions(std::string &format, TextureEncodeOptions &param)
{
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

uint32_t AstcCodec::ASTCEncode()
{
    ImageInfo imageInfo;
    astcPixelMap_->GetImageInfo(imageInfo);
    TextureEncodeOptions param;
    param.width_ = imageInfo.size.width;
    param.height_ = imageInfo.size.height;
    extractDimensions(astcOpts_.format, param);

    AstcEncoder work;
    if (InitAstcencConfig(work.profile, &param, work.config) != SUCCESS) {
        HiLog::Error(LABEL, "astc InitAstcencConfig failed");
        return ERROR;
    }
    astcenc_context_alloc(&work.config, 1, &work.codec_context);
    work.swizzle_ = {ASTCENC_SWZ_R, ASTCENC_SWZ_G, ASTCENC_SWZ_B, ASTCENC_SWZ_A};
    work.image_.dim_x = param.width_;
    work.image_.dim_y = param.height_;
    work.image_.dim_z = 1;
    work.image_.data_type = ASTCENC_TYPE_U8;
    work.image_.data = (void **)malloc(sizeof(void*) * work.image_.dim_z);
    if (GenAstcHeader(work.head, work.image_, &param) != SUCCESS) {
        HiLog::Error(LABEL, "astc GenAstcHeader failed");
        return ERROR;
    }

    work.image_.data[0] = static_cast<uint8_t *>(astcPixelMap_->GetWritablePixels());
    int outSize = ((param.width_ + param.blockX_ - 1) / param.blockX_) *
        ((param.height_ + param.blockY_ -1) / param.blockY_) * TEXTURE_HEAD_BYTES + TEXTURE_HEAD_BYTES;

    errno_t ret = memcpy_s(astcOutput_->GetAddr(), sizeof(astc_header), &work.head, sizeof(astc_header));
    if (ret != 0) {
        HiLog::Error(LABEL, "astc memcpy_s failed");
        return ERROR;
    }
    work.data_out_ = astcOutput_->GetAddr() + TEXTURE_HEAD_BYTES;
    work.data_len_ = outSize - TEXTURE_HEAD_BYTES;
    work.error_ = astcenc_compress_image(work.codec_context, &work.image_, &work.swizzle_,
                                         work.data_out_, work.data_len_, 0);
    if (ASTCENC_SUCCESS != work.error_) {
        HiLog::Error(LABEL, "astc compress failed");
        return ERROR;
    }
    astcOutput_->SetOffset(outSize);
    return SUCCESS;
}
} // namespace ImagePlugin
} // namespace OHOS