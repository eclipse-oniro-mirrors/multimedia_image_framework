/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_TEXTURE_ENCODE_TEXTURE_TYPE_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_TEXTURE_ENCODE_TEXTURE_TYPE_H

#include "astcenc.h"
#ifndef QUALITY_CONTROL
#define QUALITY_CONTROL (1)
#endif
namespace OHOS {
namespace ImagePlugin {
enum class SutProfile {
    EXTREME_SPEED = 0,
    EXTREME_SPEED_A = 1,
    HIGH_CR_LEVEL1 = 2,
    SKIP_SUT = 255
}; // the profile of superCompress for texture

constexpr uint8_t ASTC_EXTEND_INFO_TLV_NUM = 1; // curren only one group TLV
constexpr uint8_t ASTC_EXTEND_INFO_TLV_NUM_2 = 2;
constexpr uint8_t ASTC_EXTEND_INFO_TLV_NUM_4 = 4;
constexpr uint8_t ASTC_EXTEND_INFO_TLV_NUM_6 = 6;
constexpr uint32_t ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH = 4; // 4 bytes to discripte for extend info summary bytes
constexpr uint8_t ASTC_EXTEND_INFO_TYPE_LENGTH = 1; // 1 byte to discripte the content type for every TLV group
constexpr uint32_t ASTC_EXTEND_INFO_LENGTH_LENGTH = 4; // 4 bytes to discripte the content bytes for every TLV group
constexpr uint8_t ASTC_EXTEND_INFO_COLOR_SPACE_VALUE_LENGTH = 1; // 1 bytes to discripte the content for color space
constexpr uint8_t ASTC_EXTEND_INFO_PIXEL_FORMAT_VALUE_LENGTH = 1; // 1 bytes to discripte the content for pixel format

enum class TextureEncodeType {
    ASTC = 0,
    SDR_SUT_SUPERFAST_4X4 = 1,
    SDR_ASTC_4X4 = 2,
    HDR_ASTC_4X4 = 3,
};

struct TextureEncodeOptions {
    int32_t width_;
    int32_t height_;
    uint8_t blockX_;
    uint8_t blockY_;
    int32_t stride_;
    QualityProfile privateProfile_; // enum type defined in astc-encoder module: HIGH_QUALITY_PROFILE HIGH_SPEED_PROFILE
    int32_t blocksNum;
    int32_t astcBytes;
    bool enableQualityCheck;
    bool hardwareFlag;
    SutProfile sutProfile;
    int32_t sutBytes;
    bool outIsSut;
    uint8_t expandNums;
    uint8_t *extInfoBuf;
    int32_t extInfoBytes;
    TextureEncodeType textureEncodeType;
};

struct AstcEncoder {
    astcenc_config config;
    astcenc_profile profile;
    astcenc_context* codec_context;
    astcenc_image image_;
    astcenc_swizzle swizzle_;
    uint8_t* data_out_;
    astcenc_error error_;
#if defined(QUALITY_CONTROL) && (QUALITY_CONTROL == 1)
    bool calQualityEnable;
    int32_t *mse[RGBA_COM + 1];
#endif
};

using SutQulityProfile = std::tuple<uint8_t, SutProfile, QualityProfile>;

inline static const std::map<std::string, SutQulityProfile> SUT_FORMAT_MAP = {
    {"image/sdr_sut_superfast_4x4",
        {92, SutProfile::HIGH_CR_LEVEL1, QualityProfile::CUSTOMIZED_PROFILE}},
};

inline static const std::map<std::string, std::map<uint8_t, QualityProfile>> ASTC_FORMAT_MAP = {
    {
        "image/sdr_astc_4x4",
        {
            { 92, QualityProfile::CUSTOMIZED_PROFILE },
            { 85, QualityProfile::HIGH_SPEED_PROFILE }
        }
    },
    {
        "image/hdr_astc_4x4",
        {
            { 85, QualityProfile::HIGH_SPEED_PROFILE_HIGHBITS }
        }
    }
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_TEXTURE_ENCODE_TEXTURE_TYPE_H
