/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
constexpr uint32_t ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH = 4; // 4 bytes to discripte for extend info summary bytes
constexpr uint8_t ASTC_EXTEND_INFO_TYPE_LENGTH = 1; // 1 byte to discripte the content type for every TLV group
constexpr uint32_t ASTC_EXTEND_INFO_LENGTH_LENGTH = 4; // 4 bytes to discripte the content bytes for every TLV group
constexpr uint8_t ASTC_EXTEND_INFO_COLOR_SPACE_VALUE_LENGTH = 1; // 1 bytes to discripte the content for color space

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

struct AstcExtendInfo {
    uint32_t extendBufferSumBytes = 0;
    uint8_t extendNums = ASTC_EXTEND_INFO_TLV_NUM;
    uint8_t extendInfoType[ASTC_EXTEND_INFO_TLV_NUM];
    uint32_t extendInfoLength[ASTC_EXTEND_INFO_TLV_NUM];
    uint8_t *extendInfoValue[ASTC_EXTEND_INFO_TLV_NUM];
};

enum class AstcExtendInfoType : uint8_t {
    COLOR_SPACE = 0
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_TEXTURE_ENCODE_TEXTURE_TYPE_H
