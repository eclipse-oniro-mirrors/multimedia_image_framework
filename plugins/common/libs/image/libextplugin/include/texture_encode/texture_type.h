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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_TEXTURE_ENCODE_TEXTURE_TYPE_H_
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_TEXTURE_ENCODE_TEXTURE_TYPE_H_

#include "astcenc.h"

namespace OHOS {
namespace Media {
typedef struct TextureEncodeOptionsType {
    int32_t width_;
    int32_t height_;
    uint8_t blockX_;
    uint8_t blockY_;
} TextureEncodeOptions;

struct astc_header {
    uint8_t magic[4];
    uint8_t block_x; // block_x info
    uint8_t block_y; // block_y info
    uint8_t block_z; // block_z info
    uint8_t dim_x[3];
    uint8_t dim_y[3];
    uint8_t dim_z[3];
};

typedef struct AstcEncoderInfo {
    astc_header head;
    astcenc_config config;
    astcenc_profile profile;
    astcenc_context* codec_context;
    astcenc_image image_;
    astcenc_swizzle swizzle_;
    uint8_t* data_out_;
    size_t data_len_;
    astcenc_error error_;
} AstcEncoder;
} // namespace Media
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_TEXTURE_ENCODE_TEXTURE_TYPE_H_