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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_TYPE_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_TYPE_H

#include <vector>
#include "heif_utils.h"

namespace OHOS {
namespace ImagePlugin {
static const uint32_t BOX_TYPE_FTYP = fourcc_to_code("ftyp");
static const uint32_t BOX_TYPE_META = fourcc_to_code("meta");
static const uint32_t BOX_TYPE_HDLR = fourcc_to_code("hdlr");
static const uint32_t BOX_TYPE_ILOC = fourcc_to_code("iloc");
static const uint32_t BOX_TYPE_PITM = fourcc_to_code("pitm");
static const uint32_t BOX_TYPE_INFE = fourcc_to_code("infe");
static const uint32_t BOX_TYPE_IINF = fourcc_to_code("iinf");
static const uint32_t BOX_TYPE_PTIM = fourcc_to_code("ptim");
static const uint32_t BOX_TYPE_IPRP = fourcc_to_code("iprp");
static const uint32_t BOX_TYPE_AUXC = fourcc_to_code("auxC");
static const uint32_t BOX_TYPE_AUXL = fourcc_to_code("auxl");
static const uint32_t BOX_TYPE_IPCO = fourcc_to_code("ipco");
static const uint32_t BOX_TYPE_IPMA = fourcc_to_code("ipma");
static const uint32_t BOX_TYPE_ISPE = fourcc_to_code("ispe");
static const uint32_t BOX_TYPE_PIXI = fourcc_to_code("pixi");
static const uint32_t BOX_TYPE_COLR = fourcc_to_code("colr");
static const uint32_t BOX_TYPE_NCLX = fourcc_to_code("nclx");
static const uint32_t BOX_TYPE_HVCC = fourcc_to_code("hvcC");
static const uint32_t BOX_TYPE_IROT = fourcc_to_code("irot");
static const uint32_t BOX_TYPE_IMIR = fourcc_to_code("imir");
static const uint32_t BOX_TYPE_IREF = fourcc_to_code("iref");
static const uint32_t BOX_TYPE_IDAT = fourcc_to_code("idat");
static const uint32_t BOX_TYPE_MDAT = fourcc_to_code("mdat");
static const uint32_t BOX_TYPE_UUID = fourcc_to_code("uuid");
static const uint32_t BOX_TYPE_THMB = fourcc_to_code("thmb");
static const uint32_t BOX_TYPE_DIMG = fourcc_to_code("dimg");
static const uint32_t BOX_TYPE_CDSC = fourcc_to_code("cdsc");

static const uint32_t BOX_TYPE_CLLI = fourcc_to_code("clli");
static const uint32_t BOX_TYPE_MDCV = fourcc_to_code("mdcv");
static const uint32_t BOX_TYPE_IT35 = fourcc_to_code("it35");

static const uint32_t HANDLER_TYPE_PICT = fourcc_to_code("pict");

static const uint32_t ITEM_TYPE_MIME = fourcc_to_code("mime");
static const uint32_t ITEM_TYPE_URI = fourcc_to_code("uri ");

static const uint32_t COLOR_TYPE_PROF = fourcc_to_code("prof");
static const uint32_t COLOR_TYPE_RICC = fourcc_to_code("rICC");

typedef uint32_t heif_item_id;

typedef uint32_t heif_brand;

enum HeifBoxVersion {
    HEIF_BOX_VERSION_ZERO = 0,
    HEIF_BOX_VERSION_ONE = 1,
    HEIF_BOX_VERSION_TWO = 2,
    HEIF_BOX_VERSION_THREE = 3,
};

enum class HeifColorFormat {
    UNDEDEFINED = 255,
    YCBCR = 0,
    RGB = 1,
    MONOCHROME = 2
};

enum class HeifPixelFormat {
    UNDEFINED = 255,
    MONOCHROME = 0,
    YUV420 = 1,
    YUV422 = 2,
    YUV444 = 3,
};

enum class HeifTransformMirrorDirection : uint8_t {
    VERTICAL = 0,
    HORIZONTAL = 1,
    INVALID = 2,
};

typedef uint32_t heif_property_id;

struct HeifMetadata {
    heif_item_id itemId;
    std::string itemType;
    std::string contentType;
    std::string itemUriType;
    std::vector<uint8_t> mData;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_TYPE_H
