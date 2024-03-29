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
#include "image_type_converter.h"

namespace OHOS {
namespace Media {
const static int DEFAULT_INDEX = 0;
using std::string;
struct PixelFormatPair {
    SkColorType skColorType;
    PixelFormat pixelFormat;
    string skColorTypeName;
    string pixelFormatName;
};

struct AlphaTypePair {
    SkAlphaType skAlphaType;
    AlphaType alphaType;
    string skAlphaTypeName;
    string alphaTypeName;
};

static PixelFormatPair g_pixelFormatPairs[] = {
    {SkColorType::kUnknown_SkColorType, PixelFormat::UNKNOWN,
        "kUnknown_SkColorType", "PixelFormat::UNKNOWN"},
    {SkColorType::kRGBA_8888_SkColorType, PixelFormat::ARGB_8888,
        "kRGBA_8888_SkColorType", "PixelFormat::ARGB_8888"},
    {SkColorType::kRGBA_1010102_SkColorType, PixelFormat::RGBA_1010102,
        "kRGBA_1010102_SkColorType", "PixelFormat::RGBA_1010102"},
    {SkColorType::kAlpha_8_SkColorType, PixelFormat::ALPHA_8,
        "kAlpha_8_SkColorType", "PixelFormat::ALPHA_8"},
    {SkColorType::kRGB_565_SkColorType, PixelFormat::RGB_565,
        "kRGB_565_SkColorType", "PixelFormat::RGB_565"},
    {SkColorType::kRGBA_F16_SkColorType, PixelFormat::RGBA_F16,
        "kRGBA_F16_SkColorType", "PixelFormat::RGBA_F16"},
    {SkColorType::kRGBA_8888_SkColorType, PixelFormat::RGBA_8888,
        "kRGBA_8888_SkColorType", "PixelFormat::RGBA_8888"},
    {SkColorType::kBGRA_8888_SkColorType, PixelFormat::BGRA_8888,
        "kBGRA_8888_SkColorType", "PixelFormat::BGRA_8888"},
    {SkColorType::kRGB_888x_SkColorType, PixelFormat::RGB_888,
        "kRGB_888x_SkColorType", "PixelFormat::RGB_888"},
};

static AlphaTypePair g_alphaTypePairs[] = {
    {SkAlphaType::kUnknown_SkAlphaType, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        "kUnknown_SkAlphaType", "AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN"},
    {SkAlphaType::kOpaque_SkAlphaType, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        "kOpaque_SkAlphaType", "AlphaType::IMAGE_ALPHA_TYPE_OPAQUE"},
    {SkAlphaType::kPremul_SkAlphaType, AlphaType::IMAGE_ALPHA_TYPE_PREMUL,
        "kPremul_SkAlphaType", "AlphaType::IMAGE_ALPHA_TYPE_PREMUL"},
    {SkAlphaType::kUnpremul_SkAlphaType, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL,
        "kUnpremul_SkAlphaType", "AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL"},
};

template<typename T, typename C, unsigned L>
static T Find(T (&infos)[L], C compare)
{
    for (T iter : infos) {
        if (compare(iter)) {
            return iter;
        }
    }
    return infos[DEFAULT_INDEX];
}

SkColorType ImageTypeConverter::ToSkColorType(const PixelFormat pixelFormat)
{
    auto res = Find(g_pixelFormatPairs, [pixelFormat](PixelFormatPair iter) {
        return (iter.pixelFormat == pixelFormat);
    });
    return res.skColorType;
}

SkAlphaType ImageTypeConverter::ToSkAlphaType(const AlphaType alphaType)
{
    auto res = Find(g_alphaTypePairs, [alphaType](AlphaTypePair iter) {
        return (iter.alphaType == alphaType);
    });
    return res.skAlphaType;
}

PixelFormat ImageTypeConverter::ToPixelFormat(const SkColorType type)
{
    auto res = Find(g_pixelFormatPairs, [type](PixelFormatPair iter) {
        return (iter.skColorType == type);
    });
    return res.pixelFormat;
}

AlphaType ImageTypeConverter::ToAlphaType(const SkAlphaType type)
{
    auto res = Find(g_alphaTypePairs, [type](AlphaTypePair iter) {
        return (iter.skAlphaType == type);
    });
    return res.alphaType;
}

const string ImageTypeConverter::ToName(const PixelFormat pixelFormat)
{
    auto res = Find(g_pixelFormatPairs, [pixelFormat](PixelFormatPair iter) {
        return (iter.pixelFormat == pixelFormat);
    });
    return res.pixelFormatName;
}

const string ImageTypeConverter::ToName(const AlphaType alphaType)
{
    auto res = Find(g_alphaTypePairs, [alphaType](AlphaTypePair iter) {
        return (iter.alphaType == alphaType);
    });
    return res.alphaTypeName;
}

const string ImageTypeConverter::ToName(const SkColorType type)
{
    auto res = Find(g_pixelFormatPairs, [type](PixelFormatPair iter) {
        return (iter.skColorType == type);
    });
    return res.skColorTypeName;
}

const string ImageTypeConverter::ToName(const SkAlphaType type)
{
    auto res = Find(g_alphaTypePairs, [type](AlphaTypePair iter) {
        return (iter.skAlphaType == type);
    });
    return res.skAlphaTypeName;
}
} // namespace Media
} // namespace OHOS