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
#ifndef WEBP_ENCODER_H
#define WEBP_ENCODER_H
#include <vector>
#include "abs_image_encoder.h"
#include "plugin_class_base.h"
#include "webp/encode.h"
#include "src/images/SkImageEncoderFns.h"
#include "include/core/SkStream.h"
namespace OHOS {
namespace ImagePlugin {
class WebpEncoder : public AbsImageEncoder, public OHOS::MultimediaPlugin::PluginClassBase {
public:
    WebpEncoder();
    ~WebpEncoder() override;
    uint32_t StartEncode(OutputDataStream &outputStream, PlEncodeOptions &option) override;
    uint32_t AddImage(Media::PixelMap &pixelMap) override;
    uint32_t FinalizeEncode() override;
    bool Write(const uint8_t* data, size_t data_size);

private:
    DISALLOW_COPY_AND_MOVE(WebpEncoder);
    bool CheckEncodeFormat(Media::PixelMap &pixelMap);
    uint32_t SetEncodeConfig(Media::PixelMap &pixelMap, WebPConfig &webpConfig, WebPPicture &webpPicture);
    uint32_t DoEncode(Media::PixelMap &pixelMap, WebPConfig &webpConfig, WebPPicture &webpPicture);
    uint32_t DoEncodeForICC(Media::PixelMap &pixelMap);
    bool DoTransform(Media::PixelMap &pixelMap, char* dst, int componentsNum);

private:
    Media::ColorSpace GetColorSpace(Media::PixelMap &pixelMap);
    Media::PixelFormat GetPixelFormat(Media::PixelMap &pixelMap);
    Media::AlphaType GetAlphaType(Media::PixelMap &pixelMap);
    bool GetIcc(Media::PixelMap &pixelMap);
    bool IsOpaque(Media::PixelMap &pixelMap);

private:
    static bool DoTransformMemcpy(Media::PixelMap &pixelMap, char* dst, int componentsNum);
    static bool DoTransformRGBX(Media::PixelMap &pixelMap, char* dst, int componentsNum);
    static bool DoTransformRgbA(Media::PixelMap &pixelMap, char* dst, int componentsNum);
    static bool DoTransformBGRX(Media::PixelMap &pixelMap, char* dst, int componentsNum);
    static bool DoTransformBGRA(Media::PixelMap &pixelMap, char* dst, int componentsNum);
    static bool DoTransformBgrA(Media::PixelMap &pixelMap, char* dst, int componentsNum);
    static bool DoTransformF16To8888(Media::PixelMap &pixelMap, char* dst, int componentsNum);
    static bool DoTransformF16pTo8888(Media::PixelMap &pixelMap, char* dst, int componentsNum);
    static bool DoTransformArgbToRgb(Media::PixelMap &pixelMap, char* dst, int componentsNum);
    static bool DoTransformArgbToRgba(Media::PixelMap &pixelMap, char* dst, int componentsNum);
    static bool DoTransformRGB565(Media::PixelMap &pixelMap, char* dst, int componentsNum);
    static bool DoTransformGray(Media::PixelMap &pixelMap, char* dst, int componentsNum);
    static Media::ImageInfo MakeImageInfo(int width, int height, Media::PixelFormat pf, Media::AlphaType at,
        Media::ColorSpace cs = Media::ColorSpace::SRGB);
    static void ShowTransformParam(const Media::ImageInfo &srcInfo, const uint32_t &srcRowBytes,
        const Media::ImageInfo &dstInfo, const uint32_t &dstRowBytes, const int &componentsNum);

private:
    OutputDataStream *outputStream_ {nullptr};
    SkDynamicMemoryWStream memoryStream_;
    std::vector<Media::PixelMap *> pixelMaps_;
    PlEncodeOptions encodeOpts_;

    int32_t componentsNum_ {0};

    // ICC data
    bool iccValid_ {false};
    uint8_t* iccBytes_ {nullptr};
    size_t iccSize_ {0};
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // WEBP_ENCODER_H
