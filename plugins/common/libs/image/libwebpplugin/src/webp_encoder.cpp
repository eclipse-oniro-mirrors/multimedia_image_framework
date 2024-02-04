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
#include "webp_encoder.h"
#include "webp/mux.h"
#include "image_log.h"
#include "image_trace.h"
#include "media_errors.h"
#include "pixel_convert_adapter.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "WebpEncoder"

namespace OHOS {
namespace ImagePlugin {
using namespace MultimediaPlugin;
using namespace Media;
namespace {
constexpr uint32_t WEBP_IMAGE_NUM = 1;
constexpr uint32_t COMPONENT_NUM_3 = 3;
constexpr uint32_t COMPONENT_NUM_4 = 4;
} // namespace

static int StreamWriter(const uint8_t* data, size_t data_size, const WebPPicture* const picture)
{
    IMAGE_LOGD("StreamWriter data_size=%{public}zu", data_size);

    auto webpEncoder = static_cast<WebpEncoder*>(picture->custom_ptr);
    return webpEncoder->Write(data, data_size) ? 1 : 0;
}

WebpEncoder::WebpEncoder()
{
    IMAGE_LOGD("create IN");

    IMAGE_LOGD("create OUT");
}

WebpEncoder::~WebpEncoder()
{
    IMAGE_LOGD("release IN");

    pixelMaps_.clear();

    IMAGE_LOGD("release OUT");
}

uint32_t WebpEncoder::StartEncode(OutputDataStream &outputStream, PlEncodeOptions &option)
{
    ImageTrace imageTrace("WebpEncoder::StartEncode");
    IMAGE_LOGD("StartEncode IN, quality=%{public}u, numberHint=%{public}u",
        option.quality, option.numberHint);

    pixelMaps_.clear();

    outputStream_ = &outputStream;
    encodeOpts_ = option;

    IMAGE_LOGD("StartEncode OUT");
    return SUCCESS;
}

uint32_t WebpEncoder::AddImage(Media::PixelMap &pixelMap)
{
    ImageTrace imageTrace("WebpEncoder::AddImage");
    IMAGE_LOGD("AddImage IN");

    if (pixelMaps_.size() >= WEBP_IMAGE_NUM) {
        IMAGE_LOGE("AddImage, add pixel map out of range=%{public}u.", WEBP_IMAGE_NUM);
        return ERR_IMAGE_ADD_PIXEL_MAP_FAILED;
    }

    pixelMaps_.push_back(&pixelMap);

    IMAGE_LOGD("AddImage OUT");
    return SUCCESS;
}

uint32_t WebpEncoder::FinalizeEncode()
{
    ImageTrace imageTrace("WebpEncoder::FinalizeEncode");
    IMAGE_LOGD("FinalizeEncode IN");

    if (pixelMaps_.empty()) {
        IMAGE_LOGE("FinalizeEncode, no pixel map input.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    IMAGE_LOGD("FinalizeEncode, quality=%{public}u, numberHint=%{public}u",
        encodeOpts_.quality, encodeOpts_.numberHint);

    uint32_t errorCode = ERROR;

    Media::PixelMap &pixelMap = *(pixelMaps_[0]);
    WebPConfig webpConfig;
    WebPPicture webpPicture;
    WebPPictureInit(&webpPicture);

    errorCode = SetEncodeConfig(pixelMap, webpConfig, webpPicture);
    IMAGE_LOGD("FinalizeEncode, config, %{public}u.", errorCode);

    if (errorCode != SUCCESS) {
        IMAGE_LOGE("FinalizeEncode, config failed=%{public}u.", errorCode);
        WebPPictureFree(&webpPicture);
        return errorCode;
    }

    errorCode = DoEncode(pixelMap, webpConfig, webpPicture);
    IMAGE_LOGD("FinalizeEncode, encode,%{public}u.", errorCode);
    WebPPictureFree(&webpPicture);

    if (errorCode != SUCCESS) {
        IMAGE_LOGE("FinalizeEncode, encode failed=%{public}u.", errorCode);
    }

    IMAGE_LOGD("FinalizeEncode OUT");
    return errorCode;
}

bool WebpEncoder::Write(const uint8_t* data, size_t data_size)
{
    IMAGE_LOGD("Write data_size=%{public}zu, iccValid=%{public}d", data_size, iccValid_);

    if (iccValid_) {
        return memoryStream_.write(data, data_size);
    }

    return outputStream_->Write(data, data_size);
}

bool WebpEncoder::CheckEncodeFormat(Media::PixelMap &pixelMap)
{
    PixelFormat pixelFormat = GetPixelFormat(pixelMap);
    IMAGE_LOGD("CheckEncodeFormat, pixelFormat=%{public}u", pixelFormat);

    switch (pixelFormat) {
        case PixelFormat::RGBA_8888: {
            IMAGE_LOGD("CheckEncodeFormat, RGBA_8888");
            return true;
        }
        case PixelFormat::BGRA_8888: {
            IMAGE_LOGD("CheckEncodeFormat, BGRA_8888");
            return true;
        }
        case PixelFormat::RGBA_F16: {
            IMAGE_LOGD("CheckEncodeFormat, RGBA_F16");
            return true;
        }
        case PixelFormat::ARGB_8888: {
            IMAGE_LOGD("CheckEncodeFormat, ARGB_8888");
            return true;
        }
        case PixelFormat::RGB_888: {
            IMAGE_LOGD("CheckEncodeFormat, RGB_888");
            return true;
        }
        case PixelFormat::RGB_565: {
            bool isOpaque = IsOpaque(pixelMap);
            IMAGE_LOGD("CheckEncodeFormat, RGB_565, isOpaque=%{public}d", isOpaque);
            return isOpaque;
        }
        case PixelFormat::ALPHA_8: {
            IMAGE_LOGD("CheckEncodeFormat, ALPHA_8");
            return true;
        }
        default: {
            IMAGE_LOGE("CheckEncodeFormat, pixelFormat=%{public}u", pixelFormat);
            return false;
        }
    }
}

bool WebpEncoder::DoTransform(Media::PixelMap &pixelMap, char* dst, int componentsNum)
{
    IMAGE_LOGD("DoTransform IN");

    PixelFormat pixelFormat = GetPixelFormat(pixelMap);
    AlphaType alphaType = GetAlphaType(pixelMap);
    IMAGE_LOGD("DoTransform, pixelFormat=%{public}u, alphaType=%{public}d, componentsNum=%{public}d",
        pixelFormat, alphaType, componentsNum);

    if ((pixelFormat == PixelFormat::RGBA_8888) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
        return DoTransformRGBX(pixelMap, dst, componentsNum);
    } else if ((pixelFormat == PixelFormat::RGBA_8888) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL)) {
        return DoTransformMemcpy(pixelMap, dst, componentsNum);
    } else if ((pixelFormat == PixelFormat::RGBA_8888) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_PREMUL)) {
        return DoTransformRgbA(pixelMap, dst, componentsNum);
    } else if ((pixelFormat == PixelFormat::BGRA_8888) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
        return DoTransformBGRX(pixelMap, dst, componentsNum);
    } else if ((pixelFormat == PixelFormat::BGRA_8888) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL)) {
        return DoTransformBGRA(pixelMap, dst, componentsNum);
    } else if ((pixelFormat == PixelFormat::BGRA_8888) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_PREMUL)) {
        return DoTransformBgrA(pixelMap, dst, componentsNum);
    } else if ((pixelFormat == PixelFormat::RGBA_F16) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
        return DoTransformF16To8888(pixelMap, dst, componentsNum);
    } else if ((pixelFormat == PixelFormat::RGBA_F16) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL)) {
        return DoTransformF16To8888(pixelMap, dst, componentsNum);
    } else if ((pixelFormat == PixelFormat::RGBA_F16) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_PREMUL)) {
        return DoTransformF16pTo8888(pixelMap, dst, componentsNum);
    } else if ((pixelFormat == PixelFormat::ARGB_8888) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
        return DoTransformArgbToRgb(pixelMap, dst, componentsNum);
    } else if ((pixelFormat == PixelFormat::ARGB_8888) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL)) {
        return DoTransformArgbToRgba(pixelMap, dst, componentsNum);
    } else if ((pixelFormat == PixelFormat::ARGB_8888) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_PREMUL)) {
        return DoTransformArgbToRgba(pixelMap, dst, componentsNum);
    } else if (pixelFormat == PixelFormat::RGB_888) {
        return DoTransformMemcpy(pixelMap, dst, componentsNum);
    } else if ((pixelFormat == PixelFormat::RGB_565) && IsOpaque(pixelMap)) {
        IMAGE_LOGD("DoTransform, RGB_565, Opaque");
        return DoTransformRGB565(pixelMap, dst, componentsNum);
    } else if (pixelFormat == PixelFormat::ALPHA_8) {
        IMAGE_LOGD("DoTransform, ALPHA_8");
        return DoTransformGray(pixelMap, dst, componentsNum);
    }

    IMAGE_LOGD("DoTransform OUT");
    return false;
}

uint32_t WebpEncoder::SetEncodeConfig(Media::PixelMap &pixelMap, WebPConfig &webpConfig, WebPPicture &webpPicture)
{
    IMAGE_LOGD("SetEncodeConfig IN");

    if (pixelMap.GetPixels() == nullptr) {
        IMAGE_LOGE("SetEncodeConfig, pixels invalid.");
        return ERROR;
    }

    if (!CheckEncodeFormat(pixelMap)) {
        IMAGE_LOGE("SetEncodeConfig, check invalid.");
        return ERR_IMAGE_UNKNOWN_FORMAT;
    }

    if (GetPixelFormat(pixelMap) == PixelFormat::RGBA_F16) {
        componentsNum_ = COMPONENT_NUM_4;
    } else {
        componentsNum_ = IsOpaque(pixelMap) ? COMPONENT_NUM_3 : COMPONENT_NUM_4;
    }
    IMAGE_LOGD("SetEncodeConfig, componentsNum=%{public}u", componentsNum_);

    if (!WebPConfigPreset(&webpConfig, WEBP_PRESET_DEFAULT, encodeOpts_.quality)) {
        IMAGE_LOGE("SetEncodeConfig, config preset issue.");
        return ERROR;
    }

    GetIcc(pixelMap);

    webpConfig.lossless = 1; // Lossless encoding (0=lossy(default), 1=lossless).
    webpConfig.method = 0; // quality/speed trade-off (0=fast, 6=slower-better)
    webpPicture.use_argb = 1; // Main flag for encoder selecting between ARGB or YUV input.

    webpPicture.width = pixelMap.GetWidth(); // dimensions (less or equal to WEBP_MAX_DIMENSION)
    webpPicture.height = pixelMap.GetHeight(); // dimensions (less or equal to WEBP_MAX_DIMENSION)
    webpPicture.writer = StreamWriter;
    webpPicture.custom_ptr = static_cast<void*>(this);

    auto colorSpace = GetColorSpace(pixelMap);
    IMAGE_LOGD("SetEncodeConfig, "
        "width=%{public}u, height=%{public}u, colorspace=%{public}d, componentsNum=%{public}d.",
        webpPicture.width, webpPicture.height, colorSpace, componentsNum_);

    IMAGE_LOGD("SetEncodeConfig OUT");
    return SUCCESS;
}

uint32_t WebpEncoder::DoEncode(Media::PixelMap &pixelMap, WebPConfig &webpConfig, WebPPicture &webpPicture)
{
    IMAGE_LOGD("DoEncode IN");

    const int width = pixelMap.GetWidth();
    const int height = webpPicture.height;
    const int rgbStride = width * componentsNum_;
    const int rgbSize = rgbStride * height;
    IMAGE_LOGD("DoEncode, width=%{public}d, height=%{public}d, componentsNum=%{public}d,"
        " rgbStride=%{public}d, rgbSize=%{public}d", width, height, componentsNum_, rgbStride, rgbSize);

    std::unique_ptr<uint8_t[]> rgb = std::make_unique<uint8_t[]>(rgbSize);
    if (!DoTransform(pixelMap, reinterpret_cast<char*>(&rgb[0]), componentsNum_)) {
        IMAGE_LOGE("DoEncode, transform issue.");
        return ERROR;
    }

    auto importProc = WebPPictureImportRGB;
    if (componentsNum_ != COMPONENT_NUM_3) {
        importProc = (IsOpaque(pixelMap)) ? WebPPictureImportRGBX : WebPPictureImportRGBA;
    }

    IMAGE_LOGD("DoEncode, importProc");
    if (!importProc(&webpPicture, &rgb[0], rgbStride)) {
        IMAGE_LOGE("DoEncode, import issue.");
        return ERROR;
    }

    IMAGE_LOGD("DoEncode, WebPEncode");
    if (!WebPEncode(&webpConfig, &webpPicture)) {
        IMAGE_LOGE("DoEncode, encode issue.");
        return ERROR;
    }

    IMAGE_LOGD("DoEncode, iccValid=%{public}d", iccValid_);
    if (iccValid_) {
        auto res = DoEncodeForICC(pixelMap);
        if (res != SUCCESS) {
            IMAGE_LOGE("DoEncode, encode for icc issue.");
            return res;
        }
    }

    IMAGE_LOGD("DoEncode OUT");
    return SUCCESS;
}

uint32_t WebpEncoder::DoEncodeForICC(Media::PixelMap &pixelMap)
{
    IMAGE_LOGD("DoEncodeForICC IN");

    auto encodedData = memoryStream_.detachAsData();
    WebPData webpEncode = { encodedData->bytes(), encodedData->size() };
    WebPData webpIcc = { iccBytes_, iccSize_ };

    auto mux = WebPMuxNew();
    if (WebPMuxSetImage(mux, &webpEncode, 0) != WEBP_MUX_OK) {
        IMAGE_LOGE("DoEncodeForICC, image issue.");
        WebPMuxDelete(mux);
        return ERROR;
    }

    if (WebPMuxSetChunk(mux, "ICCP", &webpIcc, 0) != WEBP_MUX_OK) {
        IMAGE_LOGE("DoEncodeForICC, icc issue.");
        WebPMuxDelete(mux);
        return ERROR;
    }

    WebPData webpAssembled;
    if (WebPMuxAssemble(mux, &webpAssembled) != WEBP_MUX_OK) {
        IMAGE_LOGE("DoEncodeForICC, assemble issue.");
        WebPMuxDelete(mux);
        return ERROR;
    }

    outputStream_->Write(webpAssembled.bytes, webpAssembled.size);
    WebPDataClear(&webpAssembled);
    WebPMuxDelete(mux);

    IMAGE_LOGD("DoEncodeForICC OUT");
    return SUCCESS;
}

ColorSpace WebpEncoder::GetColorSpace(Media::PixelMap &pixelMap)
{
    return pixelMap.GetColorSpace();
}

PixelFormat WebpEncoder::GetPixelFormat(Media::PixelMap &pixelMap)
{
    return pixelMap.GetPixelFormat();
}

AlphaType WebpEncoder::GetAlphaType(Media::PixelMap &pixelMap)
{
    return pixelMap.GetAlphaType();
}

bool WebpEncoder::GetIcc(Media::PixelMap &pixelMap)
{
    return iccValid_;
}

bool WebpEncoder::IsOpaque(Media::PixelMap &pixelMap)
{
    return (GetAlphaType(pixelMap) == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);
}

bool WebpEncoder::DoTransformMemcpy(Media::PixelMap &pixelMap, char* dst, int componentsNum)
{
    IMAGE_LOGD("DoTransformMemcpy IN");

    auto src = pixelMap.GetPixels();
    if ((src == nullptr) || (dst == nullptr)) {
        IMAGE_LOGE("DoTransformMemcpy, address issue.");
        return false;
    }

    const int32_t width = pixelMap.GetWidth();
    const int32_t height = pixelMap.GetHeight();
    const uint32_t rowBytes = pixelMap.GetRowBytes();
    const int stride = pixelMap.GetWidth() * componentsNum;

    IMAGE_LOGD("width=%{public}u, height=%{public}u, rowBytes=%{public}u, stride=%{public}d, componentsNum=%{public}d",
        width, height, rowBytes, stride, componentsNum);

    for (int32_t h = 0; h < height; h++) {
        transform_scanline_memcpy(reinterpret_cast<char*>(&dst[h * stride]),
            reinterpret_cast<const char*>(&src[h * rowBytes]),
            width, componentsNum);
    }

    IMAGE_LOGD("DoTransformMemcpy OUT");
    return true;
}

bool WebpEncoder::DoTransformRGBX(Media::PixelMap &pixelMap, char* dst, int componentsNum)
{
    IMAGE_LOGD("DoTransformRGBX IN");

    const void *srcPixels = pixelMap.GetPixels();
    uint32_t srcRowBytes = pixelMap.GetRowBytes();
    const ImageInfo srcInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);

    void *dstPixels = dst;
    uint32_t dstRowBytes = pixelMap.GetWidth() * componentsNum;
    const ImageInfo dstInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGB_888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    ShowTransformParam(srcInfo, srcRowBytes, dstInfo, dstRowBytes, componentsNum);

    if ((srcPixels == nullptr) || (dstPixels == nullptr)) {
        IMAGE_LOGE("DoTransformRGBX, address issue.");
        return false;
    }

    const Position dstPos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcPixels, srcRowBytes, srcInfo,
        dstPixels, dstPos, dstRowBytes, dstInfo)) {
        IMAGE_LOGE("DoTransformRGBX, pixel convert in adapter failed.");
        return false;
    }

    IMAGE_LOGD("DoTransformRGBX OUT");
    return true;
}

bool WebpEncoder::DoTransformRgbA(Media::PixelMap &pixelMap, char* dst, int componentsNum)
{
    IMAGE_LOGD("DoTransformRgbA IN");

    const void *srcPixels = pixelMap.GetPixels();
    uint32_t srcRowBytes = pixelMap.GetRowBytes();
    const ImageInfo srcInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);

    void *dstPixels = dst;
    uint32_t dstRowBytes = pixelMap.GetWidth() * componentsNum;
    const ImageInfo dstInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    ShowTransformParam(srcInfo, srcRowBytes, dstInfo, dstRowBytes, componentsNum);

    if ((srcPixels == nullptr) || (dstPixels == nullptr)) {
        IMAGE_LOGE("DoTransformRgbA, address issue.");
        return false;
    }

    const Position dstPos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcPixels, srcRowBytes, srcInfo,
        dstPixels, dstPos, dstRowBytes, dstInfo)) {
        IMAGE_LOGE("DoTransformRgbA, pixel convert in adapter failed.");
        return false;
    }

    IMAGE_LOGD("DoTransformRgbA OUT");
    return true;
}

bool WebpEncoder::DoTransformBGRX(Media::PixelMap &pixelMap, char* dst, int componentsNum)
{
    IMAGE_LOGD("DoTransformBGRX IN");

    const void *srcPixels = pixelMap.GetPixels();
    uint32_t srcRowBytes = pixelMap.GetRowBytes();
    const ImageInfo srcInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    void *dstPixels = dst;
    uint32_t dstRowBytes = pixelMap.GetWidth() * componentsNum;
    const ImageInfo dstInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGB_888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    ShowTransformParam(srcInfo, srcRowBytes, dstInfo, dstRowBytes, componentsNum);

    if ((srcPixels == nullptr) || (dstPixels == nullptr)) {
        IMAGE_LOGE("DoTransformBGRX, address issue.");
        return false;
    }

    const Position dstPos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcPixels, srcRowBytes, srcInfo,
        dstPixels, dstPos, dstRowBytes, dstInfo)) {
        IMAGE_LOGE("DoTransformBGRX, pixel convert in adapter failed.");
        return false;
    }

    IMAGE_LOGD("DoTransformBGRX OUT");
    return true;
}

bool WebpEncoder::DoTransformBGRA(Media::PixelMap &pixelMap, char* dst, int componentsNum)
{
    IMAGE_LOGD("DoTransformBGRA IN");

    const void *srcPixels = pixelMap.GetPixels();
    uint32_t srcRowBytes = pixelMap.GetRowBytes();
    const ImageInfo srcInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    void *dstPixels = dst;
    uint32_t dstRowBytes = pixelMap.GetWidth() * componentsNum;
    const ImageInfo dstInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    ShowTransformParam(srcInfo, srcRowBytes, dstInfo, dstRowBytes, componentsNum);

    if ((srcPixels == nullptr) || (dstPixels == nullptr)) {
        IMAGE_LOGE("DoTransformBGRA, address issue.");
        return false;
    }

    const Position dstPos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcPixels, srcRowBytes, srcInfo,
        dstPixels, dstPos, dstRowBytes, dstInfo)) {
        IMAGE_LOGE("DoTransformBGRA, pixel convert in adapter failed.");
        return false;
    }

    IMAGE_LOGD("DoTransformBGRA OUT");
    return true;
}

bool WebpEncoder::DoTransformBgrA(Media::PixelMap &pixelMap, char* dst, int componentsNum)
{
    IMAGE_LOGD("DoTransformBgrA IN");

    const void *srcPixels = pixelMap.GetPixels();
    uint32_t srcRowBytes = pixelMap.GetRowBytes();
    const ImageInfo srcInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);

    void *dstPixels = dst;
    uint32_t dstRowBytes = pixelMap.GetWidth() * componentsNum;
    const ImageInfo dstInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    ShowTransformParam(srcInfo, srcRowBytes, dstInfo, dstRowBytes, componentsNum);

    if ((srcPixels == nullptr) || (dstPixels == nullptr)) {
        IMAGE_LOGE("DoTransformBgrA, address issue.");
        return false;
    }

    const Position dstPos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcPixels, srcRowBytes, srcInfo,
        dstPixels, dstPos, dstRowBytes, dstInfo)) {
        IMAGE_LOGE("DoTransformBgrA, pixel convert in adapter failed.");
        return false;
    }

    IMAGE_LOGD("DoTransformBgrA OUT");
    return true;
}

bool WebpEncoder::DoTransformF16To8888(Media::PixelMap &pixelMap, char* dst, int componentsNum)
{
    IMAGE_LOGD("DoTransformF16To8888 IN");

    const void *srcPixels = pixelMap.GetPixels();
    uint32_t srcRowBytes = pixelMap.GetRowBytes();
    const ImageInfo srcInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    void *dstPixels = dst;
    uint32_t dstRowBytes = pixelMap.GetWidth() * componentsNum;
    const ImageInfo dstInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    ShowTransformParam(srcInfo, srcRowBytes, dstInfo, dstRowBytes, componentsNum);

    if ((srcPixels == nullptr) || (dstPixels == nullptr)) {
        IMAGE_LOGE("DoTransformF16To8888, address issue.");
        return false;
    }

    const Position dstPos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcPixels, srcRowBytes, srcInfo,
        dstPixels, dstPos, dstRowBytes, dstInfo)) {
        IMAGE_LOGE("DoTransformF16To8888, pixel convert in adapter failed.");
        return false;
    }

    IMAGE_LOGD("DoTransformF16To8888 OUT");
    return true;
}

bool WebpEncoder::DoTransformF16pTo8888(Media::PixelMap &pixelMap, char* dst, int componentsNum)
{
    IMAGE_LOGD("DoTransformF16pTo8888 IN");

    const void *srcPixels = pixelMap.GetPixels();
    uint32_t srcRowBytes = pixelMap.GetRowBytes();
    const ImageInfo srcInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);

    void *dstPixels = dst;
    uint32_t dstRowBytes = pixelMap.GetWidth() * componentsNum;
    const ImageInfo dstInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    ShowTransformParam(srcInfo, srcRowBytes, dstInfo, dstRowBytes, componentsNum);

    if ((srcPixels == nullptr) || (dstPixels == nullptr)) {
        IMAGE_LOGE("DoTransformF16pTo8888, address issue.");
        return false;
    }

    const Position dstPos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcPixels, srcRowBytes, srcInfo,
        dstPixels, dstPos, dstRowBytes, dstInfo)) {
        IMAGE_LOGE("DoTransformF16pTo8888, pixel convert in adapter failed.");
        return false;
    }

    IMAGE_LOGD("DoTransformF16pTo8888 OUT");
    return true;
}

bool WebpEncoder::DoTransformArgbToRgb(Media::PixelMap &pixelMap, char* dst, int componentsNum)
{
    IMAGE_LOGD("DoTransformArgbToRgb IN");

    const void *srcPixels = pixelMap.GetPixels();
    uint32_t srcRowBytes = pixelMap.GetRowBytes();
    const ImageInfo srcInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::ARGB_8888, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);

    void *dstPixels = dst;
    uint32_t dstRowBytes = pixelMap.GetWidth() * componentsNum;
    const ImageInfo dstInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGB_888, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);

    ShowTransformParam(srcInfo, srcRowBytes, dstInfo, dstRowBytes, componentsNum);

    if ((srcPixels == nullptr) || (dstPixels == nullptr)) {
        IMAGE_LOGE("DoTransformArgbToRgb, address issue.");
        return false;
    }

    const Position dstPos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcPixels, srcRowBytes, srcInfo,
        dstPixels, dstPos, dstRowBytes, dstInfo)) {
        IMAGE_LOGE("DoTransformArgbToRgb, pixel convert in adapter failed.");
        return false;
    }

    IMAGE_LOGD("DoTransformArgbToRgb OUT");
    return true;
}

bool WebpEncoder::DoTransformArgbToRgba(Media::PixelMap &pixelMap, char* dst, int componentsNum)
{
    IMAGE_LOGD("DoTransformArgbToRgba IN");

    const void *srcPixels = pixelMap.GetPixels();
    uint32_t srcRowBytes = pixelMap.GetRowBytes();
    const ImageInfo srcInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::ARGB_8888, pixelMap.GetAlphaType());

    void *dstPixels = dst;
    uint32_t dstRowBytes = pixelMap.GetWidth() * componentsNum;
    const ImageInfo dstInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGBA_8888, pixelMap.GetAlphaType());

    ShowTransformParam(srcInfo, srcRowBytes, dstInfo, dstRowBytes, componentsNum);

    if ((srcPixels == nullptr) || (dstPixels == nullptr)) {
        IMAGE_LOGE("DoTransformArgbToRgba, address issue.");
        return false;
    }

    const Position dstPos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcPixels, srcRowBytes, srcInfo,
        dstPixels, dstPos, dstRowBytes, dstInfo)) {
        IMAGE_LOGE("DoTransformArgbToRgba, pixel convert in adapter failed.");
        return false;
    }

    IMAGE_LOGD("DoTransformArgbToRgba OUT");
    return true;
}

bool WebpEncoder::DoTransformRGB565(Media::PixelMap &pixelMap, char* dst, int componentsNum)
{
    IMAGE_LOGD("DoTransformRGB565 IN");

    const void *srcPixels = pixelMap.GetPixels();
    uint32_t srcRowBytes = pixelMap.GetRowBytes();
    const ImageInfo srcInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGB_565, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    void *dstPixels = dst;
    uint32_t dstRowBytes = pixelMap.GetWidth() * componentsNum;
    const ImageInfo dstInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGB_888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    ShowTransformParam(srcInfo, srcRowBytes, dstInfo, dstRowBytes, componentsNum);

    if ((srcPixels == nullptr) || (dstPixels == nullptr)) {
        IMAGE_LOGE("DoTransformRGB565, address issue.");
        return false;
    }

    const Position dstPos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcPixels, srcRowBytes, srcInfo,
        dstPixels, dstPos, dstRowBytes, dstInfo)) {
        IMAGE_LOGE("DoTransformRGB565, pixel convert in adapter failed.");
        return false;
    }

    IMAGE_LOGD("DoTransformRGB565 OUT");
    return true;
}

bool WebpEncoder::DoTransformGray(Media::PixelMap &pixelMap, char* dst, int componentsNum)
{
    IMAGE_LOGD("DoTransformGray IN");

    const void *srcPixels = pixelMap.GetPixels();
    uint32_t srcRowBytes = pixelMap.GetRowBytes();
    const ImageInfo srcInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::ALPHA_8, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    void *dstPixels = dst;
    uint32_t dstRowBytes = pixelMap.GetWidth() * componentsNum;
    const ImageInfo dstInfo = MakeImageInfo(pixelMap.GetWidth(), pixelMap.GetHeight(),
        PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    ShowTransformParam(srcInfo, srcRowBytes, dstInfo, dstRowBytes, componentsNum);

    if ((srcPixels == nullptr) || (dstPixels == nullptr)) {
        IMAGE_LOGE("DoTransformGray, address issue.");
        return false;
    }

    const Position dstPos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcPixels, srcRowBytes, srcInfo,
        dstPixels, dstPos, dstRowBytes, dstInfo)) {
        IMAGE_LOGE("DoTransformGray, pixel convert in adapter failed.");
        return false;
    }

    IMAGE_LOGD("DoTransformGray OUT");
    return true;
}

ImageInfo WebpEncoder::MakeImageInfo(int width, int height, PixelFormat pf, AlphaType at, ColorSpace cs)
{
    ImageInfo info = {
        .size = {
            .width = width,
            .height = height
        },
        .pixelFormat = pf,
        .colorSpace = cs,
        .alphaType = at
    };

    return info;
}

void WebpEncoder::ShowTransformParam(const ImageInfo &srcInfo, const uint32_t &srcRowBytes,
    const ImageInfo &dstInfo, const uint32_t &dstRowBytes, const int &componentsNum)
{
    IMAGE_LOGD("src(width=%{public}u, height=%{public}u, rowBytes=%{public}u,"
        " pixelFormat=%{public}u, colorspace=%{public}d, alphaType=%{public}d, baseDensity=%{public}d), "
        "dst(width=%{public}u, height=%{public}u, rowBytes=%{public}u,"
        " pixelFormat=%{public}u, colorspace=%{public}d, alphaType=%{public}d, baseDensity=%{public}d), "
        "componentsNum=%{public}d",
        srcInfo.size.width, srcInfo.size.height, srcRowBytes,
        srcInfo.pixelFormat, srcInfo.colorSpace, srcInfo.alphaType, srcInfo.baseDensity,
        dstInfo.size.width, dstInfo.size.height, dstRowBytes,
        dstInfo.pixelFormat, dstInfo.colorSpace, dstInfo.alphaType, dstInfo.baseDensity,
        componentsNum);
}
} // namespace ImagePlugin
} // namespace OHOS
