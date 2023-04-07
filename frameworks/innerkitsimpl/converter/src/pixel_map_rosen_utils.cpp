/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "pixel_map_rosen_utils.h"

#include "include/core/SkImage.h"

namespace OHOS {
namespace Media {
static sk_sp<SkColorSpace> ColorSpaceToSkColorSpace(ColorSpace colorSpace)
{
    switch (colorSpace) {
        case ColorSpace::LINEAR_SRGB:
            return SkColorSpace::MakeSRGBLinear();
        case ColorSpace::SRGB:
        default:
            return SkColorSpace::MakeSRGB();
    }
}

static SkColorType PixelFormatToSkColorType(PixelFormat pixelFormat)
{
    switch (pixelFormat) {
        case PixelFormat::RGB_565:
            return SkColorType::kRGB_565_SkColorType;
        case PixelFormat::RGBA_8888:
            return SkColorType::kRGBA_8888_SkColorType;
        case PixelFormat::BGRA_8888:
            return SkColorType::kBGRA_8888_SkColorType;
        case PixelFormat::ALPHA_8:
            return SkColorType::kAlpha_8_SkColorType;
        case PixelFormat::RGBA_F16:
            return SkColorType::kRGBA_F16_SkColorType;
        case PixelFormat::UNKNOWN:
        case PixelFormat::ARGB_8888:
        case PixelFormat::RGB_888:
        case PixelFormat::NV21:
        case PixelFormat::NV12:
        case PixelFormat::CMYK:
        default:
            return SkColorType::kUnknown_SkColorType;
    }
}

static SkAlphaType AlphaTypeToSkAlphaType(AlphaType alphaType)
{
    switch (alphaType) {
        case AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN:
            return SkAlphaType::kUnknown_SkAlphaType;
        case AlphaType::IMAGE_ALPHA_TYPE_OPAQUE:
            return SkAlphaType::kOpaque_SkAlphaType;
        case AlphaType::IMAGE_ALPHA_TYPE_PREMUL:
            return SkAlphaType::kPremul_SkAlphaType;
        case AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL:
            return SkAlphaType::kUnpremul_SkAlphaType;
        default:
            return SkAlphaType::kUnknown_SkAlphaType;
    }
}

static SkImageInfo MakeSkImageInfo(const ImageInfo& imageInfo)
{
    SkColorType ct = PixelFormatToSkColorType(imageInfo.pixelFormat);
    SkAlphaType at = AlphaTypeToSkAlphaType(imageInfo.alphaType);
    sk_sp<SkColorSpace> cs = ColorSpaceToSkColorSpace(imageInfo.colorSpace);
    return SkImageInfo::Make(imageInfo.size.width, imageInfo.size.height, ct, at, cs);
}

class RosenImageWrapper {
public:
    explicit RosenImageWrapper(sk_sp<SkImage> skImage) : skImage_(skImage) {}

    sk_sp<SkImage> GetSkImage() const
    {
        return skImage_;
    }
private:
    sk_sp<SkImage> skImage_;
};

bool PixelMapRosenUtils::UploadToGpu(
    std::shared_ptr<PixelMap> pixelMap, GrContext* context, bool buildMips, bool limitToMaxTextureSize)
{
    if (!pixelMap) {
        return false;
    }
    if (pixelMap->rosenImageWrapper_) {
        return true;
    }

    sk_sp<SkImage> skImage;
    if (context) {
#ifdef UPLOAD_GPU_ENABLED
        auto skImageInfo = MakeSkImageInfo(pixelMap->imageInfo_);
        SkPixmap skPixmap(skImageInfo, reinterpret_cast<const void*>(pixelMap->GetPixels()), pixelMap->GetRowBytes());
        skImage = SkImage::MakeCrossContextFromPixmap(context, skPixmap, buildMips, limitToMaxTextureSize);
#endif
    }
    if (skImage) {
        pixelMap->rosenImageWrapper_ = std::make_shared<RosenImageWrapper>(skImage);
    }
    return pixelMap->rosenImageWrapper_ != nullptr;
}

struct PixelMapReleaseContext {
    explicit PixelMapReleaseContext(std::shared_ptr<PixelMap> pixelMap) : pixelMap_(pixelMap) {}

    ~PixelMapReleaseContext()
    {
        pixelMap_ = nullptr;
    }

private:
    std::shared_ptr<PixelMap> pixelMap_;
};

static void PixelMapReleaseProc(const void* /* pixels */, void* context)
{
    PixelMapReleaseContext* ctx = static_cast<PixelMapReleaseContext*>(context);
    if (ctx) {
        delete ctx;
        ctx = nullptr;
    }
}

sk_sp<SkImage> PixelMapRosenUtils::ExtractSkImage(std::shared_ptr<PixelMap> pixelMap)
{
    if (!pixelMap) {
        return nullptr;
    }
    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    auto skImageInfo = MakeSkImageInfo(pixelMap->imageInfo_);
    SkPixmap skPixmap(skImageInfo, reinterpret_cast<const void*>(pixelMap->GetPixels()), pixelMap->GetRowBytes());
    return SkImage::MakeFromRaster(skPixmap, PixelMapReleaseProc, new PixelMapReleaseContext(pixelMap));
}
} // namespace Media
} // namespace OHOS
