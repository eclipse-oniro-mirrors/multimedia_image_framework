/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "image_plugin_fuzz.h"

#define private public
#define protected public
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>

#include "convert_utils.h"
#include "image_source.h"
#include "ext_decoder.h"
#include "svg_decoder.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PLUGIN_FUZZ"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;

static const std::string JPEG_HW_PATH = "/data/local/tmp/test_hw.jpg";
static const std::string JPEG_SW_PATH = "/data/local/tmp/test-tree-420.jpg";
static const std::string HEIF_HW_PATH = "/data/local/tmp/test_hw.heic";
static const std::string HDR_PATH = "/data/local/tmp/HEIFISOMultiChannelBaseColor0512V12.heic";
static const std::string WEBP_PATH = "/data/local/tmp/test.webp";
static const std::string GIF_PATH = "/data/local/tmp/test.gif";

void ExtDecoderFuncTest001(const std::string& filename)
{
    IMAGE_LOGI("%{public}s IN path: %{public}s", __func__, filename.c_str());
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(filename, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    Media::DecodeOptions dopts;
    imageSource->CreatePixelMap(dopts, errorCode);
    auto extDecoder = static_cast<ExtDecoder*>((imageSource->mainDecoder_).get());
    if (extDecoder == nullptr || !extDecoder->DecodeHeader()) {
        return;
    }
    DecodeContext context;
    extDecoder->HeifYUVMemAlloc(context);
    int dWidth;
    int dHeight;
    float scale;
    extDecoder->GetScaledSize(dWidth, dHeight, scale);
    extDecoder->GetHardwareScaledSize(dWidth, dHeight, scale);
    extDecoder->IsSupportScaleOnDecode();
    PixelDecodeOptions plOpts;
    PlImageInfo plInfo;
    extDecoder->SetDecodeOptions(0, plOpts, plInfo);
    PixelFormat dstFormat = PixelFormat::UNKNOWN;
    extDecoder->PreDecodeCheckYuv(0, dstFormat);
    extDecoder->DoHardWareDecode(context);
    extDecoder->GetJpegYuvOutFmt(dstFormat);
    extDecoder->DecodeToYuv420(0, context);
    extDecoder->CheckContext(context);
    extDecoder->HardWareDecode(context);
    SkAlphaType alphaType;
    AlphaType outputType;
    extDecoder->ConvertInfoToAlphaType(alphaType, outputType);
    SkColorType format;
    PixelFormat outputFormat;
    extDecoder->ConvertInfoToColorType(format, outputFormat);
    std::string key = "ImageWidth";
    std::string value = "500";
    int32_t valInt = 0;
    extDecoder->GetImagePropertyInt(0, key, valInt);
    extDecoder->GetImagePropertyString(0, key, value);
    extDecoder->GetMakerImagePropertyString(key, value);
    extDecoder->DoHeifToYuvDecode(context);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void SvgDecoderFuncTest001(const std::string& filename)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(filename, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return;
    }

    imageSource->sourceInfo_.encodedFormat = "image/svg+xml";
    auto svgDecoder = static_cast<SvgDecoder*>(imageSource->CreateDecoder(errorCode));
    PixelDecodeOptions plOpts;
    PlImageInfo plInfo;
    svgDecoder->SetDecodeOptions(0, plOpts, plInfo);
    DecodeContext context;
    svgDecoder->Decode(0, context);
    uint32_t num;
    svgDecoder->GetTopLevelImageNum(num);
    context.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    svgDecoder->AllocBuffer(context);
    context.allocatorType = AllocatorType::DMA_ALLOC;
    svgDecoder->AllocBuffer(context);
    context.allocatorType = AllocatorType::HEAP_ALLOC;
    svgDecoder->AllocBuffer(context);
    svgDecoder->DoSetDecodeOptions(0, plOpts, plInfo);
    Size plSize;
    svgDecoder->DoGetImageSize(0, plSize);
    svgDecoder->DoDecode(0, context);

    DecodeOptions dstOpts;
    imageSource = ImageSource::CreateImageSource(filename, srcOpts, errorCode);
    imageSource->CreatePixelMapExtended(0, dstOpts, errorCode);
    imageSource->Reset();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void PixelMapTest001(PixelMap* pixelMap)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    pixelMap->SetTransformered(pixelMap->isTransformered_);
    ImageInfo info;
    pixelMap->GetYUVByteCount(info);
    pixelMap->GetAllocatedByteCount(info);
    InitializationOptions initOpts;
    initOpts.size = {pixelMap->GetWidth(), pixelMap->GetHeight()};
    initOpts.editable = true;
    auto emptyPixelMap = PixelMap::Create(initOpts);
    Rect srcRect;
    int32_t errorCode;
    PixelMap::Create(*(emptyPixelMap.get()), srcRect, initOpts, errorCode);
    pixelMap->resize(1, 1);
    pixelMap->CopyPixelMap(*pixelMap, *(emptyPixelMap.get()));
    PixelFormat fromat = PixelFormat::RGBA_8888;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::RGBA_1010102;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::BGRA_8888;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::ARGB_8888;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::ALPHA_8;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::RGB_565;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::RGB_888;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::NV21;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::YCRCB_P010;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::CMYK;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::RGBA_F16;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::ASTC_4x4;
    pixelMap->GetPixelFormatDetail(fromat);
    pixelMap->GetPixel8(0, 0);
    pixelMap->GetPixel16(0, 0);
    pixelMap->GetPixel32(0, 0);
    pixelMap->GetPixel(0, 0);
    uint32_t color = 0;
    pixelMap->GetARGB32Color(0, 0, color);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void PixelMapTest002(PixelMap* pixelMap)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    pixelMap->GetPixelBytes();
    pixelMap->GetRowBytes();
    pixelMap->GetByteCount();
    pixelMap->GetWidth();
    pixelMap->GetHeight();
    TransformData transformData;
    pixelMap->GetTransformData(transformData);
    pixelMap->SetTransformData(transformData);
    pixelMap->GetBaseDensity();
    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    pixelMap->GetPixelFormat();
    pixelMap->GetColorSpace();
    pixelMap->GetAlphaType();
    pixelMap->GetPixels();
    pixelMap->IsHdr();
    uint32_t color = 0;
    pixelMap->GetARGB32ColorA(color);
    pixelMap->GetARGB32ColorR(color);
    pixelMap->GetARGB32ColorG(color);
    pixelMap->GetARGB32ColorB(color);
    pixelMap->IsStrideAlignment();
    pixelMap->GetAllocatorType();
    pixelMap->GetFd();
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace grColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
    pixelMap->ApplyColorSpace(grColorSpace);
#endif
    pixelMap->ResetConfig(pixelMap->imageInfo_.size, pixelMap->imageInfo_.pixelFormat);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void PixelMapTest(PixelMap* pixelMap)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    PixelMapTest001(pixelMap);
    PixelMapTest002(pixelMap);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void JpegHardwareTest001()
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(JPEG_HW_PATH, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return ;
    }
    DecodeOptions decodeOpts;
    auto pixelMap = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    PixelMapTest(pixelMap.get());
    decodeOpts.desiredPixelFormat = PixelFormat::NV21;
    auto pixelMap2 = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    PixelMapTest(pixelMap2.get());
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void JpegSoftTest001()
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(JPEG_SW_PATH, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return ;
    }
    DecodeOptions decodeOpts;
    auto pixelMap = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    PixelMapTest(pixelMap.get());
    decodeOpts.desiredPixelFormat = PixelFormat::NV12;
    auto pixelMap2 = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    PixelMapTest(pixelMap2.get());
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void HeifHardwareTest001()
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(HEIF_HW_PATH, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return ;
    }
    DecodeOptions decodeOpts;
    auto pixelMap = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void HdrTest001()
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(HDR_PATH, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return ;
    }
    ImageInfo imageInfo;
    imageSource->GetImageInfo(0, imageInfo);
    if (!imageSource->IsHdrImage()) {
        IMAGE_LOGE("%{public}s %{public}s is not hdr", __func__, HDR_PATH.c_str());
        return;
    }
    DecodeContext gainMapCtx;
    if (imageSource->mainDecoder_->DecodeHeifGainMap(gainMapCtx)) {
        IMAGE_LOGI("%{public}s DecodeHeifGainMap SUCCESS, %{public}s", __func__, HDR_PATH.c_str());
        imageSource->mainDecoder_->GetHdrMetadata(imageSource->mainDecoder_->CheckHdrType());
    } else {
        IMAGE_LOGE("%{public}s DecodeHeifGainMap failed, %{public}s", __func__, HDR_PATH.c_str());
    }
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void GifTest001(const std::string& pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return ;
    }
    for (uint32_t index = 0; index < imageSource->GetFrameCount(errorCode); ++index) {
        DecodeOptions decodeOpts;
        auto pixelMap = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
        IMAGE_LOGI("%{public}s gif decode SUCCESS", __func__);
    }
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void ImagePluginFuzzTest001(const uint8_t* data, size_t size)
{
    std::string filename = "/data/local/tmp/test_decode_ext.jpg";
    if (!WriteDataToFile(data, size, filename)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return;
    }
    ExtDecoderFuncTest001(filename);
    SvgDecoderFuncTest001(filename);
    JpegHardwareTest001();
    JpegSoftTest001();
    HeifHardwareTest001();
    GifTest001(GIF_PATH);
    GifTest001(WEBP_PATH);
    HdrTest001();
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::ImagePluginFuzzTest001(data, size);
    return 0;
}