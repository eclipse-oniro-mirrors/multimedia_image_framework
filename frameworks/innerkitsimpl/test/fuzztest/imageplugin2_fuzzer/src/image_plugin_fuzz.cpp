/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <securec.h>

#include "common_fuzztest_function.h"
#include "image_source.h"
#include "ext_decoder.h"
#include "svg_decoder.h"
#include "bmp_decoder.h"
#include "image_log.h"
#include "pixel_yuv.h"
#ifdef IMAGE_COLORSPACE_FLAG
#include "color_space.h"
#endif
#include "ext_wstream.h"
#include "hdr_helper.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PLUGIN_FUZZ"

using FuzzTestFuction = std::function<void(const std::string &)>;
namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
FuzzedDataProvider *FDP;
static const std::string JPEG_HW_PATH = "/data/local/tmp/test_hw.jpg";
static const std::string JPEG_SW_PATH = "/data/local/tmp/test-tree-420.jpg";
static const std::string HEIF_HW_PATH = "/data/local/tmp/test_hw.heic";
static const std::string HDR_PATH = "/data/local/tmp/HEIFISOMultiChannelBaseColor0512V12.heic";
static const std::string WEBP_PATH = "/data/local/tmp/test.webp";
static const std::string GIF_PATH = "/data/local/tmp/test.gif";
static const std::string HDR_PATH2 = "/data/local/tmp/HDRVividSingleLayer.heic";
static const std::string HDR_PATH3 = "/data/local/tmp/JPEGISOSingle.jpg";
static const std::string HDR_PATH4 = "/data/local/tmp/JPEGVividSingle.jpg";
static const std::string HDR_PATH5 = "/data/local/tmp/siglechanel_yuv420_20240515V2.heic";

static const std::string PNG_PATH1 = "/data/local/tmp/test_chunk_itxt_nocompress.png";
static const std::string PNG_PATH2 = "/data/local/tmp/test_out_chunk_itxt_withcompress.png";
static const std::string PNG_PATH3 = "/data/local/tmp/test_chunk_text.png";
static const std::string PNG_PATH5 = "/data/local/tmp/test_exif.png";
static const std::string JPG_PATH1 = "/data/local/tmp/800-500.jpg";
static const std::string JPG_PATH3 = "/data/local/tmp/jpeg_include_icc_profile.jpg";
static const std::string JPG_PATH4 = "/data/local/tmp/test_raw_file.jpg";
static const std::string SVG_PATH1 = "/data/local/tmp/test_large.svg";
static const std::string SVG_PATH2 = "/data/local/tmp/test.svg";
static const std::string ASTC_PATH1 = "/data/local/tmp/THM_ASTC.astc";
constexpr uint8_t ITUT35_TAG_SIZE = 6;
static constexpr uint32_t ALLOCATORTYPE_MODULO = 5;
static constexpr uint32_t CROPANDSCALESTRATEGY_MODULO = 3;

void SvgDecoderFuncTest001(const std::string &filename)
{
    IMAGE_LOGI("%{public}s IN path: %{public}s", __func__, filename.c_str());
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(filename, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return;
    }

    imageSource->sourceInfo_.encodedFormat = "image/svg+xml";
    Media::DecodeOptions dopts;
    auto pixelMap = imageSource->CreatePixelMap(dopts, errorCode);
    if (pixelMap == nullptr || errorCode != SUCCESS) {
        return;
    }
    auto svgDecoder = static_cast<SvgDecoder *>(imageSource->CreateDecoder(errorCode));
    PixelDecodeOptions plOpts;
    SetFdpPixelDecodeOptions(FDP, plOpts);
    PlImageInfo plInfo;
    svgDecoder->SetDecodeOptions(0, plOpts, plInfo);
    DecodeContext context;
    svgDecoder->Decode(0, context);
    uint32_t num;
    svgDecoder->GetTopLevelImageNum(num);
    context.allocatorType = static_cast<AllocatorType>(FDP->ConsumeIntegral<uint8_t>() % ALLOCATORTYPE_MODULO);
    svgDecoder->AllocBuffer(context);
    svgDecoder->DoSetDecodeOptions(0, plOpts, plInfo);
    Size plSize;
    svgDecoder->DoGetImageSize(0, plSize);
    svgDecoder->DoDecode(0, context);
    svgDecoder->Reset();
    delete svgDecoder;
    svgDecoder = nullptr;

    DecodeOptions dstOpts;
    imageSource = ImageSource::CreateImageSource(filename, srcOpts, errorCode);
    imageSource->CreatePixelMap(0, dstOpts, errorCode);
    imageSource->Reset();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void JpegHardwareTest001(const std::string &pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    DecodeOptions decodeOpts;
    SetFdpDecodeOptions(FDP, decodeOpts);
    auto pixelMap = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    if (pixelMap == nullptr) {
        return;
    }

    PixelMapTest001(pixelMap.get());
    PixelMapTest002(pixelMap.get());
    PixelYuvTest001(pixelMap.get());
    PixelYuvTest002(pixelMap.get());

    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void JpegSoftTest001(const std::string &pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    DecodeOptions decodeOpts;
    SetFdpDecodeOptions(FDP, decodeOpts);
    auto pixelMap = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    if (pixelMap == nullptr) {
        return;
    }
    PixelMapTest001(pixelMap.get());
    PixelMapTest002(pixelMap.get());
    PixelYuvTest001(pixelMap.get());
    PixelYuvTest002(pixelMap.get());
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void HeifHardwareTest001(const std::string &pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    DecodeOptions decodeOpts;
    SetFdpDecodeOptions(FDP, decodeOpts);
    auto pixelMap = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void HdrTest001(const std::string &pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    ImageInfo imageInfo;
    imageSource->GetImageInfo(0, imageInfo);
    if (!imageSource->IsHdrImage()) {
        IMAGE_LOGE("%{public}s %{public}s is not hdr", __func__, pathName.c_str());
        return;
    }
    DecodeContext gainMapCtx;
    if (imageSource->mainDecoder_->DecodeHeifGainMap(gainMapCtx)) {
        IMAGE_LOGI("%{public}s DecodeHeifGainMap SUCCESS, %{public}s", __func__, pathName.c_str());
        imageSource->mainDecoder_->GetHdrMetadata(imageSource->mainDecoder_->CheckHdrType());
    } else {
        IMAGE_LOGE("%{public}s DecodeHeifGainMap failed, %{public}s", __func__, pathName.c_str());
    }

    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void GifTest001(const std::string &pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    DecodeOptions decodeOpts;
    SetFdpDecodeOptions(FDP, decodeOpts);
    for (uint32_t index = 0; index < imageSource->GetFrameCount(errorCode); ++index) {
        auto pixelMap = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
        IMAGE_LOGI("%{public}s gif decode SUCCESS", __func__);
    }
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void ExtDecoderRegionFuncTest001(const std::string &filename)
{
    IMAGE_LOGI("%{public}s IN path: %{public}s", __func__, filename.c_str());
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(filename, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    Media::DecodeOptions dopts;
    dopts.desiredRegion.left = FDP->ConsumeIntegral<int32_t>();
    dopts.desiredRegion.top = FDP->ConsumeIntegral<int32_t>();
    dopts.desiredRegion.width = FDP->ConsumeIntegral<int32_t>();
    dopts.desiredRegion.height = FDP->ConsumeIntegral<int32_t>();
    dopts.cropAndScaleStrategy =
        static_cast<CropAndScaleStrategy>(FDP->ConsumeIntegral<uint8_t>() % CROPANDSCALESTRATEGY_MODULO);
    auto pixelMap = imageSource->CreatePixelMap(dopts, errorCode);
    if (pixelMap == nullptr || errorCode != SUCCESS) {
        return;
    }
    auto extDecoder = static_cast<ExtDecoder *>((imageSource->mainDecoder_).get());
    if (extDecoder == nullptr || !extDecoder->DecodeHeader()) {
        return;
    }
    DecodeContext context;
    SkImageInfo heifInfo;
    extDecoder->HeifYUVMemAlloc(context, heifInfo);
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
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void HdrHelperFucTest()
{
    HdrMetadata metadataOne;
    metadataOne.extendMeta.baseColorMeta.baseMappingFlag = ITUT35_TAG_SIZE;
    metadataOne.extendMeta.gainmapColorMeta.combineMappingFlag = ITUT35_TAG_SIZE;
    ImagePlugin::HdrJpegPackerHelper::PackVividMetadataMarker(metadataOne);

    HdrMetadata metadataTwo;
    metadataTwo.extendMeta.baseColorMeta.baseMappingFlag = ITUT35_TAG_SIZE;
    metadataTwo.extendMeta.gainmapColorMeta.combineMappingFlag = ITUT35_TAG_SIZE;
    ImagePlugin::HdrJpegPackerHelper::PackISOMetadataMarker(metadataTwo);

    HdrMetadata metadataThree;
    metadataThree.extendMeta.baseColorMeta.baseMappingFlag = ITUT35_TAG_SIZE;
    metadataThree.extendMeta.gainmapColorMeta.combineMappingFlag = ITUT35_TAG_SIZE;
    sk_sp<SkData> baseImageData;
    sk_sp<SkData> gainMapImageData;
    ExtWStream extWStream(nullptr);
    ImagePlugin::HdrJpegPackerHelper::SpliceHdrStream(baseImageData, gainMapImageData, extWStream, metadataThree);

    HdrMetadata metadataFour;
    metadataFour.extendMeta.baseColorMeta.baseMappingFlag = ITUT35_TAG_SIZE;
    metadataFour.extendMeta.gainmapColorMeta.combineMappingFlag = ITUT35_TAG_SIZE;
    std::vector<uint8_t> it35Info;
    ImagePlugin::HdrHeifPackerHelper::PackIT35Info(metadataFour, it35Info);
}

void ImagePluginFuzzTest001(const uint8_t *data, size_t size)
{
    std::string filename = "/data/local/tmp/test_decode_ext.jpg";
    if (!WriteDataToFile(data, size, filename)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return;
    }
    std::vector<std::pair<FuzzTestFuction, std::vector<std::string>>> testFunctions = {
        {SvgDecoderFuncTest001, {SVG_PATH1, SVG_PATH2, filename}},
        {JpegHardwareTest001, {JPEG_HW_PATH, filename}},
        {JpegSoftTest001, {JPEG_SW_PATH, filename}},
        {HeifHardwareTest001, {HEIF_HW_PATH, filename}},
        {GifTest001, {GIF_PATH, WEBP_PATH, filename}},
        {HdrTest001, {HDR_PATH, HDR_PATH2, HDR_PATH3, HDR_PATH4, HDR_PATH5, filename}},
        {ExtDecoderRegionFuncTest001, {filename}}};
    uint8_t functionIndex = FDP->ConsumeIntegral<uint8_t>() % testFunctions.size();
    uint8_t parmIndex = FDP->ConsumeIntegral<uint8_t>() % testFunctions[functionIndex].second.size();
    auto function = testFunctions[functionIndex].first;
    std::string param = testFunctions[functionIndex].second[parmIndex];
    function(param);
}
}  // namespace Media
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;

    OHOS::Media::ImagePluginFuzzTest001(data, size);
    OHOS::Media::HdrHelperFucTest();
    return 0;
}
