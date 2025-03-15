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

#include "image_source_fuzz.h"

#define private public
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>

#include "securec.h"
#include "image_source.h"
#include "convert_utils.h"
#include "image_log.h"
#include "image_packer.h"
#include "media_errors.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_SOURCE_FUZZ"

static const std::string JPEG_FORMAT = "image/jpeg";
static const std::string HEIF_FORMAT = "image/heif";
static const std::string WEBP_FORMAT = "image/webp";
static const std::string GIF_FORMAT = "image/gif";
static const std::string PNG_FORMAT = "image/png";
static const std::string IMAGE_ENCODE_DEST = "/data/local/tmp/test_out.dat";

namespace OHOS {
namespace Media {
void ImageSourceFuncTest001(std::unique_ptr<ImageSource>& imageSource)
{
    std::set<std::string> formats;
    imageSource->GetSupportedFormats(formats);
    imageSource->GetDecodeEvent();
    std::string key = "ImageWidth";
    std::string value = "500";
    int32_t valueInt = 0;
    uint32_t errCode = 0;
    imageSource->ModifyImageProperty(key, value);
    imageSource->ModifyImageProperty(nullptr, key, value);
    imageSource->ModifyImageProperty(0, key, value, "");
    imageSource->ModifyImageProperty(0, key, value, 0);
    imageSource->ModifyImageProperty(0, key, value, nullptr, 0);
    imageSource->GetImagePropertyCommon(0, key, value);
    imageSource->GetImagePropertyInt(0, key, valueInt);
    imageSource->GetImagePropertyString(0, key, value);
    imageSource->GetSourceInfo(errCode);
    imageSource->RegisterListener(nullptr);
    imageSource->UnRegisterListener(nullptr);
    imageSource->AddDecodeListener(nullptr);
    imageSource->RemoveDecodeListener(nullptr);
    imageSource->IsStreamCompleted();
    auto agentIter = imageSource->formatAgentMap_.begin();
    imageSource->CheckEncodedFormat(*(agentIter->second));
    imageSource->CheckFormatHint(key, agentIter);
    imageSource->DecodeSourceInfo(false);
    imageSource->DecodeSourceInfo(true);
    imageSource->CreateDecoder(errCode);
    DecodeOptions opts;
    DecodeOptions procOpts;
    PixelMap pixelMap;
    imageSource->CopyOptionsToProcOpts(opts, procOpts, pixelMap);
    MemoryUsagePreference preference = MemoryUsagePreference::LOW_RAM;
    imageSource->SetMemoryUsagePreference(preference);
    imageSource->ImageSizeChange(1, 1, 1, 1);
    Rect cropRect;
    ImageInfo imageInfo;
    imageSource->ImageConverChange(cropRect, imageInfo, imageInfo);
    imageSource->CreatePixelMapForYUV(errCode);
    imageSource->CreatePixelMapList(opts, errCode);
    imageSource->GetDelayTime(errCode);
    imageSource->GetDisposalType(errCode);
    imageSource->GetFrameCount(errCode);
}

void CreateImageSourceByDataFuzz(const uint8_t* data, size_t size)
{
    uint8_t dest[size + 1];
    int ret = memcpy_s(dest, sizeof(dest), data, size);
    if (ret != 0) {
        return;
    }
    dest[sizeof(dest) - 1] = '\0';
    Media::SourceOptions opts;
    uint32_t errorCode;
    auto imagesource = Media::ImageSource::CreateImageSource(dest, sizeof(dest), opts, errorCode);
    ImageSourceFuncTest001(imagesource);
    Media::DecodeOptions dopts;
    imagesource->CreatePixelMap(dopts, errorCode);
    imagesource->Reset();
}

void CreateImageSourceByFDEXFuzz(const uint8_t* data, size_t size)
{
    Media::SourceOptions opts;
    uint32_t errorCode;
    uint32_t offset = 0;
    uint32_t length = 1;
    std::string pathName = "/data/local/tmp/test_create_imagesource_fdex.jpg";
    if (!WriteDataToFile(data, size, pathName)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return;
    }
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        IMAGE_LOGE("open file failed, %{public}s", pathName.c_str());
        return;
    }
    auto imagesource = Media::ImageSource::CreateImageSource(fd, offset, length, opts, errorCode);
    Media ::DecodeOptions dopts;
    imagesource->CreatePixelMap(dopts, errorCode);
    close(fd);
}

void CreateImageSourceByIstreamFuzz(const uint8_t* data, size_t size)
{
    std::string pathName = "/data/local/tmp/test_create_imagesource_istream.jpg";
    if (!WriteDataToFile(data, size, pathName)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return;
    }
    std::unique_ptr<std::istream> is = std::make_unique<std::ifstream>(pathName.c_str());
    Media::SourceOptions opts;
    uint32_t errorCode;
    Media ::DecodeOptions dopts;
    auto imagesource = Media::ImageSource::CreateImageSource(std::move(is), opts, errorCode);
    if (imagesource != nullptr) {
        imagesource->CreatePixelMap(dopts, errorCode);
    }
}

void CreateImageSourceByPathNameFuzz(const uint8_t* data, size_t size)
{
    std::string pathName = "/data/local/tmp/test_create_imagesource_pathname.jpg";
    if (!WriteDataToFile(data, size, pathName)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return;
    }
    Media::SourceOptions opts;
    uint32_t errorCode;
    Media ::DecodeOptions dopts;
    auto imagesource = Media::ImageSource::CreateImageSource(pathName, opts, errorCode);
    if (imagesource != nullptr) {
        imagesource->CreatePixelMap(dopts, errorCode);
    }
}

void CreateIncrementalPixelMapFuzz(const uint8_t* data, size_t size)
{
    std::string pathName = "/data/local/tmp/test_incremental_pixelmap.jpg";
    if (!WriteDataToFile(data, size, pathName)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return;
    }
    Media::SourceOptions opts;
    uint32_t errorCode;
    auto imagesource = Media::ImageSource::CreateImageSource(pathName, opts, errorCode);
    Media ::DecodeOptions dopts;
    uint32_t index = 1;
    if (imagesource != nullptr) {
        imagesource->CreateIncrementalPixelMap(index, dopts, errorCode);
    }
}

void CreateImageSourceByPathname(const uint8_t* data, size_t size)
{
    uint32_t errCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errCode);
}

bool CreatePixelMapByRandomImageSource(const uint8_t *data, size_t size)
{
    IMAGE_LOGI("%{public}s start.", __func__);
    if (data == nullptr) {
        IMAGE_LOGE("%{public}s failed, data is nullptr", __func__);
        return false;
    }
    Media::SourceOptions opts;
    uint32_t errorCode;
    auto imageSource = Media::ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("%{public}s failed, imageSource is nullotr", __func__);
    }
    DecodeOptions dopts;
    dopts.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts.isAppUseAllocator = true;
    dopts.allocatorType = AllocatorType::DMA_ALLOC;
    std::shared_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(0, dopts, errorCode);

    dopts.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts.isAppUseAllocator = true;
    dopts.allocatorType = imageSource->ConvertAutoAllocatorType(dopts);
    pixelMap = imageSource->CreatePixelMap(0, dopts, errorCode);

    dopts.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts.isAppUseAllocator = true;
    dopts.desiredPixelFormat = PixelFormat::NV12;
    dopts.allocatorType = AllocatorType::DMA_ALLOC;
    pixelMap = imageSource->CreatePixelMap(0, dopts, errorCode);

    dopts.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts.isAppUseAllocator = true;
    dopts.desiredPixelFormat = PixelFormat::NV21;
    dopts.allocatorType = AllocatorType::DMA_ALLOC;
    pixelMap = imageSource->CreatePixelMap(0, dopts, errorCode);
    return true;
}

void EncodePictureTest(std::shared_ptr<Picture> picture, const std::string& format, const std::string& outputPath)
{
    IMAGE_LOGI("%{public}s start.", __func__);
    if (picture == nullptr) {
        IMAGE_LOGE("%{public}s picture null.", __func__);
        return;
    }
    ImagePacker pack;
    PackOption packOption;
    packOption.format = format;
    if (pack.StartPacking(outputPath, packOption) != SUCCESS) {
        IMAGE_LOGE("%{public}s StartPacking failed.", __func__);
        return;
    }
    if (pack.AddPicture(*picture) != SUCCESS) {
        IMAGE_LOGE("%{public}s AddPicture failed.",  __func__);
        return;
    }
    if (pack.FinalizePacking() != SUCCESS) {
        IMAGE_LOGE("%{public}s FinalizePacking failed.",  __func__);
        return;
    }
    IMAGE_LOGI("%{public}s SUCCESS.",  __func__);
}

void EncodePixelMapTest(std::shared_ptr<PixelMap> pixelmap, const std::string& format, const std::string& outputPath)
{
    IMAGE_LOGI("%{public}s start.", __func__);
    if (pixelmap == nullptr) {
        IMAGE_LOGE("%{public}s picture null.", __func__);
        return;
    }
    ImagePacker pack;
    PackOption packOption;
    packOption.format = format;
    if (pack.StartPacking(outputPath, packOption) != SUCCESS) {
        IMAGE_LOGE("%{public}s StartPacking failed.", __func__);
        return;
    }
    if (pack.AddImage(*pixelmap) != SUCCESS) {
        IMAGE_LOGE("%{public}s AddImage failed.",  __func__);
        return;
    }
    if (pack.FinalizePacking() != SUCCESS) {
        IMAGE_LOGE("%{public}s FinalizePacking failed.",  __func__);
        return;
    }
    IMAGE_LOGI("%{public}s SUCCESS.",  __func__);
}

bool CreatePixelMapUseArgbByRandomImageSource(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    SourceOptions opts;
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (imageSource == nullptr) {
        return false;
    }
    DecodeOptions dopts;
    dopts.desiredPixelFormat = PixelFormat::ARGB_8888;
    dopts .desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts.allocatorType = AllocatorType::DMA_ALLOC;
    std::shared_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(0, dopts, errorCode);
    dopts.desiredPixelFormat = PixelFormat::ARGB_8888;
    dopts.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    pixelMap = imageSource->CreatePixelMap(0, dopts, errorCode);
    if (pixelMap != nullptr) {
        EncodePixelMapTest(pixelMap, JPEG_FORMAT, IMAGE_ENCODE_DEST);
        EncodePixelMapTest(pixelMap, HEIF_FORMAT, IMAGE_ENCODE_DEST);
        EncodePixelMapTest(pixelMap, PNG_FORMAT, IMAGE_ENCODE_DEST);
        EncodePixelMapTest(pixelMap, WEBP_FORMAT, IMAGE_ENCODE_DEST);
        EncodePixelMapTest(pixelMap, GIF_FORMAT, IMAGE_ENCODE_DEST);
    }
    dopts.desiredPixelFormat = PixelFormat::ARGB_8888;
    dopts .desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts.allocatorType = imageSource->ConvertAutoAllocatorType(dopts);
    pixelMap = imageSource->CreatePixelMap(0, dopts, errorCode);
    ImageInfo info;
    if (pixelMap == nullptr) {
        pixelMap->GetImageInfo(info);
    }
    std::shared_ptr<AuxiliaryPicture> auxPicture = AuxiliaryPicture::Create(pixelMap,
        AuxiliaryPictureType::FRAGMENT_MAP, info.size);
    DecodingOptionsForPicture doptsForPicture;
    doptsForPicture.desiredPixelFormat = PixelFormat::ARGB_8888;
    std::shared_ptr<Picture> picture = imageSource->CreatePicture(doptsForPicture, errorCode);
    if (auxPicture != nullptr && picture != nullptr) {
        picture->SetAuxiliaryPicture(auxPicture);
    }
    if (picture != nullptr) {
        EncodePictureTest(picture, JPEG_FORMAT, IMAGE_ENCODE_DEST);
        EncodePictureTest(picture, HEIF_FORMAT, IMAGE_ENCODE_DEST);
    }
    return true;
}
    
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::CreateImageSourceByDataFuzz(data, size);
    OHOS::Media::CreateImageSourceByFDEXFuzz(data, size);
    OHOS::Media::CreateImageSourceByIstreamFuzz(data, size);
    OHOS::Media::CreateImageSourceByPathNameFuzz(data, size);
    OHOS::Media::CreateIncrementalPixelMapFuzz(data, size);
    OHOS::Media::CreateImageSourceByPathname(data, size);
    OHOS::Media::CreatePixelMapByRandomImageSource(data, size);
    OHOS::Media::CreatePixelMapUseArgbByRandomImageSource(data, size);
    return 0;
}