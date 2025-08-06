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
#include <fuzzer/FuzzedDataProvider.h>
#include "image_fwk_decode_picture_fuzzer.h"

#include <unistd.h>
#include <fcntl.h>

#include "common_fuzztest_function.h"
#include <surface.h>
#include "picture.h"
#include "image_type.h"
#include "image_utils.h"
#include "pixel_map.h"
#include "metadata.h"
#include "exif_metadata.h"
#include "fragment_metadata.h"
#include "media_errors.h"
#include "surface_buffer.h"
#include "surface_buffer_impl.h"
#include "tiff_parser.h"
#include "securec.h"
#include "image_source.h"
#include "image_log.h"
#include "image_packer.h"
#include "message_parcel.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_PICTURE_FUZZ"

static const std::string IMAGE_DEST = "/data/local/tmp/test_out";

constexpr uint32_t MAX_LENGTH_MODULO = 0xfff;
constexpr uint32_t PIXELFORMAT_MODULO = 105;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t SCALEMODE_MODULO = 2;
constexpr uint32_t AUXILLIARYMODE_MODULO = 6;
constexpr uint32_t MIMTTYPE_MODULO = 14;
constexpr uint32_t OPT_SIZE = 785;

namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;    

void AuxiliaryPictureFuncTest(std::shared_ptr<AuxiliaryPicture> auxPicture)
{
    AuxiliaryPictureType type = auxPicture->GetType();
    auxPicture->SetType(type);
    Size size = auxPicture->GetSize();
    auxPicture->SetSize(size);
    std::shared_ptr<PixelMap> pixelMap = auxPicture->GetContentPixel();
    if (pixelMap == nullptr) {
        IMAGE_LOGE("%{public}s pixelMap is nullptr", __func__);
        return;
    }
    auxPicture->SetContentPixel(pixelMap);
    AuxiliaryPictureInfo pictureInfo = auxPicture->GetAuxiliaryPictureInfo();
    auxPicture->SetAuxiliaryPictureInfo(pictureInfo);
    if (auxPicture->HasMetadata(MetadataType::EXIF)) {
        std::shared_ptr<ImageMetadata> exifMetaData = auxPicture->GetMetadata(MetadataType::EXIF);
        auxPicture->SetMetadata(MetadataType::EXIF, exifMetaData);
    }
    if (auxPicture->HasMetadata(MetadataType::FRAGMENT)) {
        std::shared_ptr<ImageMetadata> exifMetaData = auxPicture->GetMetadata(MetadataType::FRAGMENT);
        auxPicture->SetMetadata(MetadataType::FRAGMENT, exifMetaData);
    }
    uint64_t bufferSize = pixelMap->GetCapacity();
    if (bufferSize == 0) {
        return;
    }
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(bufferSize);
    auxPicture->ReadPixels(bufferSize, dst.get());
    auxPicture->WritePixels(dst.get(), bufferSize);
    
}

static void TestAllAuxiliaryPicture(std::shared_ptr<Picture> &picture)
{
    AuxiliaryPictureType type;
    type = static_cast<Media::AuxiliaryPictureType>(FDP->ConsumeIntegral<uint8_t>() % AUXILLIARYMODE_MODULO);
    
    std::shared_ptr<AuxiliaryPicture> auxGainPic = picture->GetAuxiliaryPicture(type);
    if (auxGainPic != nullptr) {
        picture->SetAuxiliaryPicture(auxGainPic);
        AuxiliaryPictureFuncTest(auxGainPic);
    }
}

void EncodePictureTest(std::shared_ptr<Picture> picture)
{
    if (picture == nullptr) {
        IMAGE_LOGE("%{public}s picture null.", __func__);
        return;
    }
    std::string mimeType[] = {"image/png" , "image/raw" , "image/vnd.wap.wbmp" , "image/bmp" , "image/gif" , "image/jpeg" , "image/mpo" , "image/heic" , "image/heif" , "image/x-adobe-dng" , "image/webp" , "image/tiff" , "image/x-icon" , "image/x-sony-arw"};
    
    ImagePacker pack;
    PackOption packOption;
    packOption.format = mimeType[FDP->ConsumeIntegral<uint8_t>() % MIMTTYPE_MODULO];
    packOption.quality = FDP->ConsumeIntegral<uint8_t>();
    packOption.numberHint = FDP->ConsumeIntegral<uint32_t>();
    packOption.desiredDynamicRange = static_cast<Media::EncodeDynamicRange>(FDP->ConsumeIntegral<uint8_t>() % ALPHATYPE_MODULO);
    packOption.needsPackProperties = FDP->ConsumeBool();
    packOption.isEditScene = FDP->ConsumeBool();
    packOption.loop = FDP->ConsumeIntegral<uint16_t>();
    uint8_t delaytimessize = FDP->ConsumeIntegral<uint8_t>();
    std::vector<uint16_t> delaytimes(delaytimessize);
    FDP->ConsumeData(delaytimes.data(), delaytimessize*2);
    packOption.delayTimes = delaytimes;
    uint8_t disposalsize = FDP->ConsumeIntegral<uint8_t>();
    packOption.disposalTypes = FDP->ConsumeBytes<uint8_t>(disposalsize);
    
    if (pack.StartPacking(IMAGE_DEST, packOption) != SUCCESS) {
        IMAGE_LOGE("%{public}s StartPacking failed.", __func__);
        return;
    }
    if (pack.AddPicture(*picture) != SUCCESS) {
        IMAGE_LOGE("%{public}s AddPicture failed.", __func__);
        return;
    }
    if (pack.FinalizePacking() != SUCCESS) {
        IMAGE_LOGE("%{public}s FinalizePacking failed.", __func__);
        return;
    }
}

void PictureFuncTest(std::shared_ptr<Picture> picture)
{
    IMAGE_LOGI("%{public}s start.", __func__);
    if (picture == nullptr) {
        IMAGE_LOGE("%{public}s picture is null.", __func__);
        return;
    }
    std::shared_ptr<PixelMap> mainPixelMap = picture->GetMainPixel();
    picture->SetMainPixel(mainPixelMap);
    picture->GetGainmapPixelMap();
    TestAllAuxiliaryPicture(picture);
    
    std::shared_ptr<ExifMetadata> exifData = picture->GetExifMetadata();
    picture->SetExifMetadata(exifData);
    sptr<SurfaceBuffer> maintenanceData = picture->GetMaintenanceData();
    picture->SetMaintenanceData(maintenanceData);

}

/*
 * test picture IPC interface
 */
bool PictureIPCTest(const uint8_t *data, size_t size)
{
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    
    Media::Picture* unmarshallingPicture = Media::Picture::Unmarshalling(parcel);
    if (unmarshallingPicture != nullptr) {
        delete unmarshallingPicture;
        unmarshallingPicture = nullptr;
    }
    
    return true;
}

bool PictureRandomFuzzTest()
{
    // creatye from opts
    Media::InitializationOptions opts;
    opts.size.width = FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO;
    opts.size.height = FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO;
    opts.srcPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    opts.pixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    opts.alphaType = static_cast<Media::AlphaType>(FDP->ConsumeIntegral<uint8_t>() % ALPHATYPE_MODULO);
    opts.scaleMode = static_cast<Media::ScaleMode>(FDP->ConsumeIntegral<uint8_t>() % SCALEMODE_MODULO);
    opts.editable = FDP->ConsumeBool();
    opts.useSourceIfMatch = FDP->ConsumeBool();
    int32_t pixelbytes = Media::ImageUtils::GetPixelBytes(opts.srcPixelFormat);
    size_t datalength = opts.size.width * opts.size.height * pixelbytes;
    std::unique_ptr<uint8_t[]> colorData = std::make_unique<uint8_t[]>(datalength);
    if(colorData == nullptr)
            return false;
    FDP->ConsumeData(colorData.get(), datalength);
    std::shared_ptr<PixelMap> pixelMapFromOpts = Media::PixelMap::Create(reinterpret_cast<uint32_t*>(colorData.get()), datalength, opts);
    if(pixelMapFromOpts.get() == nullptr)
        return false;
    
    std::unique_ptr<Picture> pictureFromOpts = Picture::Create(pixelMapFromOpts);
    if (!pictureFromOpts) {
        return false;
    }

    MessageParcel parcel;
    pictureFromOpts->Marshalling(parcel);
    return true;
}

bool CreatePictureByRandomImageSource(const std::string& pathName)
{
	std::string mimeType[] = {"image/jpeg" , "image/heic" , "image/heif"};
    SourceOptions opts;
	opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % 3];
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(pathName, opts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("%{public}s failed, imageSource is nullptr.", __func__);
        return false;
    }
    DecodingOptionsForPicture pictureOpts;
    pictureOpts.desireAuxiliaryPictures.insert(static_cast<Media::AuxiliaryPictureType>(FDP->ConsumeIntegral<uint8_t>() % AUXILLIARYMODE_MODULO));
    pictureOpts.desiredPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);

    std::shared_ptr<Picture> picture = imageSource->CreatePicture(pictureOpts, errorCode);
    
    PictureFuncTest(picture);
    EncodePictureTest(picture);

    return true;
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 3;
    switch(action){
        case 0:
            OHOS::Media::PictureRandomFuzzTest();
            break;
        case 1:
            OHOS::Media::PictureIPCTest(data, size - 1);
            break;
        default:
            if(size < OPT_SIZE) return -1;
            FuzzedDataProvider fdp(data + size - OPT_SIZE, OPT_SIZE - 1);
            OHOS::Media::FDP = &fdp;
            static const std::string pathName = "/data/local/tmp/test_decode_bmp.bmp";
            WriteDataToFile(data, size - OPT_SIZE, pathName);
            OHOS::Media::CreatePictureByRandomImageSource(pathName);
            break;
    }
    return 0;
}
