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
#include "common_fuzztest_function.h"

#include <fcntl.h>
#include <surface.h>
#define private public
#define protected public
#include "picture.h"
#include "image_type.h"
#include "image_utils.h"
#include "pixel_map.h"
#include "image_source.h"
#include "image_packer.h"
#include "metadata.h"
#include "exif_metadata.h"
#include "fragment_metadata.h"
#include "media_errors.h"
#include "surface_buffer.h"
#include "surface_buffer_impl.h"
#include "tiff_parser.h"
#include "securec.h"
#include "image_log.h"
#include "ext_stream.h"
#include "include/codec/SkCodec.h"
#include "HeifDecoderImpl.h"
#include "HeifDecoder.h"
#include "buffer_source_stream.h"
#include "message_parcel.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_PICTURE_FUZZ"

static const std::string IMAGE_DEST = "/data/local/tmp/test_out.dat";
static constexpr uint32_t SIZE_WIDTH = 3072;
static constexpr uint32_t SIZE_HEIGHT = 4096;
static constexpr uint32_t MAX_LENGTH_MODULO = 0xfff;
static constexpr uint32_t PIXELFORMAT_MODULO = 105;
static constexpr uint32_t ALPHATYPE_MODULO = 4;
static constexpr uint32_t SCALEMODE_MODULO = 2;
static constexpr uint32_t AUXILIARYMODE_MODULO = 6;
static constexpr uint32_t MIMETYPE_MODULO = 14;
static constexpr uint32_t OPT_SIZE = 785;
static constexpr uint32_t DELAY_TIMES_SIZE = 2;
static constexpr uint32_t IMAGE_SOURCE_MIMETYPE_MODULO = 3;

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
FuzzedDataProvider* FDP;

void AuxiliaryPictureFuncTest(std::shared_ptr<AuxiliaryPicture> auxPicture)
{
    IMAGE_LOGI("%{public}s start", __func__);
    if (auxPicture == nullptr) {
        IMAGE_LOGE("%{public}s auxPicture null.", __func__);
        return;
    }
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
    MessageParcel data;
    if (auxPicture->Marshalling(data)) {
        Media::AuxiliaryPicture* unmarshallingAuxPicture = AuxiliaryPicture::Unmarshalling(data);
        if (unmarshallingAuxPicture == nullptr) {
            return;
        }
        delete unmarshallingAuxPicture;
        unmarshallingAuxPicture = nullptr;
    }
    IMAGE_LOGI("%{public}s SUCCESS.", __func__);
}

static void TestAllAuxiliaryPicture(std::shared_ptr<Picture> &picture)
{
    IMAGE_LOGI("%{public}s start.", __func__);
    AuxiliaryPictureType type =
        static_cast<Media::AuxiliaryPictureType>(FDP->ConsumeIntegral<uint8_t>() % AUXILIARYMODE_MODULO);
    std::shared_ptr<AuxiliaryPicture> auxPicture = picture->GetAuxiliaryPicture(type);
    if (auxPicture != nullptr) {
        IMAGE_LOGI("Picture has %{public}d auxiliaryPicture.", static_cast<int32_t>(type));
        picture->SetAuxiliaryPicture(auxPicture);
        AuxiliaryPictureFuncTest(auxPicture);
    }
    IMAGE_LOGI("%{public}s SUCCESS.", __func__);
}

static void EncodePictureTest(std::shared_ptr<Picture> picture)
{
    IMAGE_LOGI("%{public}s start.", __func__);
    if (picture == nullptr) {
        IMAGE_LOGE("%{public}s picture null.", __func__);
        return;
    }
    std::string mimeType[] = {"image/png", "image/raw", "image/vnd.wap.wbmp", "image/bmp", "image/gif", "image/jpeg",
        "image/mpo", "image/heic", "image/heif", "image/x-adobe-dng", "image/webp", "image/tiff", "image/x-icon",
        "image/x-sony-arw"};
    ImagePacker pack;
    PackOption packOption;
    packOption.format = mimeType[FDP->ConsumeIntegral<uint8_t>() % MIMETYPE_MODULO];
    packOption.quality = FDP->ConsumeIntegral<uint8_t>();
    packOption.numberHint = FDP->ConsumeIntegral<uint32_t>();
    packOption.desiredDynamicRange =
        static_cast<Media::EncodeDynamicRange>(FDP->ConsumeIntegral<uint8_t>() % ALPHATYPE_MODULO);
    packOption.needsPackProperties = FDP->ConsumeBool();
    packOption.isEditScene = FDP->ConsumeBool();
    packOption.loop = FDP->ConsumeIntegral<uint16_t>();
    uint8_t delayTimesSize = FDP->ConsumeIntegral<uint8_t>();
    std::vector<uint16_t> delayTimes(delayTimesSize);
    FDP->ConsumeData(delayTimes.data(), delayTimesSize * DELAY_TIMES_SIZE);
    packOption.delayTimes = delayTimes;
    uint8_t disposalSize = FDP->ConsumeIntegral<uint8_t>();
    packOption.disposalTypes = FDP->ConsumeBytes<uint8_t>(disposalSize);
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
    IMAGE_LOGI("%{public}s SUCCESS.", __func__);
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
    picture->SetExifMetadata(maintenanceData);
    MessageParcel data;
    if (picture->Marshalling(data)) {
        Media::Picture* unmarshallingPicture = Picture::Unmarshalling(data);
        if (!unmarshallingPicture) {
            return;
        }
        delete unmarshallingPicture;
        unmarshallingPicture = nullptr;
    }
    IMAGE_LOGI("%{public}s SUCCESS.", __func__);
}
/*
 *test picture IPc interface
 */
bool PictureIPCTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        IMAGE_LOGE("%{public}s data is nullptr.", __func__);
        return false;
    }
    //test parcel picture
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
    IMAGE_LOGI("%{public}s start.", __func__);
    Media::InitializationOptions opts;
    opts.size.width = FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO;
    opts.size.height = FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO;
    opts.srcPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    opts.pixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    opts.alphaType = static_cast<Media::AlphaType>(FDP->ConsumeIntegral<uint8_t>() % ALPHATYPE_MODULO);
    opts.scaleMode = static_cast<Media::ScaleMode>(FDP->ConsumeIntegral<uint8_t>() % SCALEMODE_MODULO);
    opts.editable = FDP->ConsumeBool();
    opts.useSourceIfMatch = FDP->ConsumeBool();
    int32_t pixelBytes = Media::ImageUtils::GetPixelBytes(opts.srcPixelFormat);
    size_t dataLength = opts.size.width * opts.size.height * pixelBytes;
    std::unique_ptr<uint8_t> colorData = std::make_unique<uint8_t>(dataLength);
    if (colorData == nullptr) {
        return false;
    }
    FDP->ConsumeData(colorData.get(), dataLength);
    std::shared_ptr<PixelMap> pixelMapFromOpts = Media::PixelMap::Create(reinterpret_cast<uint32_t*>(colorData.get()),
        dataLength, opts);
    if (pixelMapFromOpts.get() == nullptr) {
        return false;
    }
    std::unique_ptr<Picture> pictureFromOpts = Picture::Create(pixelMapFromOpts);
    if (pictureFromOpts.get() == nullptr) {
        return false;
    }
    MessageParcel parcel;
    pictureFromOpts->Marshalling(parcel);
    return true;
}

bool CreatePictureByRandomImageSource(const uint8_t *data, size_t size, const std::string& pathName)
{
    IMAGE_LOGI("%{public}s start.", __func__);
    BufferRequestConfig requestConfig = {
        .width = SIZE_WIDTH,
        .height = SIZE_HEIGHT,
        .strideAlignment = 0x8, // set 0x8 as default value to alloc SurfaceBufferImpl
        .format = GRAPHIC_PIXEL_FMT_YCRCB_420_SP, // hardware decode only support rgba8888
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
        .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,
    };
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    if (sb != nullptr) {
        sb->Alloc(requestConfig);
        Picture::Create(sb);
    }
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    SourceOptions opts;
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % IMAGE_SOURCE_MIMETYPE_MODULO];
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = nullptr;
    if (pathName != "") {
        imageSource = ImageSource::CreateImageSource(pathName, opts, errorCode);
    } else {
        imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    }
    if (imageSource == nullptr) {
        IMAGE_LOGE("%{public}s failed, imageSource is nullptr.", __func__);
        return false;
    }
    DecodingOptionsForPicture pictureOpts;
    pictureOpts.desireAuxiliaryPictures.insert(static_cast<Media::AuxiliaryPictureType>(
        FDP->ConsumeIntegral<uint8_t>()% AUXILIARYMODE_MODULO));
    pictureOpts.desiredPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() %
        PIXELFORMAT_MODULO);
    std::shared_ptr<Picture> picture = imageSource->CreatePicture(pictureOpts, errorCode);
    PictureFuncTest(picture);
    EncodePictureTest(picture);
    IMAGE_LOGI("%{public}s SUCCESS.", __func__);
    return true;
}

void HeifDecodeFuzz(const uint8_t *data, size_t size, const std::string& pathName = "")
{
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions opts;
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = nullptr;
    if (pathName != "") {
        imageSource = ImageSource::CreateImageSource(pathName, opts, errorCode);
    } else {
        imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    }
    
    if (imageSource == nullptr) {
        return;
    }
    auto extStream = std::make_unique<ImagePlugin::ExtStream>();
    if (extStream == nullptr) {
        return;
    }
    extStream->stream_ = imageSource->sourceStreamPtr_.get();
    std::unique_ptr<SkCodec> codec =
        SkCodec::MakeFromStream(std::make_unique<ImagePlugin::ExtStream>(extStream->stream_));
    if (codec == nullptr) {
        return;
    }
    auto heifContext = reinterpret_cast<ImagePlugin::HeifDecoderImpl*>(codec->getHeifContext());
    if (heifContext == nullptr) {
        return;
    }
    sptr<SurfaceBuffer> hwBuffer;
    heifContext->HwDecodeIdenImage(nullptr, heifContext->primaryImage_, heifContext->gridInfo_, &hwBuffer, true);
    HeifFrameInfo* frameInfo = nullptr;
    heifContext->getTmapInfo(frameInfo);
#endif
}
} // namespace Media
} // namespace OHOS

/*Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /*Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    std::string pathName = "/data/local/tmp/test_jpeg.jpg";
    OHOS::Media::CreatePictureByRandomImageSource(data, size, pathName);
    pathName = "/data/local/tmp/test_heif.heic";
    OHOS::Media::HeifDecodeFuzz(data, size, pathName);
    OHOS::Media::CreatePictureByRandomImageSource(data, size, pathName);
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 3;
    switch (action) {
        case 0:
            OHOS::Media::PictureRandomFuzzTest();
            break;
        case 1:
            OHOS::Media::PictureIPCTest(data, size - 1);
            break;
        default:
            if (size < OPT_SIZE) {
                return -1;
            }
            FuzzedDataProvider fdp(data + size - OPT_SIZE, OPT_SIZE - 1);
            OHOS::Media::FDP = &fdp;
            std::string path = "/data/local/tmp/test_picture_fuzz.jpg";
            WriteDataToFile(data, size - OPT_SIZE, path);
            OHOS::Media::CreatePictureByRandomImageSource(data, size, path);
            break;
    }
    return 0;
}