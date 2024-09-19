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

#include "image_picture_fuzzer.h"

#include <fcntl.h>
#include <surface.h>
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

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_PICTURE_FUZZ"

namespace OHOS {
namespace Media {
using namespace std;

constexpr int32_t SIZE_WIDTH = 2;
constexpr int32_t SIZE_HEIGHT = 3;
constexpr int32_t BUFFER_LENGTH = 8;
constexpr int32_t STRIDE_ALIGNMENT = 8;
static const std::string IMAGE_METADATA_SRC = "/data/local/tmp/image/test_metadata.jpg";
static const std::string IMAGE_INPUT_EXIF_JPEG_PATH = "/data/local/tmp/image/test_exif.jpg";
static const std::string IMAGE_JPEG_SRC = "/data/local/tmp/image/test_jpeg.jpg";
static const std::string IMAGE_JPEG_DEST = "/data/local/tmp/image/test_jpeg_out.jpg";
static const std::string IMAGE_HEIF_SRC = "/data/local/tmp/image/test_heif.heic";
static const std::string IMAGE_HEIF_DEST = "/data/local/tmp/image/test_heif_out.heic";

static std::shared_ptr<PixelMap> CreatePixelMap()
{
    const uint32_t color[BUFFER_LENGTH] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    InitializationOptions options;
    options.size.width = SIZE_WIDTH;
    options.size.height = SIZE_HEIGHT;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::shared_ptr<PixelMap> pixelmap = PixelMap::Create(color, BUFFER_LENGTH, options);
    return pixelmap;
}

static std::unique_ptr<Picture> CreatePicture()
{
    std::shared_ptr<PixelMap> pixelmap = CreatePixelMap();
    if (pixelmap == nullptr) {
        return nullptr;
    }
    return Picture::Create(pixelmap);
}

static std::shared_ptr<AuxiliaryPicture> CreateAuxiliaryPicture(AuxiliaryPictureType type)
{
    std::shared_ptr<PixelMap> pixelmap = CreatePixelMap();
    if (pixelmap == nullptr) {
        return nullptr;
    }
    Size size = {SIZE_WIDTH, SIZE_HEIGHT};
    std::unique_ptr<AuxiliaryPicture> tmpAuxiliaryPicture = AuxiliaryPicture::Create(pixelmap, type, size);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = std::move(tmpAuxiliaryPicture);
    return auxiliaryPicture;
}

static std::shared_ptr<ImageSource> CreateImageSourceByUri(const std::string uri)
{
    SourceOptions opts;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> tmpImageSource = ImageSource::CreateImageSource(uri, opts, errorCode);
    std::shared_ptr<ImageSource> imageSource = std::move(tmpImageSource);
    return imageSource;
}

static std::shared_ptr<Picture> CreatePictureByImageSourceUri(std::shared_ptr<ImageSource> imageSource)
{
    DecodingOptionsForPicture opts;
    uint32_t errorCode = 0;
    std::unique_ptr<Picture> tmpPicture = imageSource->CreatePicture(opts, errorCode);
    std::shared_ptr<Picture> picture = std::move(tmpPicture);
    return picture;
}

void ImagePackingTest001()
{
    std::shared_ptr<ImageSource> imageSource = CreateImageSourceByUri(IMAGE_JPEG_SRC);
    std::shared_ptr<Picture> picture = CreatePictureByImageSourceUri(imageSource);
    ImagePacker pack;
    PackOption option;
    option.format = "image/jpeg";
    pack.StartPacking(IMAGE_JPEG_DEST, option);
    pack.AddPicture(*picture);
    pack.FinalizePacking();
}

void ImagePackingTest002()
{
    std::shared_ptr<ImageSource> imageSource = CreateImageSourceByUri(IMAGE_HEIF_SRC);
    std::shared_ptr<Picture> picture = CreatePictureByImageSourceUri(imageSource);
    ImagePacker pack;
    PackOption option;
    option.format = "image/heif";
    pack.StartPacking(IMAGE_HEIF_DEST, option);
    pack.AddPicture(*picture);
    pack.FinalizePacking();
}

void CreatefromSurfaceBufferTest()
{
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = OHOS::SurfaceBuffer::Create();
    std::unique_ptr<Picture> picture = Picture::Create(surfaceBuffer);
}

void ExifMetadataTest()
{
    ImageMetadata::PropertyMapPtr KValueStr;
    auto exifData = exif_data_new_from_file(IMAGE_METADATA_SRC.c_str());
    ExifMetadata metadata(exifData);
    KValueStr = metadata.GetAllProperties();
    std::shared_ptr<ImageMetadata> newmetadata = metadata.CloneMetadata();
    Parcel data;
    metadata.Marshalling(data);
    ExifMetadata::Unmarshalling(data);
}

void PictureTest()
{
    std::shared_ptr<PixelMap> pixelmap = CreatePixelMap();
    std::unique_ptr<Picture> picture = CreatePicture();
    picture->SetMainPixel(pixelmap);

    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    picture->SetAuxiliaryPicture(auxiliaryPicture);
    picture->GetGainmapPixelMap();

    picture->SetAuxiliaryPicture(auxiliaryPicture);
    picture->GetAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    picture->HasAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);

    Parcel data;
    picture->Marshalling(data);
    Picture::Unmarshalling(data);

    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = OHOS::SurfaceBuffer::Create();
    picture->SetExifMetadata(surfaceBuffer);

    const int fd = open(IMAGE_INPUT_EXIF_JPEG_PATH.c_str(), O_RDWR | S_IRUSR | S_IWUSR);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(fd, opts, errorCode);
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    std::shared_ptr<PixelMap> newpixelMap = std::move(pixelMap);

    uint8_t dataBlob[] = "Test set maintenance data";
    uint32_t size = sizeof(dataBlob) / sizeof(dataBlob[0]);
    sptr<SurfaceBuffer> maintenanceBuffer = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = SIZE_WIDTH,
        .height = SIZE_HEIGHT,
        .strideAlignment = STRIDE_ALIGNMENT,
        .format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_BGRA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };
    maintenanceBuffer->Alloc(requestConfig);
    if (memcpy_s(maintenanceBuffer->GetVirAddr(), size, dataBlob, size) != 0) {
        picture->SetMaintenanceData(maintenanceBuffer);
        picture->GetMaintenanceData();
    }

    std::unique_ptr<Picture> pictureByImageSource = Picture::Create(newpixelMap);
    std::shared_ptr<ExifMetadata> exif = pictureByImageSource->GetExifMetadata();
    pictureByImageSource->SetExifMetadata(exif);
}

void AuxiliaryPictureTest()
{
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    OHOS::Media::AuxiliaryPictureType type = auxiliaryPicture->GetType();
    auxiliaryPicture->SetType(type);

    Size size = auxiliaryPicture->GetSize();
    auxiliaryPicture->SetSize(size);

    std::shared_ptr<PixelMap> pixelMap = auxiliaryPicture->GetContentPixel();
    auxiliaryPicture->SetContentPixel(pixelMap);

    uint64_t bufferSize = auxiliaryPicture->GetContentPixel()->GetCapacity();
    if (bufferSize >= 0) {
        auto buffer = new uint8_t[bufferSize];
        auxiliaryPicture->ReadPixels(bufferSize, buffer);
        auxiliaryPicture->WritePixels(buffer, bufferSize);
    }
    const std::string srcValue = "9, 9, 8";
    auto exifData = exif_data_new_from_file(IMAGE_METADATA_SRC.c_str());
    std::shared_ptr<ExifMetadata> srcExifMetadata = std::make_shared<ExifMetadata>(exifData);
    auxiliaryPicture->SetMetadata(MetadataType::EXIF, srcExifMetadata);
    std::shared_ptr<ImageMetadata> dstExifMetadata = auxiliaryPicture->GetMetadata(MetadataType::EXIF);
    auxiliaryPicture->HasMetadata(MetadataType::EXIF);

    OHOS::Media::AuxiliaryPictureInfo info = auxiliaryPicture->GetAuxiliaryPictureInfo();
    auxiliaryPicture->SetAuxiliaryPictureInfo(info);

    Parcel data;
    auxiliaryPicture->Marshalling(data);
    AuxiliaryPicture::Unmarshalling(data);
}

void CreateAuxiliaryPictureTestBySurfaceBuffer()
{
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = SurfaceBuffer::Create();
    AuxiliaryPicture::Create(buffer, OHOS::Media::AuxiliaryPictureType::GAINMAP);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::PictureTest();
    OHOS::Media::CreatefromSurfaceBufferTest();
    OHOS::Media::AuxiliaryPictureTest();
    OHOS::Media::CreateAuxiliaryPictureTestBySurfaceBuffer();
    OHOS::Media::ExifMetadataTest();
    OHOS::Media::ImagePackingTest001();
    OHOS::Media::ImagePackingTest002();
    return 0;
}
