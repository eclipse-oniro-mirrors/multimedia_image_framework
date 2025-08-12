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

#include "image_fwk_decode_picture_fuzzer.h"

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

static const std::string IMAGE_JPEG_DEST = "/data/local/tmp/test_jpeg_out.jpg";
static const std::string IMAGE_HEIF_DEST = "/data/local/tmp/test_heif_out.heic";
static const std::string JPEG_FORMAT = "image/jpeg";
static const std::string HEIF_FORMAT = "image/heif";
static const std::string IMAGE_ENCODE_DEST = "/data/local/tmp/test_out.dat";
static const uint32_t WIDTH_FACTOR = 4;
static const uint32_t SIZE_WIDTH = 3072;
static const uint32_t SIZE_HEIGHT = 4096;
static const int32_t MAX_WIDTH = 4096;
static const int32_t MAX_HEIGHT = 4096;

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;

namespace {
    const uint8_t* g_data = nullptr;
    size_t g_size = 0;
    size_t g_pos = 0;
} // namespace
/*
 *describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
 * tips: only support basic type
 */
template<class T>
T GetData()
{
    T object {};
    size_t objectsize = sizeof(object);
    if (g_data == nullptr || objectsize > g_size - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectsize, g_data + g_pos, objectsize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectsize;
    return object;
}
/*
 *get parcel from g_data
 */
bool ChangeParcel(Parcel &parcel)
{
    if (!parcel.WriteBuffer(g_data, g_size)) {
        return false;
    }
    return true;
}
/*
 *get a pixelmap from opts
 */
std::unique_ptr<Media::PixelMap> GetPixelMapFromOpts(Media::PixelFormat pixelFormat = PixelFormat::UNKNOWN)
{
    int32_t width = GetData<int32_t>();
    int32_t height = GetData<int32_t>();
    if (width <= 0 || width > MAX_WIDTH) {
        return nullptr;
    }
    if (height <= 0 || height > MAX_HEIGHT) {
        return nullptr;
    }
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.pixelFormat = pixelFormat == PixelFormat::UNKNOWN ?
        static_cast<Media::PixelFormat>(GetData<int32_t>()) : pixelFormat;
    opts.alphaType = static_cast<Media::AlphaType>(GetData<int32_t>());
    opts.scaleMode = static_cast<Media::ScaleMode>(GetData<int32_t>());
    opts.editable = GetData<bool>();
    opts.useSourceIfMatch = GetData<bool>();
    return Media::PixelMap::Create(opts);
}

/*
 * get a pixelmap from g_data
 */
std::unique_ptr<Media::PixelMap> GetPixelMapFromData(Media::PixelFormat pixelFormat = PixelFormat::UNKNOWN)
{
    int32_t width = GetData<int32_t>();
    int32_t height = GetData<int32_t>();
    if (width <= 0 || width > MAX_WIDTH) {
        return nullptr;
    }
    if (height <= 0 || height > MAX_HEIGHT) {
        return nullptr;
    }
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.pixelFormat = pixelFormat == PixelFormat::UNKNOWN ?
        static_cast<Media::PixelFormat>(GetData<int32_t>()) : pixelFormat;
    opts.alphaType = static_cast<Media::AlphaType>(GetData<int32_t>());
    opts.scaleMode = static_cast<Media::ScaleMode>(GetData<int32_t>());
    opts.editable = GetData<bool>();
    opts.useSourceIfMatch = GetData<bool>();
    size_t datalength = width * height * WIDTH_FACTOR;
    std::unique_ptr<uint32_t[]> colorData = std::make_unique<uint32_t[]>(datalength);
    for (size_t i = 0; i < datalength; i++) {
        colorData[i] = GetData<uint32_t>();
    }
    return Media::PixelMap::Create(colorData.get(), datalength, opts);
}

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
    std::shared_ptr<AuxiliaryPicture> auxGainPic = picture->GetAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    if (auxGainPic != nullptr) {
        IMAGE_LOGI("Picture has GAINMAP auxiliaryPicture.");
        picture->SetAuxiliaryPicture(auxGainPic);
        AuxiliaryPictureFuncTest(auxGainPic);
    }
    std::shared_ptr<AuxiliaryPicture> auxDepthPic = picture->GetAuxiliaryPicture(AuxiliaryPictureType::DEPTH_MAP);
    if (auxDepthPic != nullptr) {
        IMAGE_LOGI("Picture has DEPTH_MAP auxiliaryPicture.");
        picture->SetAuxiliaryPicture(auxDepthPic);
        AuxiliaryPictureFuncTest(auxDepthPic);
    }
    std::shared_ptr<AuxiliaryPicture> auxUnrefocusPic =
        picture->GetAuxiliaryPicture(AuxiliaryPictureType::UNREFOCUS_MAP);
    if (auxUnrefocusPic != nullptr) {
        IMAGE_LOGI("Picture has UNREFOCUS_MAP auxiliaryPicture.");
        picture->SetAuxiliaryPicture(auxUnrefocusPic);
        AuxiliaryPictureFuncTest(auxUnrefocusPic);
    }
    std::shared_ptr<AuxiliaryPicture> auxLinearPic = picture->GetAuxiliaryPicture(AuxiliaryPictureType::LINEAR_MAP);
    if (auxLinearPic != nullptr) {
        IMAGE_LOGI("Picture has LINEAR_MAP auxiliaryPicture.");
        picture->SetAuxiliaryPicture(auxLinearPic);
        AuxiliaryPictureFuncTest(auxLinearPic);
    }
    std::shared_ptr<AuxiliaryPicture> auxFramentPic = picture->GetAuxiliaryPicture(AuxiliaryPictureType::FRAGMENT_MAP);
    if (auxFramentPic != nullptr) {
        IMAGE_LOGI("Picture has FRAGMENT _MAP auxiliaryPicture.");
        picture->SetAuxiliaryPicture(auxFramentPic);
        AuxiliaryPictureFuncTest(auxFramentPic);
    }
    IMAGE_LOGI("%{public}s SUCCESS.", __func__);
}

static void EncodePictureTest(std::shared_ptr<Picture> picture, const std::string& format,
    const std::string& outputPath)
{
    IMAGE_LOGI("%{public}s start.", __func__);
    if (picture == nullptr) {
        IMAGE_LOGE("%{public}s picture null.", __func__);
        return;
    }
    ImagePacker pack;
    PackOption packoption;
    packoption.format = format;
    if (pack.StartPacking(outputPath, packoption) != SUCCESS) {
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
bool PictureIPCTest(std::unique_ptr<Picture> &picture)
{
    if (picture == nullptr) {
        IMAGE_LOGE("%{public}s picture is nullptr.", __func__);
        return false;
    }
    //test parcel picture
    MessageParcel parcel;
    if (picture->Marshalling(parcel)) {
        ChangeParcel(parcel);
        Media::Picture* unmarshallingPicture = Media::Picture::Unmarshalling(parcel);
        if (unmarshallingPicture != nullptr) {
            delete unmarshallingPicture;
            unmarshallingPicture = nullptr;
        } else {
            IMAGE_LOGE("%{public}s Unmarshalling falied.", __func__);
        }
    } else {
        IMAGE_LOGE("%{public}s Marshalling falied.", __func__);
    }
    return true;
}

bool PictureRandomFuzzTest(const uint8_t* data, size_t size)
{
    IMAGE_LOGI("%{public}s start.", __func__);
    if (data == nullptr) {
    return false;
    }
    //initialize
    g_data = data;
    g_size = size;
    g_pos = 0;
    // create from opts
    std::shared_ptr<PixelMap> pixelMapFromOpts = GetPixelMapFromOpts(Media::PixelFormat::RGBA_8888);
    if (!pixelMapFromOpts) {
        return false;
    }
    std::unique_ptr<Picture> pictureFromOpts = Picture::Create(pixelMapFromOpts);
    if (!pictureFromOpts) {
        return false;
    }
    //create from data
    std::shared_ptr<Media::PixelMap> pixelMapFromData = GetPixelMapFromData(Media::PixelFormat::RGBA_8888);
    if (!pixelMapFromData) {
        return false;
    }
    std::unique_ptr<Picture> pictureFromData = Picture::Create(pixelMapFromData);
    if (!pictureFromData) {
        return false;
    }
    PictureIPCTest(pictureFromOpts);
    PictureIPCTest(pictureFromData);
    IMAGE_LOGI("%{public}s SUCCESS.", __func__);
    return true;
}

bool CreatePictureByRandomImageSource(const uint8_t *data, size_t size, const std::string& pathName)
{
    IMAGE_LOGI("%{public}s start.", __func__);
    BufferRequestConfig requestConfig = {
        .width = SIZE_WIDTH,
        .height = SIZE_HEIGHT,
        .strideAlignment = 0x8, // set Ox8 as default value to alloc SurfaceBufferImpl
        .format = GRAPHIC_PIXEL_FMT_YCRCB_420_SP, // hardware decode only support rgba8888
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
        .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,
    };
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    sb->Alloc(requestConfig);
    Picture::Create(sb);
    SourceOptions opts;
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
    std::shared_ptr<Picture> picture = imageSource->CreatePicture(pictureOpts, errorCode);
    PictureFuncTest(picture);
    EncodePictureTest(picture, JPEG_FORMAT, IMAGE_JPEG_DEST);
    EncodePictureTest(picture, HEIF_FORMAT, IMAGE_HEIF_DEST);
    pictureOpts.desiredPixelFormat = PixelFormat::NV21;
    picture = imageSource->CreatePicture(pictureOpts, errorCode);
    PictureFuncTest(picture);
    EncodePictureTest(picture, JPEG_FORMAT, IMAGE_JPEG_DEST);
    EncodePictureTest(picture, HEIF_FORMAT, IMAGE_HEIF_DEST);
    IMAGE_LOGI("%{public}s SUCCESS.", __func__);
    return true;
}
} // namespace Media
} // namespace OHOS

/*Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /*Run your code on data */
    OHOS::Media::PictureRandomFuzzTest(data, size);
    std::string pathName = "/data/local/tmp/test_jpeg.jpg";
    OHOS::Media::CreatePictureByRandomImageSource(data, size, pathName);
    pathName = "/data/local/tmp/test_heif.heic";
    OHOS::Media::CreatePictureByRandomImageSource(data, size, pathName);
    return 0;
}