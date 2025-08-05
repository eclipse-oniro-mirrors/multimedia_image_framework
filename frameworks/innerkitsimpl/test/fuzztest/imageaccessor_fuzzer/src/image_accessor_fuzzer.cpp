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

#include "image_accessor_fuzzer.h"
#define private public

#include <cstdint>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include "securec.h"

#include "common_fuzztest_function.h"
#include "metadata_accessor_factory.h"
#include "dng_exif_metadata_accessor.h"
#include "heif_exif_metadata_accessor.h"
#include "jpeg_exif_metadata_accessor.h"
#include "png_exif_metadata_accessor.h"
#include "webp_exif_metadata_accessor.h"
#include "file_metadata_stream.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_ACCESSOR_FUZZ"

namespace OHOS {
namespace Media {
using namespace std;

void AccessMetadata(std::shared_ptr<ExifMetadata> exifMetadata, const std::string& key, const std::string &value)
{
    if (exifMetadata == nullptr) {
        IMAGE_LOGI("%{public}s failed, exifMetadata is null", __func__);
        return;
    }
    exifMetadata->SetValue(key, value); 
    std::string res = "";
    exifMetadata->GetValue(key, res);
    exifMetadata->RemoveEntry(key);
}

void MetadataFuncTest001(std::shared_ptr<ExifMetadata> exifMetadata)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    if (exifMetadata == nullptr) {
        IMAGE_LOGI("%{public}s failed, exifMetadata is null", __func__);
        return;
    }
    AccessMetadata(exifMetadata, "BitsPerSample", "9, 7, 8");
    AccessMetadata(exifMetadata, "Orientation", "Top-right");
    AccessMetadata(exifMetadata, "ImageLength", "1000");
    AccessMetadata(exifMetadata, "ImageWidth", "500");
    AccessMetadata(exifMetadata, "GPSLatitude", "39, 54, 20");
    AccessMetadata(exifMetadata, "GPSLongitude", "120, 52, 26");
    AccessMetadata(exifMetadata, "GPSLatitudeRef", "N");
    AccessMetadata(exifMetadata, "GPSLongitudeRef", "E");
    AccessMetadata(exifMetadata, "DateTimeOriginal", "2024:01:25 05:51:34");
    AccessMetadata(exifMetadata, "ExposureTime", "1/34 sec.");
    AccessMetadata(exifMetadata, "SceneType", "Directly photographed");
    AccessMetadata(exifMetadata, "ISOSpeedRatings", "160");
    AccessMetadata(exifMetadata, "FNumber", "f/3.0");
    AccessMetadata(exifMetadata, "DateTime", "");
    AccessMetadata(exifMetadata, "GPSTimeStamp", "11:37:58.00");
    AccessMetadata(exifMetadata, "GPSDateStamp", "2025:01:11");
    AccessMetadata(exifMetadata, "ImageDescription", "_cuva");
    AccessMetadata(exifMetadata, "Make", "");
    AccessMetadata(exifMetadata, "Model", "TNY-AL00");
    AccessMetadata(exifMetadata, "SensitivityType", "Standard output sensitivity (SOS) and ISO speed");
    AccessMetadata(exifMetadata, "StandardOutputSensitivity", "5");
    AccessMetadata(exifMetadata, "RecommendedExposureIndex", "241");
    AccessMetadata(exifMetadata, "ApertureValue", "4.00 EV (f/4.0)");
    AccessMetadata(exifMetadata, "ExposureBiasValue", "23.00 EV");
    AccessMetadata(exifMetadata, "MeteringMode", "Pattern");
    AccessMetadata(exifMetadata, "LightSource", "Fluorescent");
    AccessMetadata(exifMetadata, "Flash", "Strobe return light not detected");
    AccessMetadata(exifMetadata, "FocalLength", "31.0 mm");
    AccessMetadata(exifMetadata, "UserComment", "comm");
    AccessMetadata(exifMetadata, "PixelXDimension", "1000");
    AccessMetadata(exifMetadata, "PixelYDimension", "2000");
    AccessMetadata(exifMetadata, "WhiteBalance", "Manual white balance");
    AccessMetadata(exifMetadata, "FocalLengthIn35mmFilm", "26");
    AccessMetadata(exifMetadata, "JPEGProc", "252");
    AccessMetadata(exifMetadata, "MakerNote", "HwMnoteCaptureMode:123");
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void MetadataFuncTest002(std::shared_ptr<ExifMetadata> exifMetadata)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    if (exifMetadata == nullptr) {
        IMAGE_LOGI("%{public}s failed, exifMetadata is null", __func__);
        return;
    }
    AccessMetadata(exifMetadata, "MaxApertureValue", "0.08 EV (f/1.0)");
    AccessMetadata(exifMetadata, "Artist", "Joseph.Xu");
    AccessMetadata(exifMetadata, "NewSubfileType", "1");
    AccessMetadata(exifMetadata, "OECF", "1 bytes undefined data");
    AccessMetadata(exifMetadata, "PlanarConfiguration", "Chunky format");
    AccessMetadata(exifMetadata, "PrimaryChromaticities", "124");
    AccessMetadata(exifMetadata, "ReferenceBlackWhite", "221");
    AccessMetadata(exifMetadata, "ResolutionUnit", "Inch");
    AccessMetadata(exifMetadata, "SamplesPerPixel", "23");
    AccessMetadata(exifMetadata, "Compression", "JPEG compression");
    AccessMetadata(exifMetadata, "Software", "MNA-AL00 4.0.0.120(C00E116R3P7)");
    AccessMetadata(exifMetadata, "Copyright", "xxxxxx (Photographer) - [None] (Editor)");
    AccessMetadata(exifMetadata, "SpectralSensitivity", "sensitivity");
    AccessMetadata(exifMetadata, "DNGVersion", "0x01, 0x01, 0x02, 0x03");
    AccessMetadata(exifMetadata, "SubjectDistance", "");
    AccessMetadata(exifMetadata, "DefaultCropSize", "12, 1");
    AccessMetadata(exifMetadata, "SubjectLocation", "3");
    AccessMetadata(exifMetadata, "TransferFunction", "2");
    AccessMetadata(exifMetadata, "WhitePoint", "124.2");
    AccessMetadata(exifMetadata, "XResolution", "72");
    AccessMetadata(exifMetadata, "YCbCrCoefficients", "0.299, 0.587, 0.114");
    AccessMetadata(exifMetadata, "YCbCrPositioning", "Centered");
    AccessMetadata(exifMetadata, "YCbCrSubSampling", "3, 2");
    AccessMetadata(exifMetadata, "YResolution", "72");
    AccessMetadata(exifMetadata, "Gamma", "1.5");
    AccessMetadata(exifMetadata, "ISOSpeed", "200");
    AccessMetadata(exifMetadata, "ISOSpeedLatitudeyyy", "3");
    AccessMetadata(exifMetadata, "ISOSpeedLatitudezzz", "3");
    AccessMetadata(exifMetadata, "ImageUniqueID", "FXIC012");
    AccessMetadata(exifMetadata, "JPEGInterchangeFormat", "");
    AccessMetadata(exifMetadata, "JPEGInterchangeFormatLength", "");
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void MetadataFuncTest003(std::shared_ptr<ExifMetadata> exifMetadata)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    if (exifMetadata == nullptr) {
        IMAGE_LOGI("%{public}s failed, exifMetadata is null", __func__);
        return;
    }
    AccessMetadata(exifMetadata, "GPSAltitude", "0.00");
    AccessMetadata(exifMetadata, "GPSAltitudeRef", "Sea level reference");
    AccessMetadata(exifMetadata, "GPSAreaInformation", "23...15...57");
    AccessMetadata(exifMetadata, "GPSDOP", "182");
    AccessMetadata(exifMetadata, "GPSDestBearing", "2.6");
    AccessMetadata(exifMetadata, "GPSDestBearingRef", "T");
    AccessMetadata(exifMetadata, "GPSDestDistance", "10");
    AccessMetadata(exifMetadata, "GPSDestDistanceRef", "N");
    AccessMetadata(exifMetadata, "GPSDestLatitude", "33, 22, 11");
    AccessMetadata(exifMetadata, "GPSDestLatitudeRef", "N");
    AccessMetadata(exifMetadata, "GPSDestLongitude", "33, 22, 11");
    AccessMetadata(exifMetadata, "GPSDestLongitudeRef", "E");
    AccessMetadata(exifMetadata, "GPSDifferential", "1");
    AccessMetadata(exifMetadata, "GPSImgDirection", "2.23214");
    AccessMetadata(exifMetadata, "GPSImgDirectionRef", "M");
    AccessMetadata(exifMetadata, "GPSMapDatum", "xxxx");
    AccessMetadata(exifMetadata, "GPSMeasureMode", "2");
    AccessMetadata(exifMetadata, "GPSProcessingMethod", "CELLID");
    AccessMetadata(exifMetadata, "GPSSatellites", "xxx");
    AccessMetadata(exifMetadata, "GPSSpeed", "150");
    AccessMetadata(exifMetadata, "GPSSpeedRef", "K");
    AccessMetadata(exifMetadata, "GPSStatus", "V");
    AccessMetadata(exifMetadata, "GPSTrack", "56");
    AccessMetadata(exifMetadata, "GPSTrackRef", "T");
    AccessMetadata(exifMetadata, "GPSVersionID", "2.2.0.0");
    AccessMetadata(exifMetadata, "GPSHPositioningError", " 3");
    AccessMetadata(exifMetadata, "LensMake", "xxx");
    AccessMetadata(exifMetadata, "LensModel", "xxx");
    AccessMetadata(exifMetadata, "LensSerialNumber", "xxx");
    AccessMetadata(exifMetadata, "LensSpecification", " 1, 1.5,  1,  2");
    AccessMetadata(exifMetadata, "MakerNote", "HwMnoteCaptureMode:123");
    AccessMetadata(exifMetadata, "GainControl", "Normal");
    AccessMetadata(exifMetadata, "OffsetTime", "xx");
    AccessMetadata(exifMetadata, "OffsetTimeDigitized", "xx");
    AccessMetadata(exifMetadata, "OffsetTimeOriginal", "xx");
    AccessMetadata(exifMetadata, "PhotometricInterpretation", "");
    AccessMetadata(exifMetadata, "RelatedSoundFile", "/usr/home/sound/sea.wav");
    AccessMetadata(exifMetadata, "RowsPerStrip", "");
    AccessMetadata(exifMetadata, "Saturation", "Normal");
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void MetadataFuncTest004(std::shared_ptr<ExifMetadata> exifMetadata)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    if (exifMetadata == nullptr) {
        IMAGE_LOGI("%{public}s failed, exifMetadata is null", __func__);
        return;
    }
    AccessMetadata(exifMetadata, "SceneCaptureType", "Standard");
    AccessMetadata(exifMetadata, "SensingMethod", "Two-chip color area sensor");
    AccessMetadata(exifMetadata, "Sharpness", "Normal");
    AccessMetadata(exifMetadata, "ShutterSpeedValue", "13.00 EV (1/8192 sec.)");
    AccessMetadata(exifMetadata, "SourceExposureTimesOfCompositeImage", ".");
    AccessMetadata(exifMetadata, "SourceImageNumberOfCompositeImage", "1234");
    AccessMetadata(exifMetadata, "SpatialFrequencyResponse", ".");
    AccessMetadata(exifMetadata, "StripByteCounts", "");
    AccessMetadata(exifMetadata, "StripOffsets", "");
    AccessMetadata(exifMetadata, "SubsecTime", "427000");
    AccessMetadata(exifMetadata, "SubsecTimeDigitized", "427000");
    AccessMetadata(exifMetadata, "SubsecTimeOriginal", "427000");
    AccessMetadata(exifMetadata, "SubfileType", "");
    AccessMetadata(exifMetadata, "SubjectArea",
        "Within rectangle (width 183, height 259) around (x,y) = (10,20)");
    AccessMetadata(exifMetadata, "SubjectDistanceRange", "Unknown");
    AccessMetadata(exifMetadata, "BodySerialNumber", "xx");
    AccessMetadata(exifMetadata, "BrightnessValue", "2.50 EV (19.38 cd/m^2)");
    AccessMetadata(exifMetadata, "CFAPattern", "1 bytes undefined data");
    AccessMetadata(exifMetadata, "CameraOwnerName", "xx");
    AccessMetadata(exifMetadata, "ColorSpace", "Adobe RGB");
    AccessMetadata(exifMetadata, "ComponentsConfiguration", "");
    AccessMetadata(exifMetadata, "CompositeImage", "1");
    AccessMetadata(exifMetadata, "CompressedBitsPerPixel", "1.5");
    AccessMetadata(exifMetadata, "Contrast", "Normal");
    AccessMetadata(exifMetadata, "CustomRendered", "Custom process");
    AccessMetadata(exifMetadata, "DateTimeDigitized", "2023:01:19 10:39:58");
    AccessMetadata(exifMetadata, "DeviceSettingDescription", ".");
    AccessMetadata(exifMetadata, "DigitalZoomRatio", "321");
    AccessMetadata(exifMetadata, "ExifVersion", "");
    AccessMetadata(exifMetadata, "ExposureIndex", "1.5");
    AccessMetadata(exifMetadata, "ExposureMode", "Auto exposure");
    AccessMetadata(exifMetadata, "ExposureProgram", "Normal program");
    AccessMetadata(exifMetadata, "FileSource", "DSC");
    AccessMetadata(exifMetadata, "FlashEnergy", "832");
    AccessMetadata(exifMetadata, "FlashpixVersion", "");
    AccessMetadata(exifMetadata, "FocalPlaneResolutionUnit", "Centimeter");
    AccessMetadata(exifMetadata, "FocalPlaneXResolution", "1080");
    AccessMetadata(exifMetadata, "FocalPlaneYResolution", "880");
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void MetadataFuncTest005(std::shared_ptr<ExifMetadata> exifMetadata)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    if (exifMetadata == nullptr) {
        IMAGE_LOGI("%{public}s failed, exifMetadata is null", __func__);
        return;
    }
    AccessMetadata(exifMetadata, "BitsPerSample", "8, 8, 8");
    AccessMetadata(exifMetadata, "Orientation", "Unknown value 0");
    AccessMetadata(exifMetadata, "ImageLength", "4000");
    AccessMetadata(exifMetadata, "ImageWidth", "3000");
    AccessMetadata(exifMetadata, "GPSLatitude", "");
    AccessMetadata(exifMetadata, "GPSLongitude", "");
    AccessMetadata(exifMetadata, "GPSLatitudeRef", "");
    AccessMetadata(exifMetadata, "GPSLongitudeRef", "");
    AccessMetadata(exifMetadata, "DateTimeOriginal", "2024:01:11 09:39:58");
    AccessMetadata(exifMetadata, "ExposureTime", "1/590 sec.");
    AccessMetadata(exifMetadata, "SceneType", "Directly photographed");
    AccessMetadata(exifMetadata, "ISOSpeedRatings", "160");
    AccessMetadata(exifMetadata, "FNumber", "f/2.0");
    AccessMetadata(exifMetadata, "DateTime", "");
    AccessMetadata(exifMetadata, "GPSTimeStamp", "01:39:58.00");
    AccessMetadata(exifMetadata, "GPSDateStamp", "2024:01:11");
    AccessMetadata(exifMetadata, "ImageDescription", "_cuva");
    AccessMetadata(exifMetadata, "Make", "");
    AccessMetadata(exifMetadata, "Model", "");
    AccessMetadata(exifMetadata, "SensitivityType", "");
    AccessMetadata(exifMetadata, "StandardOutputSensitivity", "");
    AccessMetadata(exifMetadata, "RecommendedExposureIndex", "");
    AccessMetadata(exifMetadata, "ApertureValue", "2.00 EV (f/2.0)");
    AccessMetadata(exifMetadata, "ExposureBiasValue", "0.00 EV");
    AccessMetadata(exifMetadata, "MeteringMode", "Pattern");
    AccessMetadata(exifMetadata, "LightSource", "Daylight");
    AccessMetadata(exifMetadata, "Flash", "Flash did not fire");
    AccessMetadata(exifMetadata, "FocalLength", "6.3 mm");
    AccessMetadata(exifMetadata, "UserComment", "");
    AccessMetadata(exifMetadata, "PixelXDimension", "4000");
    AccessMetadata(exifMetadata, "PixelYDimension", "3000");
    AccessMetadata(exifMetadata, "WhiteBalance", "Auto white balance");
    AccessMetadata(exifMetadata, "FocalLengthIn35mmFilm", "27");
    AccessMetadata(exifMetadata, "JPEGProc", "");
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void MetadataAccessorFuncTest001(std::shared_ptr<MetadataAccessor>& metadataAccessor)
{
    if (metadataAccessor == nullptr) {
        return;
    }
    metadataAccessor->Read();
    auto exifMetadata = metadataAccessor->Get();
    if (exifMetadata == nullptr) {
        return;
    }
    std::string key = "ImageWidth";
    MetadataFuncTest001(exifMetadata);
    MetadataFuncTest002(exifMetadata);
    MetadataFuncTest003(exifMetadata);
    MetadataFuncTest004(exifMetadata);
    MetadataFuncTest005(exifMetadata);
    metadataAccessor->Write();
    metadataAccessor->Set(exifMetadata);
    DataBuf inputBuf;
    metadataAccessor->ReadBlob(inputBuf);
    metadataAccessor->WriteBlob(inputBuf);
}

void JpegAccessorTest(const std::string& pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(pathName);
    if (metadataAccessor == nullptr) {
        IMAGE_LOGI("%{public}s failed", __func__);
        return;
    }
    MetadataAccessorFuncTest001(metadataAccessor);
    auto jpegMetadataAccessor = reinterpret_cast<JpegExifMetadataAccessor*>(metadataAccessor.get());
    jpegMetadataAccessor->Read();
    jpegMetadataAccessor->Write();
    DataBuf inputBuf;
    jpegMetadataAccessor->WriteBlob(inputBuf);
    int marker = jpegMetadataAccessor->FindNextMarker();
    jpegMetadataAccessor->ReadSegmentLength(static_cast<uint8_t>(marker));
    jpegMetadataAccessor->ReadNextSegment(static_cast<byte>(marker));
    jpegMetadataAccessor->GetInsertPosAndMarkerAPP1();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void PngAccessorTest(const std::string& pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(pathName);
    if (metadataAccessor == nullptr) {
        IMAGE_LOGI("%{public}s failed", __func__);
        return;
    }
    MetadataAccessorFuncTest001(metadataAccessor);
    auto pngMetadataAccessor = reinterpret_cast<PngExifMetadataAccessor*>(metadataAccessor.get());
    pngMetadataAccessor->IsPngType();
    pngMetadataAccessor->Read();
    pngMetadataAccessor->Write();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void WebpAccessorTest(const std::string& pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(pathName);
    if (metadataAccessor == nullptr) {
        IMAGE_LOGI("%{public}s failed", __func__);
        return;
    }
    MetadataAccessorFuncTest001(metadataAccessor);
    auto webpMetadataAccessor = reinterpret_cast<WebpExifMetadataAccessor*>(metadataAccessor.get());
    webpMetadataAccessor->Read();
    webpMetadataAccessor->Write();
    Vp8xAndExifInfo exifFlag = Vp8xAndExifInfo::UNKNOWN;
    webpMetadataAccessor->CheckChunkVp8x(exifFlag);
    webpMetadataAccessor->GetImageWidthAndHeight();
    std::string strChunkId = "000";
    DataBuf chunkData = {};
    webpMetadataAccessor->GetWidthAndHeightFormChunk(strChunkId, chunkData);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void HeifAccessorTest(const std::string& pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(pathName);
    if (metadataAccessor == nullptr) {
        IMAGE_LOGI("%{public}s failed", __func__);
        return;
    }
    MetadataAccessorFuncTest001(metadataAccessor);
    auto heifMetadataAccessor = reinterpret_cast<HeifExifMetadataAccessor*>(metadataAccessor.get());
    heifMetadataAccessor->Read();
    heifMetadataAccessor->Write();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void DngAccessorTest(const std::string& pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(pathName);
    if (metadataAccessor == nullptr) {
        IMAGE_LOGI("%{public}s failed", __func__);
        return;
    }
    MetadataAccessorFuncTest001(metadataAccessor);
    auto dngMetadataAccessor = reinterpret_cast<DngExifMetadataAccessor*>(metadataAccessor.get());
    dngMetadataAccessor->Read();
    dngMetadataAccessor->Write();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void DataBufTest(const uint8_t *data, size_t size)
{
    if (size == 0) {
        return;
    }
    DataBuf dataBuf(data, size);
    dataBuf.ReadUInt8(0);
    dataBuf.Resize(size);
    dataBuf.WriteUInt8(0, 0);
    dataBuf.Reset();
}

void AccessorTest001()
{
    static const std::string JPEG_EXIF_PATH = "/data/local/tmp/test_exif.jpg";
    static const std::string PNG_EXIF_PATH = "/data/local/tmp/test_exif.png";
    static const std::string WEBP_EXIF_PATH = "/data/local/tmp/test_exif.webp";
    static const std::string HEIF_EXIF_PATH = "/data/local/tmp/test_exif.heic";
    static const std::string DNG_EXIF_PATH = "/data/local/tmp/test_exif.dng";
    JpegAccessorTest(JPEG_EXIF_PATH);
    PngAccessorTest(PNG_EXIF_PATH);
    WebpAccessorTest(WEBP_EXIF_PATH);
    HeifAccessorTest(HEIF_EXIF_PATH);
    DngAccessorTest(DNG_EXIF_PATH);
}

void AccessorTest002(const uint8_t* data, size_t size)
{
    std::string filename = "/data/local/tmp/test_parse_exif.jpg";
    if (!WriteDataToFile(data, size, filename)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return;
    }
    BufferMetadataStream::MemoryMode mode = BufferMetadataStream::MemoryMode::Dynamic;
    std::shared_ptr<MetadataAccessor> metadataAccessor1 = MetadataAccessorFactory::Create(const_cast<uint8_t*>(data),
        size, mode);
    MetadataAccessorFuncTest001(metadataAccessor1);
    std::shared_ptr<MetadataAccessor> metadataAccessor2 = MetadataAccessorFactory::Create(filename);
    MetadataAccessorFuncTest001(metadataAccessor2);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::DataBufTest(data, size);
    OHOS::Media::AccessorTest001();
    OHOS::Media::AccessorTest002(data, size);
    return 0;
}