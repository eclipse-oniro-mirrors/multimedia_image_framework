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
#include <fuzzer/FuzzedDataProvider.h>
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
#include "exif_metadata_formatter.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_ACCESSOR_FUZZ"

namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;
using namespace std;

void AccessMetadata(std::shared_ptr<ExifMetadata> exifMetadata, const std::string &key, const std::string &value)
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

void MetadataAccessorFuncTest(std::shared_ptr<MetadataAccessor> &metadataAccessor)
{
    if (metadataAccessor == nullptr) {
        return;
    }
    metadataAccessor->Read();
    auto exifMetadata = metadataAccessor->Get();
    if (exifMetadata == nullptr) {
        return;
    }
    uint32_t index = FDP->ConsumeIntegral<uint32_t>() % KEY_VALUE_MAPS.size();
    auto key = KEY_VALUE_MAPS[index].first;
    for (const auto &v : KEY_VALUE_MAPS[index].second) {
        AccessMetadata(exifMetadata, key, v);
    }
    metadataAccessor->Write();
    metadataAccessor->Set(exifMetadata);
    DataBuf inputBuf;
    metadataAccessor->ReadBlob(inputBuf);
    metadataAccessor->WriteBlob(inputBuf);
}

void JpegAccessorTest(const std::string &pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(pathName);
    if (metadataAccessor == nullptr) {
        IMAGE_LOGI("%{public}s failed", __func__);
        return;
    }
    MetadataAccessorFuncTest(metadataAccessor);
    auto jpegMetadataAccessor = reinterpret_cast<JpegExifMetadataAccessor *>(metadataAccessor.get());
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

void PngAccessorTest(const std::string &pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(pathName);
    if (metadataAccessor == nullptr) {
        IMAGE_LOGI("%{public}s failed", __func__);
        return;
    }
    MetadataAccessorFuncTest(metadataAccessor);
    auto pngMetadataAccessor = reinterpret_cast<PngExifMetadataAccessor *>(metadataAccessor.get());
    pngMetadataAccessor->IsPngType();
    pngMetadataAccessor->Read();
    pngMetadataAccessor->Write();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void WebpAccessorTest(const std::string &pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(pathName);
    if (metadataAccessor == nullptr) {
        IMAGE_LOGI("%{public}s failed", __func__);
        return;
    }
    MetadataAccessorFuncTest(metadataAccessor);
    auto webpMetadataAccessor = reinterpret_cast<WebpExifMetadataAccessor *>(metadataAccessor.get());
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

void HeifAccessorTest(const std::string &pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(pathName);
    if (metadataAccessor == nullptr) {
        IMAGE_LOGI("%{public}s failed", __func__);
        return;
    }
    MetadataAccessorFuncTest(metadataAccessor);
    auto heifMetadataAccessor = reinterpret_cast<HeifExifMetadataAccessor *>(metadataAccessor.get());
    heifMetadataAccessor->Read();
    heifMetadataAccessor->Write();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void DngAccessorTest(const std::string &pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(pathName);
    if (metadataAccessor == nullptr) {
        IMAGE_LOGI("%{public}s failed", __func__);
        return;
    }
    MetadataAccessorFuncTest(metadataAccessor);
    auto dngMetadataAccessor = reinterpret_cast<DngExifMetadataAccessor *>(metadataAccessor.get());
    dngMetadataAccessor->Read();
    dngMetadataAccessor->Write();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void AccessorTest001(const uint8_t *data, size_t size)
{
    static const std::string JPEG_EXIF_PATH = "/data/local/tmp/test_exif.jpg";
    static const std::string PNG_EXIF_PATH = "/data/local/tmp/test_exif.png";
    static const std::string WEBP_EXIF_PATH = "/data/local/tmp/test_exif.webp";
    static const std::string HEIF_EXIF_PATH = "/data/local/tmp/test_exif.heic";
    static const std::string DNG_EXIF_PATH = "/data/local/tmp/test_exif.dng";
    static std::vector<string> EXIF_PATHS = {
        JPEG_EXIF_PATH, PNG_EXIF_PATH, WEBP_EXIF_PATH, HEIF_EXIF_PATH, DNG_EXIF_PATH};
    uint8_t action = FDP->ConsumeIntegral<uint8_t>() % 5;
    std::string path = EXIF_PATHS[action];
    WriteDataToFile(data, size, path);

    JpegAccessorTest(path);
    PngAccessorTest(path);
    WebpAccessorTest(path);
    HeifAccessorTest(path);
    DngAccessorTest(path);
}

void AccessorTest002(const uint8_t *data, size_t size)
{
    std::string filename = "/data/local/tmp/test_parse_exif.jpg";
    if (!WriteDataToFile(data, size, filename)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return;
    }
    BufferMetadataStream::MemoryMode mode = BufferMetadataStream::MemoryMode::Dynamic;
    std::shared_ptr<MetadataAccessor> metadataAccessor1 =
        MetadataAccessorFactory::Create(const_cast<uint8_t *>(data), size, mode);
    MetadataAccessorFuncTest(metadataAccessor1);
    std::shared_ptr<MetadataAccessor> metadataAccessor2 = MetadataAccessorFactory::Create(filename);
    MetadataAccessorFuncTest(metadataAccessor2);
}

void ExifMetadatFormatterTest()
{
    auto size = ExifMetadatFormatter::valueFormatConvertConfig_.size();
    uint8_t size_checked = (size == 0) ? 1 : size;
    uint8_t index = FDP->ConsumeIntegral<uint8_t>() % size_checked;
    auto it = ExifMetadatFormatter::valueFormatConvertConfig_.begin();
    std::advance(it, index);
    auto func = (it->second).first;
    std::string value = "";
    func(value, (it->second).second);
}
}  // namespace Media
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;

    OHOS::Media::AccessorTest001(data, size);
    OHOS::Media::AccessorTest002(data, size);
    OHOS::Media::ExifMetadatFormatterTest();
    return 0;
}
