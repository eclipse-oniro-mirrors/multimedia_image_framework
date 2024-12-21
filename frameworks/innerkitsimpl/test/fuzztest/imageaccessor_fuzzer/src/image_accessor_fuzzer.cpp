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

#include "convert_utils.h"
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

static const std::string JPEG_EXIF_PATH = "/data/local/tmp/test_exif.jpg";
static const std::string PNG_EXIF_PATH = "/data/local/tmp/test_exif.png";
static const std::string WEBP_EXIF_PATH = "/data/local/tmp/test.webp";
static const std::string HEIF_EXIF_PATH = "/data/local/tmp/test_exif.heic";
static const std::string DNG_EXIF_PATH = "/data/local/tmp/test.dng";

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
    exifMetadata->SetValue(key, "500");
    std::string value;
    exifMetadata->GetValue(key, value);
    metadataAccessor->Write();
    metadataAccessor->Set(exifMetadata);
    DataBuf inputBuf;
    metadataAccessor->ReadBlob(inputBuf);
    metadataAccessor->WriteBlob(inputBuf);
}

void JpegAccessorTest(const uint8_t *data, size_t size)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(JPEG_EXIF_PATH);
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

void PngAccessorTest(const uint8_t *data, size_t size)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(PNG_EXIF_PATH);
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

void WebpAccessorTest(const uint8_t *data, size_t size)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(WEBP_EXIF_PATH);
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

void HeifAccessorTest(const uint8_t *data, size_t size)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(HEIF_EXIF_PATH);
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

void DngAccessorTest(const uint8_t *data, size_t size)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    auto metadataAccessor = MetadataAccessorFactory::Create(DNG_EXIF_PATH);
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

void AccessorTest001(const uint8_t *data, size_t size)
{
    JpegAccessorTest(data, size);
    PngAccessorTest(data, size);
    WebpAccessorTest(data, size);
    HeifAccessorTest(data, size);
    DngAccessorTest(data, size);
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
    OHOS::Media::AccessorTest001(data, size);
    OHOS::Media::AccessorTest002(data, size);
    return 0;
}