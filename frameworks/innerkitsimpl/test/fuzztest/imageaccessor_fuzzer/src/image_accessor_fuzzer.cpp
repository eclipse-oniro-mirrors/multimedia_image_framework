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

void JpegAccessorTest(const uint8_t *data, size_t size)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    int fd = ConvertDataToFd(data, size);
    if (fd < 0) {
        return;
    }
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(fd);
    if (!stream->Open(OpenMode::ReadWrite)) {
        IMAGE_LOGE("Failed to open the stream with file descriptor: %{public}d", fd);
        return;
    }
    if (EncodedFormat::JPEG != MetadataAccessorFactory::GetImageType(stream)) {
        return;
    }
    std::shared_ptr<JpegExifMetadataAccessor> metadataAccessor = std::make_shared<JpegExifMetadataAccessor>(stream);
    metadataAccessor->Read();
    metadataAccessor->Write();
    DataBuf inputBuf;
    metadataAccessor->WriteBlob(inputBuf);
    int marker = metadataAccessor->FindNextMarker();
    metadataAccessor->ReadSegmentLength(static_cast<uint8_t>(marker));
    metadataAccessor->ReadNextSegment(static_cast<byte>(marker));
    metadataAccessor->GetInsertPosAndMarkerAPP1();

    close(fd);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void PngAccessorTest(const uint8_t *data, size_t size)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    int fd = ConvertDataToFd(data, size, "image/png");
    if (fd < 0) {
        return;
    }
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(fd);
    if (!stream->Open(OpenMode::ReadWrite)) {
        IMAGE_LOGE("Failed to open the stream with file descriptor: %{public}d", fd);
        return;
    }
    if (EncodedFormat::PNG != MetadataAccessorFactory::GetImageType(stream)) {
        return;
    }
    std::shared_ptr<PngExifMetadataAccessor> metadataAccessor = std::make_shared<PngExifMetadataAccessor>(stream);
    metadataAccessor->IsPngType();
    metadataAccessor->Read();
    metadataAccessor->Write();

    close(fd);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void WebpAccessorTest(const uint8_t *data, size_t size)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    int fd = ConvertDataToFd(data, size, "image/webp");
    if (fd < 0) {
        return;
    }
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(fd);
    if (!stream->Open(OpenMode::ReadWrite)) {
        IMAGE_LOGE("Failed to open the stream with file descriptor: %{public}d", fd);
        return;
    }
    if (EncodedFormat::WEBP != MetadataAccessorFactory::GetImageType(stream)) {
        return;
    }

    std::shared_ptr<WebpExifMetadataAccessor> metadataAccessor = std::make_shared<WebpExifMetadataAccessor>(stream);
    metadataAccessor->Read();
    metadataAccessor->Write();
    Vp8xAndExifInfo exifFlag = Vp8xAndExifInfo::UNKNOWN;
    metadataAccessor->CheckChunkVp8x(exifFlag);
    metadataAccessor->GetImageWidthAndHeight();
    std::string strChunkId = "000";
    DataBuf chunkData = {};
    metadataAccessor->GetWidthAndHeightFormChunk(strChunkId, chunkData);

    close(fd);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void HeifAccessorTest(const uint8_t *data, size_t size)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    int fd = ConvertDataToFd(data, size, "image/heif");
    if (fd < 0) {
        return;
    }
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(fd);
    if (!stream->Open(OpenMode::ReadWrite)) {
        IMAGE_LOGE("Failed to open the stream with file descriptor: %{public}d", fd);
        return;
    }
    if (EncodedFormat::HEIF != MetadataAccessorFactory::GetImageType(stream)) {
        return;
    }

    std::shared_ptr<HeifExifMetadataAccessor> metadataAccessor = std::make_shared<HeifExifMetadataAccessor>(stream);
    metadataAccessor->Read();
    metadataAccessor->Write();

    close(fd);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void DngAccessorTest(const uint8_t *data, size_t size)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    int fd = ConvertDataToFd(data, size, "image/dng");
    if (fd < 0) {
        return;
    }
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(fd);
    if (!stream->Open(OpenMode::ReadWrite)) {
        IMAGE_LOGE("Failed to open the stream with file descriptor: %{public}d", fd);
        return;
    }
    if (EncodedFormat::DNG != MetadataAccessorFactory::GetImageType(stream)) {
        return;
    }

    std::shared_ptr<DngExifMetadataAccessor> metadataAccessor = std::make_shared<DngExifMetadataAccessor>(stream);
    metadataAccessor->Read();
    metadataAccessor->Write();

    close(fd);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void AccessorTest001(const uint8_t *data, size_t size)
{
    JpegAccessorTest(data, size);
    PngAccessorTest(data, size);
    WebpAccessorTest(data, size);
    HeifAccessorTest(data, size);
    DngAccessorTest(data, size);
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

void AccessorTest002(const uint8_t* data, size_t size)
{
    int fd = ConvertDataToFd(data, size);
    if (fd < 0) {
        return;
    }
    BufferMetadataStream::MemoryMode mode = BufferMetadataStream::MemoryMode::Dynamic;
    std::shared_ptr<MetadataAccessor> metadataAccessor1 = MetadataAccessorFactory::Create(const_cast<uint8_t*>(data),
        size, mode);
    MetadataAccessorFuncTest001(metadataAccessor1);
    std::shared_ptr<MetadataAccessor> metadataAccessor2 = MetadataAccessorFactory::Create(fd);
    MetadataAccessorFuncTest001(metadataAccessor2);
    close(fd);
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