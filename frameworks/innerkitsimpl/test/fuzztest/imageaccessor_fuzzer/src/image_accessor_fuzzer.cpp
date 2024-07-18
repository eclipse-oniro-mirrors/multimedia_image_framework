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
#include "securec.h"

#include "metadata_accessor_factory.h"
#include "dng_exif_metadata_accessor.h"
#include "heif_exif_metadata_accessor.h"
#include "jpeg_exif_metadata_accessor.h"
#include "png_exif_metadata_accessor.h"
#include "webp_exif_metadata_accessor.h"

namespace OHOS {
namespace Media {
using namespace std;
const int IMAGE_HEADER_SIZE = 12;
const int WEBP_HEADER_OFFSET = 8;
const int IMAGE_HEIF_HEADER_OFFSET = 4;
const byte jpegHeader[] = { 0xff, 0xd8, 0xff };
const byte pngHeader[] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
const byte webpHeader[] = { 0x57, 0x45, 0x42, 0x50 };
const byte riffHeader[] = { 0x52, 0x49, 0x46, 0x46 };
const byte heifHeader[] = { 0x66, 0x74, 0x79, 0x70 };
const byte DNG_LITTLE_ENDIAN_HEADER[] = { 0x49, 0x49, 0x2A, 0x00 };

void JpegAccessorTest(std::shared_ptr<JpegExifMetadataAccessor>& metadataAccessor)
{
    metadataAccessor->Read();
    metadataAccessor->Write();
    DataBuf inputBuf;
    metadataAccessor->WriteBlob(inputBuf);
    int marker = metadataAccessor->FindNextMarker();
    metadataAccessor->ReadSegmentLength(static_cast<uint8_t>(marker));
    metadataAccessor->ReadNextSegment(static_cast<byte>(marker));
    metadataAccessor->GetInsertPosAndMarkerAPP1();
}

void PngAccessorTest(std::shared_ptr<PngExifMetadataAccessor>& metadataAccessor)
{
    metadataAccessor->IsPngType();
    metadataAccessor->Read();
    metadataAccessor->Write();
}

void WebpAccessorTest(std::shared_ptr<WebpExifMetadataAccessor>& metadataAccessor)
{
    metadataAccessor->Read();
    metadataAccessor->Write();
    Vp8xAndExifInfo exifFlag = Vp8xAndExifInfo::UNKNOWN;
    metadataAccessor->CheckChunkVp8x(exifFlag);
    metadataAccessor->GetImageWidthAndHeight();
    std::string strChunkId = "000";
    DataBuf chunkData = {};
    metadataAccessor->GetWidthAndHeightFormChunk(strChunkId, chunkData);
}

void HeifAccessorTest(std::shared_ptr<HeifExifMetadataAccessor>& metadataAccessor)
{
    metadataAccessor->Read();
    metadataAccessor->Write();
}

void DngAccessorTest(std::shared_ptr<DngExifMetadataAccessor>& metadataAccessor)
{
    metadataAccessor->Read();
    metadataAccessor->Write();
}

void AccessorTest(const uint8_t *data, size_t size)
{
    if (size <= IMAGE_HEADER_SIZE) {
        return;
    }
    uint8_t* data_cpy = const_cast<uint8_t*>(data);

    if (EOK != memcpy_s(data_cpy, size, jpegHeader, sizeof(jpegHeader)) == 0) {
        return;
    }
    BufferMetadataStream::MemoryMode mode = BufferMetadataStream::MemoryMode::Dynamic;
    std::shared_ptr<MetadataStream> stream = std::make_shared<BufferMetadataStream>(data_cpy, size, mode);
    if (EncodedFormat::JPEG == MetadataAccessorFactory::GetImageType(stream)) {
        std::shared_ptr<JpegExifMetadataAccessor> metadataAccessor = std::make_shared<JpegExifMetadataAccessor>(stream);
        JpegAccessorTest(metadataAccessor);
    }

    if (EOK != memcpy_s(data_cpy, size, pngHeader, sizeof(pngHeader)) == 0) {
        return;
    }
    stream = std::make_shared<BufferMetadataStream>(data_cpy, size, mode);
    if (EncodedFormat::PNG == MetadataAccessorFactory::GetImageType(stream)) {
        std::shared_ptr<PngExifMetadataAccessor> metadataAccessor = std::make_shared<PngExifMetadataAccessor>(stream);
        PngAccessorTest(metadataAccessor);
    }

    if (EOK != memcpy_s(data_cpy, size, riffHeader, sizeof(riffHeader)) == 0 &&
        EOK != memcpy_s(data_cpy + WEBP_HEADER_OFFSET, size, webpHeader, sizeof(webpHeader))) {
        return;
    }
    stream = std::make_shared<BufferMetadataStream>(data_cpy, size, mode);
    if (EncodedFormat::WEBP == MetadataAccessorFactory::GetImageType(stream)) {
        std::shared_ptr<WebpExifMetadataAccessor> metadataAccessor = std::make_shared<WebpExifMetadataAccessor>(stream);
        WebpAccessorTest(metadataAccessor);
    }

    if (EOK != memcpy_s(data_cpy + IMAGE_HEIF_HEADER_OFFSET, size, heifHeader, sizeof(heifHeader)) == 0) {
        return;
    }
    stream = std::make_shared<BufferMetadataStream>(data_cpy, size, mode);
    if (EncodedFormat::HEIF == MetadataAccessorFactory::GetImageType(stream)) {
        std::shared_ptr<HeifExifMetadataAccessor> metadataAccessor = std::make_shared<HeifExifMetadataAccessor>(stream);
        HeifAccessorTest(metadataAccessor);
    }

    if (EOK != memcpy_s(data_cpy, size, DNG_LITTLE_ENDIAN_HEADER, sizeof(DNG_LITTLE_ENDIAN_HEADER)) == 0) {
        return;
    }
    stream = std::make_shared<BufferMetadataStream>(data_cpy, size, mode);
    if (EncodedFormat::DNG == MetadataAccessorFactory::GetImageType(stream)) {
        std::shared_ptr<DngExifMetadataAccessor> metadataAccessor = std::make_shared<DngExifMetadataAccessor>(stream);
        DngAccessorTest(metadataAccessor);
    }
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

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::DataBufTest(data, size);
    OHOS::Media::AccessorTest(data, size);
    return 0;
}