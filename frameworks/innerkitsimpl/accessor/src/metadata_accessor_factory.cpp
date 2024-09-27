/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "buffer_metadata_stream.h"
#include "dng_exif_metadata_accessor.h"
#include "file_metadata_stream.h"
#include "image_log.h"
#include "image_type.h"
#include "heif_exif_metadata_accessor.h"
#include "jpeg_exif_metadata_accessor.h"
#include "metadata_accessor_factory.h"
#include "png_exif_metadata_accessor.h"
#include "tiff_parser.h"
#include "webp_exif_metadata_accessor.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "MetadataAccessorFactory"

namespace OHOS {
namespace Media {
const int IMAGE_HEADER_SIZE = 12;
const int WEBP_HEADER_OFFSET = 8;
const int IMAGE_HEIF_HEADER_OFFSET = 4;
const byte jpegHeader[] = { 0xff, 0xd8, 0xff };
const byte pngHeader[] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
const byte webpHeader[] = { 0x57, 0x45, 0x42, 0x50 };
const byte riffHeader[] = { 0x52, 0x49, 0x46, 0x46 };
const byte heifHeader[] = { 0x66, 0x74, 0x79, 0x70 };
const byte DNG_LITTLE_ENDIAN_HEADER[] = { 0x49, 0x49, 0x2A, 0x00 };
const byte DNG_BIG_ENDIAN_HEADER[] = { 0x4D, 0x4D, 0x00, 0x2A };
const ssize_t STREAM_READ_ERROR = -1;

std::shared_ptr<MetadataAccessor> MetadataAccessorFactory::Create(uint8_t *buffer, const uint32_t size,
                                                                  BufferMetadataStream::MemoryMode mode)
{
    DataInfo dataInfo {buffer, size};
    uint32_t error = SUCCESS;
    return Create(dataInfo, error, mode);
}

std::shared_ptr<MetadataAccessor> MetadataAccessorFactory::Create(const int fd)
{
    uint32_t error = SUCCESS;
    return Create(fd, error);
}

std::shared_ptr<MetadataAccessor> MetadataAccessorFactory::Create(const std::string &path)
{
    uint32_t error = SUCCESS;
    return Create(path, error);
}

std::shared_ptr<MetadataAccessor> MetadataAccessorFactory::Create(const DataInfo &dataInfo, uint32_t &error,
                                                                  BufferMetadataStream::MemoryMode mode,
                                                                  int originalFd,
                                                                  const std::string &originalPath)
{
    if (dataInfo.buffer == nullptr) {
        return nullptr;
    }
    std::shared_ptr<MetadataStream> stream = std::make_shared<BufferMetadataStream>(dataInfo.buffer, dataInfo.size,
                                                                                    mode, originalFd, originalPath);
    return Create(stream, error);
}

std::shared_ptr<MetadataAccessor> MetadataAccessorFactory::Create(const int fd, uint32_t &error, const int originalFd)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(fd, originalFd);
    if (!stream->Open(OpenMode::ReadWrite)) {
        IMAGE_LOGE("Failed to open the stream with file descriptor: %{public}d", fd);
        return nullptr;
    }
    return Create(stream, error);
}

std::shared_ptr<MetadataAccessor> MetadataAccessorFactory::Create(const std::string &path, uint32_t &error,
                                                                  const std::string &originalPath)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(path, originalPath);
    if (!stream->Open(OpenMode::ReadWrite)) {
        IMAGE_LOGE("Failed to open the stream with file");
        return nullptr;
    }
    return Create(stream, error);
}

std::shared_ptr<MetadataAccessor> MetadataAccessorFactory::Create(std::shared_ptr<MetadataStream> &stream,
                                                                  uint32_t &error)
{
    EncodedFormat type = GetImageType(stream, error);

    switch (type) {
        case EncodedFormat::JPEG:
            return std::make_shared<JpegExifMetadataAccessor>(stream);
        case EncodedFormat::PNG:
            return std::make_shared<PngExifMetadataAccessor>(stream);
        case EncodedFormat::WEBP:
            return std::make_shared<WebpExifMetadataAccessor>(stream);
        case EncodedFormat::HEIF:
            return std::make_shared<HeifExifMetadataAccessor>(stream);
        case EncodedFormat::DNG:
            return std::make_shared<DngExifMetadataAccessor>(stream);
        default:
            return nullptr;
    }
}

EncodedFormat MetadataAccessorFactory::GetImageType(std::shared_ptr<MetadataStream> &stream, uint32_t &error)
{
    byte buff[IMAGE_HEADER_SIZE] = {0};
    auto byteSize = static_cast<uint32_t>(sizeof(byte));
    stream->Seek(0, SeekPos::BEGIN);
    auto ret = stream->Read(buff, IMAGE_HEADER_SIZE * byteSize);
    stream->Seek(0, SeekPos::BEGIN);
    if (ret == STREAM_READ_ERROR) {
        IMAGE_LOGE("Failed to read image type from stream.");
        if (stream->IsFileChanged()) {
            error = ERR_MEDIA_MMAP_FILE_CHANGED;
        }
        return EncodedFormat::UNKNOWN;
    }

    if (memcmp(buff, jpegHeader, sizeof(jpegHeader) * byteSize) == 0) {
        return EncodedFormat::JPEG;
    }

    if (memcmp(buff, pngHeader, sizeof(pngHeader) * byteSize) == 0) {
        return EncodedFormat::PNG;
    }

    if (memcmp(buff, riffHeader, sizeof(riffHeader) * byteSize) == 0 &&
        memcmp(buff + WEBP_HEADER_OFFSET, webpHeader, sizeof(webpHeader) * byteSize) == 0) {
        return EncodedFormat::WEBP;
    }

    if (memcmp(buff + IMAGE_HEIF_HEADER_OFFSET, heifHeader, sizeof(heifHeader) * byteSize) == 0) {
        return EncodedFormat::HEIF;
    }

    if ((memcmp(buff, DNG_LITTLE_ENDIAN_HEADER, sizeof(DNG_LITTLE_ENDIAN_HEADER) * byteSize) == 0) ||
        (memcmp(buff, DNG_BIG_ENDIAN_HEADER, sizeof(DNG_BIG_ENDIAN_HEADER) * byteSize) == 0)) {
        return EncodedFormat::DNG;
    }

    return EncodedFormat::UNKNOWN;
}
} // namespace Media
} // namespace OHOS
