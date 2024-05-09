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

#include <zlib.h>

#include "data_buf.h"
#include "exif_metadata.h"
#include "image_log.h"
#include "media_errors.h"
#include "metadata_stream.h"
#include "png_exif_metadata_accessor.h"
#include "png_image_chunk_utils.h"
#include "tiff_parser.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PngExifMetadataAccessor"

namespace OHOS {
namespace Media {
namespace {
constexpr auto PNG_CHUNK_DATA_MAX = 0x7fffffff;
constexpr auto PNG_CHUNK_IEND = "IEND";
constexpr auto PNG_CHUNK_IHDR = "IHDR";
constexpr auto PNG_CHUNK_TEXT = "tEXt";
constexpr auto PNG_CHUNK_ZTXT = "zTXt";
constexpr auto PNG_CHUNK_ITXT = "iTXt";
constexpr auto PNG_CHUNK_EXIF = "eXIf";
constexpr auto PNG_CHUNK_HEAD_SIZE = 8;
constexpr auto PNG_CHUNK_LENGTH_SIZE = 4;
constexpr auto PNG_CHUNK_TYPE_SIZE = 4;
constexpr auto PNG_CHUNK_CRC_SIZE = 4;
constexpr auto PNG_SIGN_SIZE = 8;
}

PngExifMetadataAccessor::PngExifMetadataAccessor(std::shared_ptr<MetadataStream> &stream)
    : AbstractExifMetadataAccessor(stream)
{}

PngExifMetadataAccessor::~PngExifMetadataAccessor() {}

bool PngExifMetadataAccessor::IsPngType() const
{
    if (imageStream_->IsEof()) {
        return false;
    }
    const int32_t len = PNG_SIGN_SIZE;
    byte buf[len];
    if (imageStream_->Read(buf, len) == -1) {
        return false;
    }
    if (imageStream_->IsEof()) {
        return false;
    }

    return !memcmp(buf, pngSignature, PNG_SIGN_SIZE);
}

ssize_t PngExifMetadataAccessor::ReadChunk(DataBuf &buffer) const
{
    return imageStream_->Read(buffer.Data(), buffer.Size());
}

bool PngExifMetadataAccessor::FindTiffFromText(const DataBuf &data, const std::string chunkType,
    DataBuf &tiffData) const
{
    PngImageChunkUtils::TextChunkType txtType;
    if (chunkType == PNG_CHUNK_TEXT) {
        txtType = PngImageChunkUtils::tEXtChunk;
    } else if (chunkType == PNG_CHUNK_ZTXT) {
        txtType = PngImageChunkUtils::zTXtChunk;
    } else if (chunkType == PNG_CHUNK_ITXT) {
        txtType = PngImageChunkUtils::iTXtChunk;
    } else {
        return false;
    }
    if (PngImageChunkUtils::ParseTextChunk(data, txtType, tiffData) != 0) {
        return false;
    }
    return true;
}

bool PngExifMetadataAccessor::ProcessExifData(DataBuf &blob, std::string chunkType, uint32_t chunkLength) const
{
    DataBuf chunkData(chunkLength);
    if (chunkLength > 0) {
        if (static_cast<size_t>(ReadChunk(chunkData)) != chunkData.Size()) {
            IMAGE_LOGE("Failed to read chunk data. Expected size: %{public}zu", chunkData.Size());
            return false;
        }
    }
    if (chunkType != PNG_CHUNK_EXIF) {
        return FindTiffFromText(chunkData, chunkType, blob);
    }
    blob = chunkData;
    return true;
}

bool PngExifMetadataAccessor::ReadBlob(DataBuf &blob) const
{
    if (!imageStream_->IsOpen()) {
        IMAGE_LOGE("The output image stream is not open");
        return false;
    }
    imageStream_->Seek(0, SeekPos::BEGIN);

    if (!IsPngType()) {
        IMAGE_LOGE("The file is not a PNG file");
        return false;
    }

    const size_t imgSize = static_cast<size_t>(imageStream_->GetSize());
    DataBuf chunkHead(PNG_CHUNK_HEAD_SIZE);

    while (!imageStream_->IsEof()) {
        if (static_cast<size_t>(ReadChunk(chunkHead)) != chunkHead.Size()) {
            IMAGE_LOGE("Failed to read chunk head. Expected size: %{public}zu", chunkHead.Size());
            return false;
        }
        uint32_t chunkLength = chunkHead.ReadUInt32(0, bigEndian);
        if (chunkLength > imgSize - imageStream_->Tell()) {
            IMAGE_LOGE("Chunk length is larger than the remaining image size");
            return false;
        }
        std::string chunkType(reinterpret_cast<const char *>(chunkHead.CData(PNG_CHUNK_LENGTH_SIZE)),
            PNG_CHUNK_TYPE_SIZE);
        if (chunkType == PNG_CHUNK_IEND) {
            return false;
        }
        if (chunkType == PNG_CHUNK_TEXT || chunkType == PNG_CHUNK_ZTXT || chunkType == PNG_CHUNK_EXIF ||
            chunkType == PNG_CHUNK_ITXT) {
            if (ProcessExifData(blob, chunkType, chunkLength)) {
                break;
            }
            chunkLength = 0;
        }
        imageStream_->Seek(chunkLength + PNG_CHUNK_CRC_SIZE, CURRENT);
        if (imageStream_->IsEof()) {
            IMAGE_LOGE("Failed to read the file");
            return false;
        }
    }
    return true;
}

uint32_t PngExifMetadataAccessor::Read()
{
    DataBuf tiffBuf;
    if (!ReadBlob(tiffBuf)) {
        IMAGE_LOGD("Failed to read the blob.");
        return ERR_IMAGE_SOURCE_DATA;
    }
    ExifData *exifData;
    size_t byteOrderPos = TiffParser::FindTiffPos(tiffBuf);
    if (byteOrderPos == std::numeric_limits<size_t>::max()) {
        IMAGE_LOGE("Cannot find TIFF byte order in Exif metadata.");
        return ERR_IMAGE_SOURCE_DATA;
    }
    TiffParser::Decode(tiffBuf.CData(), tiffBuf.Size(), &exifData);
    if (exifData == nullptr) {
        IMAGE_LOGE("Failed to decode TIFF buffer.");
        return ERR_EXIF_DECODE_FAILED;
    }

    exifMetadata_ = std::make_shared<OHOS::Media::ExifMetadata>(exifData);
    return SUCCESS;
}

bool PngExifMetadataAccessor::GetExifEncodedBlob(uint8_t **dataBlob, uint32_t &size)
{
    if (this->Get() == nullptr) {
        IMAGE_LOGE("Exif metadata empty");
        return false;
    }

    ExifData *exifData = this->Get()->GetExifData();
    TiffParser::Encode(dataBlob, size, exifData);

    if (dataBlob == nullptr || *dataBlob == nullptr) {
        IMAGE_LOGE("Encode Jpeg data failed");
        return false;
    }
    DataBuf blobBuf(*dataBlob, size);
    size_t byteOrderPos = TiffParser::FindTiffPos(blobBuf);
    if (byteOrderPos == std::numeric_limits<size_t>::max()) {
        IMAGE_LOGE("Failed to Encode Exif metadata: cannot find tiff byte order");
        return false;
    }
    return ((size > 0) && (size <= PNG_CHUNK_DATA_MAX));
}

bool PngExifMetadataAccessor::WriteData(BufferMetadataStream &bufStream, uint8_t *data, uint32_t size)
{
    if (bufStream.Write(data, size) != size) {
        IMAGE_LOGE("Write the bufStream failed");
        return false;
    }
    return true;
}

bool PngExifMetadataAccessor::WriteExifData(BufferMetadataStream &bufStream, uint8_t *dataBlob, uint32_t size,
                                            DataBuf &chunkBuf, std::string chunkType)
{
    if ((dataBlob == nullptr) || (size == 0)) {
        return false;
    }
    if (chunkType == PNG_CHUNK_EXIF) {
        return true;
    }
    if (chunkType == PNG_CHUNK_IHDR) {
        if (!WriteData(bufStream, chunkBuf.Data(), chunkBuf.Size())) {
            return false;
        }

        byte length[PNG_CHUNK_LENGTH_SIZE];
        UL2Data(length, size, bigEndian);
        uint8_t typeExif[] = "eXIf";
        uint32_t tmp = crc32(0L, Z_NULL, 0);
        tmp = crc32(tmp, typeExif, PNG_CHUNK_CRC_SIZE);
        tmp = crc32(tmp, dataBlob, size);
        byte crc[PNG_CHUNK_CRC_SIZE];
        UL2Data(crc, tmp, bigEndian);
        if (!(WriteData(bufStream, length, PNG_CHUNK_LENGTH_SIZE) &&
            WriteData(bufStream, typeExif, PNG_CHUNK_TYPE_SIZE) &&
            WriteData(bufStream, dataBlob, size) &&
            WriteData(bufStream, crc, PNG_CHUNK_CRC_SIZE))) {
            return false;
        }
    } else if (chunkType == PNG_CHUNK_TEXT || chunkType == PNG_CHUNK_ZTXT || chunkType == PNG_CHUNK_ITXT) {
        if (PngImageChunkUtils::FindExifFromTxt(chunkBuf)) {
            return true;
        }

        return WriteData(bufStream, chunkBuf.Data(), chunkBuf.Size());
    }
    return true;
}

bool PngExifMetadataAccessor::UpdateExifMetadata(BufferMetadataStream &bufStream, uint8_t *dataBlob, uint32_t size)
{
    const size_t imgSize = static_cast<size_t>(imageStream_->GetSize());
    DataBuf chunkHead(PNG_CHUNK_HEAD_SIZE);

    if (!WriteData(bufStream, pngSignature, PNG_SIGN_SIZE)) {
        return false;
    }

    while (!imageStream_->IsEof()) {
        if (static_cast<size_t>(ReadChunk(chunkHead)) != chunkHead.Size()) {
            IMAGE_LOGE("Read chunk head error.");
            return false;
        }

        uint32_t chunkLength = chunkHead.ReadUInt32(0, bigEndian);
        if (chunkLength > imgSize - imageStream_->Tell()) {
            IMAGE_LOGE("Read chunk length error.");
            return false;
        }

        DataBuf chunkBuf(PNG_CHUNK_HEAD_SIZE + chunkLength + PNG_CHUNK_CRC_SIZE);
        std::copy_n(chunkHead.Begin(), PNG_CHUNK_HEAD_SIZE, chunkBuf.Begin());

        ssize_t bufLength = imageStream_->Read(chunkBuf.Data(PNG_CHUNK_HEAD_SIZE), chunkLength + PNG_CHUNK_CRC_SIZE);
        if (bufLength != chunkLength + PNG_CHUNK_CRC_SIZE) {
            IMAGE_LOGE("Read chunk head error.");
            return false;
        }
        std::string chunkType(reinterpret_cast<const char*>(chunkHead.CData(PNG_CHUNK_LENGTH_SIZE)),
                              PNG_CHUNK_TYPE_SIZE);
        if (chunkType == PNG_CHUNK_IEND) {
            return WriteData(bufStream, chunkBuf.Data(), chunkBuf.Size());
        }
        if (chunkType == PNG_CHUNK_EXIF || chunkType == PNG_CHUNK_IHDR || chunkType == PNG_CHUNK_TEXT ||
            chunkType == PNG_CHUNK_ZTXT || chunkType == PNG_CHUNK_ITXT) {
            if (!WriteExifData(bufStream, dataBlob, size, chunkBuf, chunkType)) {
                return false;
            }
        } else {
            if (!WriteData(bufStream, chunkBuf.Data(), chunkBuf.Size())) {
                return false;
            }
        }
    }
    return false;
}

uint32_t PngExifMetadataAccessor::UpdateData(uint8_t *dataBlob, uint32_t size)
{
    BufferMetadataStream tmpBufStream;
    if (!tmpBufStream.Open(OpenMode::ReadWrite)) {
        IMAGE_LOGE("Image temp stream open failed");
        return ERR_IMAGE_SOURCE_DATA;
    }

    if (!UpdateExifMetadata(tmpBufStream, dataBlob, size)) {
        IMAGE_LOGE("Image temp stream write failed");
        return ERROR;
    }

    imageStream_->Seek(0, SeekPos::BEGIN);
    if (!imageStream_->CopyFrom(tmpBufStream)) {
        IMAGE_LOGE("Copy from temp stream failed");
        return ERR_MEDIA_INVALID_OPERATION;
    }
    return SUCCESS;
}

uint32_t PngExifMetadataAccessor::Write()
{
    uint8_t *dataBlob = nullptr;
    uint32_t size = 0;

    if (!imageStream_->IsOpen()) {
        IMAGE_LOGE("Output image stream not open");
        return ERR_IMAGE_SOURCE_DATA;
    }
    imageStream_->Seek(0, SeekPos::BEGIN);
    if (!IsPngType()) {
        IMAGE_LOGE("Is not a PNG file.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    if (!GetExifEncodedBlob(&dataBlob, size)) {
        IMAGE_LOGE("Encode Metadata failed");
        return ERR_MEDIA_VALUE_INVALID;
    }

    uint32_t result = UpdateData(dataBlob, size);

    if (dataBlob != nullptr) {
        free(dataBlob);
        dataBlob = nullptr;
    }

    return result;
}

uint32_t PngExifMetadataAccessor::WriteBlob(DataBuf &blob)
{
    byte *dataBlob = nullptr;
    uint32_t size = 0;

    imageStream_->Seek(0, SeekPos::BEGIN);
    if (!IsPngType()) {
        IMAGE_LOGE("Is not a PNG file.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    if (blob.Empty()) {
        IMAGE_LOGE("Image exif blob data empty");
        return ERR_MEDIA_VALUE_INVALID;
    }

    size_t byteOrderPos = TiffParser::FindTiffPos(blob);
    if (byteOrderPos == std::numeric_limits<size_t>::max()) {
        IMAGE_LOGE("Failed to checkout Exif metadata: cannot find tiff byte order");
        return ERR_MEDIA_VALUE_INVALID;
    }

    dataBlob = (byte *)blob.CData();
    size = blob.Size();

    return UpdateData(dataBlob, size);
}
} // namespace Media
} // namespace OHOS
