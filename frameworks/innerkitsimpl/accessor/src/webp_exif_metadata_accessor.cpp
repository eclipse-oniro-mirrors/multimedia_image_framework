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

#include "webp_exif_metadata_accessor.h"

#include <libexif/exif-data.h>

#include "file_metadata_stream.h"
#include "image_log.h"
#include "media_errors.h"
#include "tiff_parser.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "WebpExifMetadataAccessor"

namespace OHOS {
namespace Media {
namespace {
byte WEBP_PAD_ODD = 0x00;
constexpr auto WEBP_RIFF_SIZE = 4;
constexpr auto WEBP_FILE_SIZE_BUFF_SIZE = 4;
constexpr auto WEBP_CHUNK_HEAD_SIZE = 12;
constexpr auto WEBP_CHUNK_ID_SIZE = 4;
constexpr auto WEBP_CHUNK_SIZE = 4;
constexpr auto WEBP_CHUNK_VP8X_SIZE = 18;
constexpr auto WEBP_EXIF_FLAG_BIT = 0x08;
constexpr auto WEBP_BYTE_BITS = 8;
constexpr auto WEBP_BUF_SIZE = 2;
constexpr auto WEBP_CHUNK_WIDTH_OFFSET = 6;
constexpr auto WEBP_CHUNK_HEIGHT_OFFSET = 8;
constexpr auto WEBP_VP8L_WIDTH_BIT = 0x3F;
constexpr auto WEBP_VP8L_HEIGHT_BIT = 0x3FU;
constexpr auto WEBP_VP8L_HEIGHT_BIT1 = 0xFU;
constexpr auto WEBP_CHUNK_HEADER_VP8X = "VP8X";
constexpr auto WEBP_CHUNK_HEADER_VP8 = "VP8 ";
constexpr auto WEBP_CHUNK_HEADER_VP8L = "VP8L";
constexpr auto WEBP_CHUNK_HEADER_ANMF = "ANMF";
constexpr auto WEBP_CHUNK_HEADER_EXIF = "EXIF";
constexpr auto WEBP_CHUNK_OPERATE_FLAG = 0xFF;
constexpr auto WEBP_WRITE_BLOCK = 4096 * 32;
}

WebpExifMetadataAccessor::WebpExifMetadataAccessor(std::shared_ptr<MetadataStream> &stream)
    : AbstractExifMetadataAccessor(stream)
{}

WebpExifMetadataAccessor::~WebpExifMetadataAccessor() {}

uint32_t WebpExifMetadataAccessor::Read()
{
    DataBuf dataBuf;
    if (!ReadBlob(dataBuf)) {
        IMAGE_LOGD("Image stream does not have dataBuf.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    ExifData *exifData;
    TiffParser::Decode(reinterpret_cast<const unsigned char *>(dataBuf.CData()), dataBuf.Size(), &exifData);
    if (exifData == nullptr) {
        IMAGE_LOGD("Image stream does not have exifData.");
        return ERR_IMAGE_DECODE_FAILED;
    }

    exifMetadata_ = std::make_shared<OHOS::Media::ExifMetadata>(exifData);

    return SUCCESS;
}

bool WebpExifMetadataAccessor::ReadBlob(DataBuf &blob) const
{
    if (!imageStream_->IsOpen()) {
        if (!imageStream_->Open(OpenMode::ReadWrite)) {
            IMAGE_LOGE("Output image stream open failed.");
            return false;
        }
    }
    imageStream_->Seek(WEBP_CHUNK_HEAD_SIZE, SeekPos::BEGIN);

    Vp8xAndExifInfo exifFlag = Vp8xAndExifInfo::UNKNOWN;
    if (!CheckChunkVp8x(exifFlag)) {
        return false;
    }

    while (!imageStream_->IsEof()) {
        DataBuf chunkId(WEBP_CHUNK_ID_SIZE);
        if (static_cast<size_t>(imageStream_->Read(chunkId.Data(), chunkId.Size())) != chunkId.Size() ||
            imageStream_->IsEof()) {
            IMAGE_LOGE("Image stream does not find chunkid.");
            return false;
        }

        DataBuf chunkSize(WEBP_CHUNK_SIZE);
        if (static_cast<size_t>(imageStream_->Read(chunkSize.Data(), chunkSize.Size())) != chunkSize.Size() ||
            imageStream_->IsEof()) {
            IMAGE_LOGE("Image stream does not find chunk size.");
            return false;
        }
        const uint32_t size = chunkSize.ReadUInt32(0, littleEndian);
        const size_t imgSize = static_cast<size_t>(imageStream_->GetSize());
        if (size > imgSize - imageStream_->Tell()) {
            IMAGE_LOGE("Read chunk length error.");
            return false;
        }

        std::string strChunkId(reinterpret_cast<const char*>(chunkId.CData()), WEBP_CHUNK_ID_SIZE);
        if (strChunkId != WEBP_CHUNK_HEADER_EXIF) {
            imageStream_->Seek(size, SeekPos::CURRENT);
            if (size % WEBP_BUF_SIZE) {
                imageStream_->Seek(1, SeekPos::CURRENT);
            }
            continue;
        }

        blob.Resize(size);
        imageStream_->Read(blob.Data(), size);
        return true;
    }

    IMAGE_LOGE("Image stream does not find exif blob.");
    return false;
}

bool WebpExifMetadataAccessor::CheckChunkVp8x(Vp8xAndExifInfo &exifFlag) const
{
    DataBuf chunkId(WEBP_CHUNK_ID_SIZE);
    if (static_cast<size_t>(imageStream_->Read(chunkId.Data(), chunkId.Size())) != chunkId.Size() ||
        imageStream_->IsEof()) {
        IMAGE_LOGE("Image stream does not find vp8x.");
        return false;
    }

    std::string strChunkId(reinterpret_cast<const char *>(chunkId.CData()), WEBP_CHUNK_ID_SIZE);
    if (strChunkId != WEBP_CHUNK_HEADER_VP8X) {
        exifFlag = Vp8xAndExifInfo::VP8X_NOT_EXIST;
        IMAGE_LOGE("Image stream does not find vp8x.");
        return false;
    }

    byte chunkSize[WEBP_CHUNK_ID_SIZE];
    if (static_cast<size_t>(imageStream_->Read(chunkSize, WEBP_CHUNK_SIZE)) != WEBP_CHUNK_SIZE ||
        imageStream_->IsEof()) {
        IMAGE_LOGE("Image stream does not find vp8x size.");
        return false;
    }
    const uint32_t size = GetULong(chunkSize, littleEndian);

    DataBuf chunkData(size);
    if (size == 0 || chunkData.Empty()) {
        IMAGE_LOGE("Image stream does not find vp8x data.");
        return false;
    }

    if (static_cast<size_t>(imageStream_->Read(chunkData.Data(), chunkData.Size())) != chunkData.Size() ||
        imageStream_->IsEof()) {
        IMAGE_LOGE("Image stream does not find vp8x data.");
        return false;
    }

    byte reserved = chunkData.Data()[0];
    if (!(reserved & WEBP_EXIF_FLAG_BIT)) {
        exifFlag = Vp8xAndExifInfo::EXIF_NOT_EXIST;
        IMAGE_LOGD("Image stream does not have exifData.");
        return false;
    }
    exifFlag = Vp8xAndExifInfo::EXIF_EXIST;
    return true;
}

uint32_t WebpExifMetadataAccessor::Write()
{
    uint8_t *dataBlob = nullptr;
    uint32_t size = 0;
    if (!GetExifEncodeBlob(&dataBlob, size)) {
        IMAGE_LOGE("Encode Metadata failed.");
        return ERR_MEDIA_VALUE_INVALID;
    }

    uint32_t result = UpdateData(dataBlob, size);

    if (dataBlob != nullptr) {
        free(dataBlob);
        dataBlob = nullptr;
    }

    return result;
}

bool WebpExifMetadataAccessor::GetExifEncodeBlob(uint8_t **dataBlob, uint32_t &size)
{
    if (this->Get() == nullptr) {
        IMAGE_LOGE("Exif blob empty.");
        return false;
    }

    ExifData *exifData = this->Get()->GetExifData();
    TiffParser::Encode(dataBlob, size, exifData);

    if (dataBlob == nullptr || *dataBlob == nullptr) {
        IMAGE_LOGE("Encode webp data failed.");
        return false;
    }

    return (size > 0);
}

uint32_t WebpExifMetadataAccessor::WriteBlob(DataBuf &blob)
{
    byte *dataBlob = nullptr;
    uint32_t size = 0;
    if (!GetExifBlob(blob, &dataBlob, size)) {
        IMAGE_LOGE("Blob data empty.");
        return ERR_MEDIA_VALUE_INVALID;
    }

    return UpdateData(dataBlob, size);
}

bool WebpExifMetadataAccessor::GetExifBlob(const DataBuf &blob, uint8_t **dataBlob, uint32_t &size)
{
    if (blob.Empty()) {
        IMAGE_LOGE("Image exif blob data empty.");
        return false;
    }

    *dataBlob = (byte *)blob.CData();
    size = blob.Size();

    return true;
}

uint32_t WebpExifMetadataAccessor::UpdateData(uint8_t *dataBlob, uint32_t size)
{
    BufferMetadataStream tmpBufStream;
    if (!tmpBufStream.Open(OpenMode::ReadWrite)) {
        IMAGE_LOGE("Image temp stream open failed.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    if (!imageStream_->IsOpen()) {
        IMAGE_LOGE("Output image stream not open.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    if (!UpdateExifMetadata(tmpBufStream, dataBlob, size)) {
        IMAGE_LOGE("Image temp stream write failed.");
        return ERROR;
    }

    imageStream_->Seek(0, SeekPos::BEGIN);
    if (!imageStream_->CopyFrom(tmpBufStream)) {
        IMAGE_LOGE("Copy from temp stream failed");
        return ERR_MEDIA_INVALID_OPERATION;
    }
    return SUCCESS;
}

bool WebpExifMetadataAccessor::UpdateExifMetadata(BufferMetadataStream &bufStream, uint8_t *dataBlob, uint32_t size)
{
    Vp8xAndExifInfo exifFlag = Vp8xAndExifInfo::UNKNOWN;
    if (!WriteHeader(bufStream, size, exifFlag)) {
        IMAGE_LOGE("Output image stream write header failed.");
        return false;
    }

    imageStream_->Seek(WEBP_CHUNK_HEAD_SIZE, SeekPos::BEGIN);
    if (!WirteChunkVp8x(bufStream, exifFlag)) {
        IMAGE_LOGE("Output image stream write vp8x failed.");
        return false;
    }

    if (exifFlag == Vp8xAndExifInfo::VP8X_NOT_EXIST || exifFlag == Vp8xAndExifInfo::EXIF_NOT_EXIST) {
        return InsertExifMetadata(bufStream, dataBlob, size);
    }

    while (!imageStream_->IsEof()) {
        DataBuf chunkHead(WEBP_CHUNK_ID_SIZE + WEBP_CHUNK_SIZE);
        if (static_cast<size_t>(imageStream_->Read(chunkHead.Data(), chunkHead.Size())) != chunkHead.Size() ||
            imageStream_->IsEof()) {
            IMAGE_LOGE("Failed to read image chunk header information.");
            return false;
        }

        uint32_t chunkSize = chunkHead.ReadUInt32(WEBP_CHUNK_ID_SIZE, littleEndian);
        const ssize_t imgSize = imageStream_->GetSize();
        if (chunkSize > imgSize - imageStream_->Tell()) {
            IMAGE_LOGE("Read chunk length error.");
            return false;
        }

        if (chunkSize % WEBP_BUF_SIZE) {
            ++chunkSize;
        }

        DataBuf chunkData(chunkSize);
        if (static_cast<size_t>(imageStream_->Read(chunkData.Data(), chunkData.Size())) != chunkData.Size()) {
            IMAGE_LOGE("Failed to read image chunk data.");
            return false;
        }

        std::string strChunkId(reinterpret_cast<const char *>(chunkHead.CData()), WEBP_CHUNK_ID_SIZE);
        if (strChunkId == WEBP_CHUNK_HEADER_EXIF) {
            UL2Data(chunkHead.Data(WEBP_FILE_SIZE_BUFF_SIZE), size, littleEndian);
            bufStream.Write(chunkHead.Data(), chunkHead.Size());
            bufStream.Write(dataBlob, size);
            if (chunkData.Size() % WEBP_BUF_SIZE) {
                bufStream.Write(&WEBP_PAD_ODD, 1);
            }
            break;
        }

        bufStream.Write(chunkHead.Data(), chunkHead.Size());
        bufStream.Write(chunkData.Data(), chunkData.Size());
    }

    return CopyRestData(bufStream);
}

bool WebpExifMetadataAccessor::InsertExifMetadata(BufferMetadataStream &bufStream, uint8_t *dataBlob, uint32_t size)
{
    if (!CopyRestData(bufStream)) {
        return false;
    }

    static byte exifChunckId[] = { 0x45, 0x58, 0x49, 0x46 };
    if (bufStream.Write(exifChunckId, WEBP_CHUNK_ID_SIZE) != WEBP_CHUNK_ID_SIZE) {
        IMAGE_LOGE("BufStream tell: %{public}lu", bufStream.Tell());
        return false;
    }
    DataBuf exifChunckSize(WEBP_CHUNK_SIZE);
    UL2Data(exifChunckSize.Data(), size, littleEndian);
    if (bufStream.Write(exifChunckSize.Data(), exifChunckSize.Size()) != (ssize_t)exifChunckSize.Size() ||
        bufStream.Write(dataBlob, size) != size) {
        return false;
    }
    if (size % WEBP_BUF_SIZE) {
        bufStream.Write(&WEBP_PAD_ODD, 1);
    }
    return true;
}

std::tuple<uint32_t, uint32_t> WebpExifMetadataAccessor::GetImageWidthAndHeight()
{
    while (!imageStream_->IsEof()) {
        DataBuf chunkHead(WEBP_CHUNK_ID_SIZE + WEBP_CHUNK_SIZE);
        if (static_cast<size_t>(imageStream_->Read(chunkHead.Data(), chunkHead.Size())) != chunkHead.Size() ||
            imageStream_->IsEof()) {
            IMAGE_LOGE("Failed to read image chunk header information.");
            return std::make_tuple(0, 0);
        }

        const uint32_t size = chunkHead.ReadUInt32(WEBP_CHUNK_ID_SIZE, littleEndian);
        const ssize_t imgSize = imageStream_->GetSize();
        if (size > imgSize - imageStream_->Tell()) {
            IMAGE_LOGE("Read chunk length error.");
            return std::make_tuple(0, 0);
        }

        DataBuf chunkData(size);
        if (static_cast<size_t>(imageStream_->Read(chunkData.Data(), chunkData.Size())) != chunkData.Size()) {
            IMAGE_LOGE("Failed to read image chunk data.");
            return std::make_tuple(0, 0);
        }
        
        std::string strChunkId(reinterpret_cast<const char *>(chunkHead.CData()), WEBP_CHUNK_ID_SIZE);
        if (strChunkId == WEBP_CHUNK_HEADER_VP8 || strChunkId == WEBP_CHUNK_HEADER_VP8L ||
            strChunkId == WEBP_CHUNK_HEADER_ANMF) {
            return GetWidthAndHeightFormChunk(strChunkId, chunkData);
        }
    }
    return std::make_tuple(0, 0);
}

std::tuple<uint32_t, uint32_t> WebpExifMetadataAccessor::GetWidthAndHeightFormChunk(const std::string &strChunkId,
    const DataBuf &chunkData)
{
    uint32_t width = 0;
    uint32_t height = 0;
    static const uint32_t bitOperVp8 = 0x3fff;
    static const byte offset3 = 3;
    static const byte offset2 = 2;
    if (strChunkId == WEBP_CHUNK_HEADER_VP8) {
        byte sizeBuf[WEBP_BUF_SIZE];

        (void)memcpy_s(&sizeBuf, WEBP_BUF_SIZE, chunkData.CData(WEBP_CHUNK_WIDTH_OFFSET), WEBP_BUF_SIZE);
        width = GetUShort(sizeBuf, littleEndian) & bitOperVp8;
        (void)memcpy_s(&sizeBuf, WEBP_BUF_SIZE, chunkData.CData(WEBP_CHUNK_HEIGHT_OFFSET), WEBP_BUF_SIZE);
        height = GetUShort(sizeBuf, littleEndian) & bitOperVp8;
        return std::make_tuple(width, height);
    }
    
    if (strChunkId == WEBP_CHUNK_HEADER_VP8L) {
        byte bufWidth[WEBP_BUF_SIZE];
        byte bufHeight[WEBP_BUF_SIZE + 1];

        (void)memcpy_s(&bufWidth, WEBP_BUF_SIZE, chunkData.CData(1), WEBP_BUF_SIZE);
        bufWidth[1] &= WEBP_VP8L_WIDTH_BIT;
        width = GetUShort(bufWidth, littleEndian) + 1;
        (void)memcpy_s(&bufHeight, WEBP_BUF_SIZE + 1, chunkData.CData(WEBP_BUF_SIZE), WEBP_BUF_SIZE + 1);
        bufHeight[0] = ((bufHeight[0] >> WEBP_CHUNK_WIDTH_OFFSET) & offset3) |
            ((bufHeight[1] & WEBP_VP8L_HEIGHT_BIT) << offset2);
        bufHeight[1] = ((bufHeight[1] >> WEBP_CHUNK_WIDTH_OFFSET) & offset3) |
            ((bufHeight[WEBP_BUF_SIZE] & WEBP_VP8L_HEIGHT_BIT1) << offset2);
        height = GetUShort(bufHeight, littleEndian) + 1;
        return std::make_tuple(width, height);
    }

    if (strChunkId == WEBP_CHUNK_HEADER_ANMF) {
        byte sizeBuf[WEBP_CHUNK_SIZE];
        
        (void)memcpy_s(&sizeBuf, offset3, chunkData.CData(WEBP_CHUNK_WIDTH_OFFSET), offset3);
        sizeBuf[offset3] = 0;
        width = GetULong(sizeBuf, littleEndian) + 1;
        (void)memcpy_s(&sizeBuf, offset3, chunkData.CData(WEBP_CHUNK_WIDTH_OFFSET + offset3), offset3);
        sizeBuf[offset3] = 0;
        height = GetULong(sizeBuf, littleEndian) + 1;
        return std::make_tuple(width, height);
    }
    return std::make_tuple(width, height);
}

bool WebpExifMetadataAccessor::CopyRestData(BufferMetadataStream &bufStream)
{
    DataBuf buf(WEBP_WRITE_BLOCK);
    ssize_t readSize = imageStream_->Read(buf.Data(), buf.Size());
    while (readSize > 0) {
        if (bufStream.Write(buf.Data(), readSize) != readSize) {
            IMAGE_LOGE("Write block data to temp stream failed.");
            return false;
        }
        readSize = imageStream_->Read(buf.Data(), buf.Size());
    }

    return true;
}

bool WebpExifMetadataAccessor::WriteHeader(BufferMetadataStream &bufStream, uint32_t size, Vp8xAndExifInfo &exifFlag)
{
    DataBuf headInfo(WEBP_CHUNK_HEAD_SIZE);
    imageStream_->Seek(0, SeekPos::BEGIN);
    if (static_cast<size_t>(imageStream_->Read(headInfo.Data(), headInfo.Size())) != headInfo.Size() ||
        imageStream_->IsEof()) {
        return false;
    }
    uint32_t fileSize = GetULong(headInfo.Data(WEBP_RIFF_SIZE), littleEndian) + size;
    if (size % WEBP_BUF_SIZE) {
        ++fileSize;
    }

    if (!CheckChunkVp8x(exifFlag) && exifFlag == Vp8xAndExifInfo::UNKNOWN) {
        return false;
    }

    if (exifFlag == Vp8xAndExifInfo::VP8X_NOT_EXIST || exifFlag == Vp8xAndExifInfo::EXIF_NOT_EXIST) {
        fileSize += exifFlag == Vp8xAndExifInfo::VP8X_NOT_EXIST ? WEBP_CHUNK_VP8X_SIZE : 0;
        fileSize += WEBP_CHUNK_ID_SIZE + WEBP_CHUNK_SIZE;
        UL2Data(headInfo.Data(WEBP_FILE_SIZE_BUFF_SIZE), fileSize, littleEndian);
        IMAGE_LOGD("Write webp file size: %{public}u, new exif size: %{public}u", fileSize, size);
        return bufStream.Write(headInfo.Data(), headInfo.Size()) == (ssize_t)headInfo.Size();
    }

    DataBuf exifData;
    if (!ReadBlob(exifData)) {
        return false;
    }

    fileSize -= exifData.Size() % WEBP_BUF_SIZE ? (exifData.Size() + 1) : exifData.Size();
    UL2Data(headInfo.Data(WEBP_FILE_SIZE_BUFF_SIZE), fileSize, littleEndian);
    IMAGE_LOGD("Write webp file size: %{public}u, old exif size: %{public}u, new exif size: %{public}lu",
        fileSize, size, static_cast<unsigned long>(exifData.Size()));
    return bufStream.Write(headInfo.Data(), headInfo.Size()) == (ssize_t)headInfo.Size();
}

bool WebpExifMetadataAccessor::WirteChunkVp8x(BufferMetadataStream &bufStream, const Vp8xAndExifInfo &exifFlag)
{
    if (exifFlag == Vp8xAndExifInfo::VP8X_NOT_EXIST) {
        auto [width, height] = GetImageWidthAndHeight();
        imageStream_->Seek(WEBP_CHUNK_HEAD_SIZE, SeekPos::BEGIN);
        if (width <= 0 || height <= 0) {
            return false;
        }
        static byte chunckHeader[] = { 0x56, 0x50, 0x38, 0x58, 0x0a, 0x00, 0x00, 0x00, 0x08,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        size_t offset = WEBP_CHUNK_HEAD_SIZE;
        uint32_t w = width - 1;
        chunckHeader[offset] = w & WEBP_CHUNK_OPERATE_FLAG;
        chunckHeader[++offset] = (w >> WEBP_BYTE_BITS) & WEBP_CHUNK_OPERATE_FLAG;
        chunckHeader[++offset] = (w >> (WEBP_BYTE_BITS + WEBP_BYTE_BITS)) & WEBP_CHUNK_OPERATE_FLAG;

        uint32_t h = height - 1;
        chunckHeader[++offset] = h & WEBP_CHUNK_OPERATE_FLAG;
        chunckHeader[++offset] = (h >> WEBP_BYTE_BITS) & WEBP_CHUNK_OPERATE_FLAG;
        chunckHeader[++offset] = (h >> (WEBP_BYTE_BITS + WEBP_BYTE_BITS)) & WEBP_CHUNK_OPERATE_FLAG;
        return bufStream.Write(chunckHeader, WEBP_CHUNK_VP8X_SIZE) == WEBP_CHUNK_VP8X_SIZE;
    }

    DataBuf chunkHead(WEBP_CHUNK_ID_SIZE + WEBP_CHUNK_SIZE);
    if (static_cast<size_t>(imageStream_->Read(chunkHead.Data(), chunkHead.Size())) != chunkHead.Size()) {
        return false;
    }
    if (bufStream.Write(chunkHead.Data(), chunkHead.Size()) != (ssize_t)chunkHead.Size()) {
        return false;
    }

    const uint32_t size = chunkHead.ReadUInt32(WEBP_CHUNK_ID_SIZE, littleEndian);
    DataBuf chunkData(size);
    if (static_cast<size_t>(imageStream_->Read(chunkData.Data(), chunkData.Size())) != chunkData.Size()) {
        return false;
    }
    chunkData.Data()[0] |= WEBP_EXIF_FLAG_BIT;
    return bufStream.Write(chunkData.Data(), chunkData.Size()) == (ssize_t)chunkData.Size();
}
} // namespace Media
} // namespace OHOS