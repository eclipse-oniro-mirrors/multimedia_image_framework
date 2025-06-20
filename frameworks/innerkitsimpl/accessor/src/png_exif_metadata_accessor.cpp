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
    CHECK_ERROR_RETURN_RET(imageStream_->Read(buf, len) == -1, false);
    CHECK_ERROR_RETURN_RET(imageStream_->IsEof(), false);

    return !memcmp(buf, pngSignature, PNG_SIGN_SIZE);
}

ssize_t PngExifMetadataAccessor::ReadChunk(DataBuf &buffer) const
{
    return imageStream_->Read(buffer.Data(), buffer.Size());
}

bool PngExifMetadataAccessor::FindTiffFromText(const DataBuf &data, const std::string chunkType,
    DataBuf &tiffData)
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
    bool isCompressed;
    if (PngImageChunkUtils::ParseTextChunk(data, txtType, tiffData, isCompressed) != 0) {
        return false;
    }
    if (isCompressed) {
        isCompressed_ = isCompressed;
    }
    return true;
}

bool PngExifMetadataAccessor::ProcessExifData(DataBuf &blob, std::string chunkType, uint32_t chunkLength)
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

bool PngExifMetadataAccessor::ReadBlob(DataBuf &blob)
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
        CHECK_ERROR_RETURN_RET_LOG(static_cast<size_t>(ReadChunk(chunkHead)) != chunkHead.Size(),
            false, "Failed to read chunk head. Expected size: %{public}zu", chunkHead.Size());
        uint32_t chunkLength = chunkHead.ReadUInt32(0, bigEndian);
        CHECK_ERROR_RETURN_RET_LOG(chunkLength > imgSize - imageStream_->Tell(),
            false, "Chunk length is larger than the remaining image size");
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
        CHECK_ERROR_RETURN_RET_LOG(imageStream_->IsEof(), false, "Failed to read the file");
    }
    tiffOffset_ = imageStream_->Tell() - static_cast<long>(blob.Size());
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
    CHECK_ERROR_RETURN_RET_LOG(byteOrderPos == std::numeric_limits<size_t>::max(),
        ERR_IMAGE_SOURCE_DATA, "Cannot find TIFF byte order in Exif metadata.");

    TiffParser::Decode(tiffBuf.CData(), tiffBuf.Size(), &exifData);
    CHECK_ERROR_RETURN_RET_LOG(exifData == nullptr, ERR_EXIF_DECODE_FAILED, "Failed to decode TIFF buffer.");

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
    CHECK_ERROR_RETURN_RET_LOG(byteOrderPos == std::numeric_limits<size_t>::max(),
        false, "Failed to Encode Exif metadata: cannot find tiff byte order");
    return ((size > 0) && (size <= PNG_CHUNK_DATA_MAX));
}

bool PngExifMetadataAccessor::WriteData(BufferMetadataStream &bufStream, uint8_t *data, uint32_t size)
{
    CHECK_ERROR_RETURN_RET_LOG(bufStream.Write(data, size) != size,
        false, "Write the bufStream failed");
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
        CHECK_ERROR_RETURN_RET(!WriteData(bufStream, chunkBuf.Data(), chunkBuf.Size()), false);

        byte length[PNG_CHUNK_LENGTH_SIZE];
        UL2Data(length, size, bigEndian);
        uint8_t typeExif[] = "eXIf";
        uint32_t tmp = crc32(0L, Z_NULL, 0);
        tmp = crc32(tmp, typeExif, PNG_CHUNK_CRC_SIZE);
        tmp = crc32(tmp, dataBlob, size);
        byte crc[PNG_CHUNK_CRC_SIZE];
        UL2Data(crc, tmp, bigEndian);
        bool cond = !(WriteData(bufStream, length, PNG_CHUNK_LENGTH_SIZE) &&
                    WriteData(bufStream, typeExif, PNG_CHUNK_TYPE_SIZE) &&
                    WriteData(bufStream, dataBlob, size) &&
                    WriteData(bufStream, crc, PNG_CHUNK_CRC_SIZE));
        CHECK_ERROR_RETURN_RET(cond, false);
    } else if (chunkType == PNG_CHUNK_TEXT || chunkType == PNG_CHUNK_ZTXT || chunkType == PNG_CHUNK_ITXT) {
        CHECK_ERROR_RETURN_RET(PngImageChunkUtils::FindExifFromTxt(chunkBuf), true);

        return WriteData(bufStream, chunkBuf.Data(), chunkBuf.Size());
    }
    return true;
}

bool PngExifMetadataAccessor::UpdateExifMetadata(BufferMetadataStream &bufStream, uint8_t *dataBlob, uint32_t size)
{
    const size_t imgSize = static_cast<size_t>(imageStream_->GetSize());
    DataBuf chunkHead(PNG_CHUNK_HEAD_SIZE);

    CHECK_ERROR_RETURN_RET(!WriteData(bufStream, pngSignature, PNG_SIGN_SIZE), false);

    while (!imageStream_->IsEof()) {
        CHECK_ERROR_RETURN_RET_LOG(static_cast<size_t>(ReadChunk(chunkHead)) != chunkHead.Size(),
            false, "Read chunk head error.");

        uint32_t chunkLength = chunkHead.ReadUInt32(0, bigEndian);
        CHECK_ERROR_RETURN_RET_LOG(chunkLength > imgSize - imageStream_->Tell(), false, "Read chunk length error.");

        DataBuf chunkBuf(PNG_CHUNK_HEAD_SIZE + chunkLength + PNG_CHUNK_CRC_SIZE);
        std::copy_n(chunkHead.Begin(), PNG_CHUNK_HEAD_SIZE, chunkBuf.Begin());

        ssize_t bufLength = imageStream_->Read(chunkBuf.Data(PNG_CHUNK_HEAD_SIZE), chunkLength + PNG_CHUNK_CRC_SIZE);
        CHECK_ERROR_RETURN_RET_LOG(bufLength != chunkLength + PNG_CHUNK_CRC_SIZE, false, "Read chunk head error.");

        std::string chunkType(reinterpret_cast<const char*>(chunkHead.CData(PNG_CHUNK_LENGTH_SIZE)),
                              PNG_CHUNK_TYPE_SIZE);
        if (chunkType == PNG_CHUNK_IEND) {
            return WriteData(bufStream, chunkBuf.Data(), chunkBuf.Size());
        }
        if (chunkType == PNG_CHUNK_EXIF || chunkType == PNG_CHUNK_IHDR || chunkType == PNG_CHUNK_TEXT ||
            chunkType == PNG_CHUNK_ZTXT || chunkType == PNG_CHUNK_ITXT) {
            CHECK_ERROR_RETURN_RET(!WriteExifData(bufStream, dataBlob, size, chunkBuf, chunkType), false);
        } else {
            CHECK_ERROR_RETURN_RET(!WriteData(bufStream, chunkBuf.Data(), chunkBuf.Size()), false);
        }
    }
    return false;
}

uint32_t PngExifMetadataAccessor::UpdateData(uint8_t *dataBlob, uint32_t size)
{
    BufferMetadataStream tmpBufStream;
    CHECK_ERROR_RETURN_RET_LOG(!tmpBufStream.Open(OpenMode::ReadWrite),
        ERR_IMAGE_SOURCE_DATA, "Image temp stream open failed");

    CHECK_ERROR_RETURN_RET_LOG(!UpdateExifMetadata(tmpBufStream, dataBlob, size),
        ERROR, "Image temp stream write failed");

    imageStream_->Seek(0, SeekPos::BEGIN);
    CHECK_ERROR_RETURN_RET_LOG(!imageStream_->CopyFrom(tmpBufStream),
        ERR_MEDIA_INVALID_OPERATION, "Copy from temp stream failed");
    return SUCCESS;
}

uint32_t PngExifMetadataAccessor::Write()
{
    uint8_t *dataBlob = nullptr;
    uint32_t size = 0;

    CHECK_ERROR_RETURN_RET_LOG(!imageStream_->IsOpen(), ERR_IMAGE_SOURCE_DATA, "Output image stream not open");
    imageStream_->Seek(0, SeekPos::BEGIN);
    CHECK_ERROR_RETURN_RET_LOG(!IsPngType(), ERR_IMAGE_SOURCE_DATA, "Is not a PNG file.");

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
    CHECK_ERROR_RETURN_RET_LOG(!IsPngType(), ERR_IMAGE_SOURCE_DATA, "Is not a PNG file.");

    if (blob.Empty()) {
        IMAGE_LOGE("Image exif blob data empty");
        return ERR_MEDIA_VALUE_INVALID;
    }

    size_t byteOrderPos = TiffParser::FindTiffPos(blob);
    if (byteOrderPos == std::numeric_limits<size_t>::max()) {
        IMAGE_LOGE("Failed to checkout Exif metadata: cannot find tiff byte order");
        return ERR_MEDIA_VALUE_INVALID;
    }

    dataBlob = const_cast<byte *>(blob.CData());
    size = blob.Size();

    return UpdateData(dataBlob, size);
}

uint32_t PngExifMetadataAccessor::GetFilterArea(const std::vector<std::string> &exifKeys,
    std::vector<std::pair<uint32_t, uint32_t>> &ranges)
{
    uint32_t ret = Read();
    bool cond = ret != SUCCESS;
    CHECK_DEBUG_RETURN_RET_LOG(cond, E_NO_EXIF_TAG, "Failed to read the exif info.");
    cond = isCompressed_;
    CHECK_DEBUG_RETURN_RET_LOG(cond, E_NO_EXIF_TAG, "This png is compressed.");
    exifMetadata_->GetFilterArea(exifKeys, ranges);
    cond = ranges.empty();
    CHECK_ERROR_RETURN_RET(cond, E_NO_EXIF_TAG);
    for (auto& range : ranges) {
        range.first += static_cast<uint32_t>(GetTiffOffset());
    }
    return SUCCESS;
}
} // namespace Media
} // namespace OHOS
