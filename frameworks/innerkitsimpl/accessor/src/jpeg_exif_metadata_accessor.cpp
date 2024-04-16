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

#include "jpeg_exif_metadata_accessor.h"

#include <libexif/exif-data.h>
#include <array>
#include "file_metadata_stream.h"
#include "image_log.h"
#include "media_errors.h"
#include "tiff_parser.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "JpegExifMetadataAccessor"

namespace OHOS {
namespace Media {
namespace {
using uint_8 = byte;
constexpr byte JPEG_MARKER_APP0 = 0xe0;
constexpr byte JPEG_MARKER_APP1 = 0xe1;
constexpr byte JPEG_MARKER_SOI = 0xd8;
constexpr byte JPEG_MARKER_EOI = 0xd9;
constexpr byte JPEG_MARKER_RST1 = 0xd0;
constexpr byte JPEG_MARKER_SOS = 0xda;
constexpr auto EXIF_ID = "Exif\0\0";
constexpr auto EXIF_BLOB_OFFSET = 2;
constexpr auto EXIF_ID_LENGTH = 2;
constexpr auto SEGMENT_LENGTH_SIZE = 2;
constexpr auto READ_BYTES = 2;
constexpr auto JPEG_HEADER_LENGTH = 2;
constexpr auto EXIF_ID_SIZE = 6;
constexpr auto APP1_EXIF_LENGTH = 8;
constexpr auto APP1_HEADER_LENGTH = 10;
constexpr auto MARKER_LENGTH_SIZE = 4;
constexpr auto READ_WRITE_BLOCK_SIZE = 4096;
constexpr auto READ_WRITE_BLOCK_SIZE_NUM = 32;
constexpr auto JPEG_MARKER_HEADER = 0xff;
constexpr auto JPEG_DATA_MAX_SIZE = 0xffff;
}

JpegExifMetadataAccessor::JpegExifMetadataAccessor(std::shared_ptr<MetadataStream> &stream)
    : AbstractExifMetadataAccessor(stream)
{}

JpegExifMetadataAccessor::~JpegExifMetadataAccessor() {}

uint32_t JpegExifMetadataAccessor::Read()
{
    DataBuf dataBuf;
    if (!ReadBlob(dataBuf)) {
        IMAGE_LOGD("Failed to read data buffer from image stream.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    ExifData *exifData;
    TiffParser::DecodeJpegExif(reinterpret_cast<const unsigned char *>(dataBuf.CData()), dataBuf.Size(), &exifData);
    if (exifData == nullptr) {
        IMAGE_LOGE("Failed to decode EXIF data from image stream.");
        return ERR_EXIF_DECODE_FAILED;
    }

    exifMetadata_ = std::make_shared<OHOS::Media::ExifMetadata>(exifData);

    return SUCCESS;
}

bool JpegExifMetadataAccessor::ReadBlob(DataBuf &blob) const
{
    if (!imageStream_->IsOpen()) {
        IMAGE_LOGE("Output image stream is not open.");
        return false;
    }
    imageStream_->Seek(0, SeekPos::BEGIN);

    int marker = FindNextMarker();
    if (marker == EOF) {
        IMAGE_LOGE("Failed to find marker 0xff in image stream.");
        return false;
    }

    while ((marker != JPEG_MARKER_SOS) && (marker != JPEG_MARKER_EOI)) {
        const auto [sizeBuf, size] = ReadSegmentLength(marker);

        if ((marker == JPEG_MARKER_APP1) && (size >= APP1_EXIF_LENGTH)) {
            blob.Resize(size - SEGMENT_LENGTH_SIZE);
            if (imageStream_->Read(blob.Data(), (size - SEGMENT_LENGTH_SIZE)) == -1) {
                return false;
            }
            if (blob.CmpBytes(0, EXIF_ID, EXIF_ID_SIZE) == 0) {
                return true;
            }
        }

        marker = FindNextMarker();
        if (marker == EOF) {
            IMAGE_LOGE("Failed to find marker 0xff in image stream.");
            return false;
        }
    }
    IMAGE_LOGD("Failed to find APP1 in image stream.");
    return false;
}

uint32_t JpegExifMetadataAccessor::Write()
{
    uint8_t *dataBlob = nullptr;
    uint32_t size = 0;
    if (!GetExifEncodeBlob(&dataBlob, size)) {
        IMAGE_LOGE("Failed to encode metadata. Size: %{public}u", size);
        return ERR_MEDIA_VALUE_INVALID;
    }

    uint32_t result = UpdateData(dataBlob, size);

    if (dataBlob != nullptr) {
        free(dataBlob);
        dataBlob = nullptr;
    }

    return result;
}

uint32_t JpegExifMetadataAccessor::WriteBlob(DataBuf &blob)
{
    byte *dataBlob = nullptr;
    uint32_t size = 0;
    if (!GetExifBlob(blob, &dataBlob, size)) {
        IMAGE_LOGE("Blob data is empty. Size: %{public}u", size);
        return ERR_MEDIA_VALUE_INVALID;
    }

    return UpdateData(dataBlob, size);
}

int JpegExifMetadataAccessor::FindNextMarker() const
{
    int marker = -1;
    do {
        marker = imageStream_->ReadByte();
        if (marker == EOF) {
            return marker;
        }
    } while (marker != JPEG_MARKER_HEADER);

    do {
        marker = imageStream_->ReadByte();
        if (marker == EOF) {
            return marker;
        }
    } while (marker == JPEG_MARKER_HEADER);

    return marker;
}

bool HasLength(byte marker)
{
    if ((marker >= JPEG_MARKER_RST1) && (marker <= JPEG_MARKER_EOI)) {
        return false;
    }
    return true;
}

std::pair<std::array<byte, 2>, uint16_t> JpegExifMetadataAccessor::ReadSegmentLength(uint8_t marker) const
{
    std::array<byte, READ_BYTES> buf { 0, 0 };
    uint16_t size { 0 };
    if (HasLength(marker)) {
        if (imageStream_->Read(buf.data(), buf.size()) == -1) {
            IMAGE_LOGE("Failed to read from image stream. Marker: %{public}u", marker);
            return { buf, size };
        }
        size = GetUShort(buf.data(), bigEndian);
    }
    return { buf, size };
}

DataBuf JpegExifMetadataAccessor::ReadNextSegment(byte marker)
{
    const auto [sizeBuf, size] = ReadSegmentLength(marker);
    DataBuf buf(size);
    if (size > SEGMENT_LENGTH_SIZE) {
        imageStream_->Read(buf.Data(SEGMENT_LENGTH_SIZE), (size - SEGMENT_LENGTH_SIZE));
        std::copy(sizeBuf.begin(), sizeBuf.end(), buf.Begin());
    }

    return buf;
}

bool JpegExifMetadataAccessor::GetExifEncodeBlob(uint8_t **dataBlob, uint32_t &size)
{
    if (this->Get() == nullptr) {
        IMAGE_LOGE("EXIF metadata is empty.");
        return false;
    }

    ExifData *exifData = this->Get()->GetExifData();
    TiffParser::EncodeJpegExif(dataBlob, size, exifData);

    if (dataBlob == nullptr || *dataBlob == nullptr) {
        IMAGE_LOGE("Failed to encode JPEG data.");
        return false;
    }

    return (size > 0);
}

bool JpegExifMetadataAccessor::GetExifBlob(const DataBuf &blob, uint8_t **dataBlob, uint32_t &size)
{
    if (blob.Empty()) {
        IMAGE_LOGE("EXIF blob data is empty.");
        return false;
    }

    *dataBlob = (byte *)blob.CData();
    size = blob.Size();

    return true;
}

bool JpegExifMetadataAccessor::WriteHeader(BufferMetadataStream &bufStream)
{
    byte tmpBuf[JPEG_HEADER_LENGTH];
    tmpBuf[0] = JPEG_MARKER_HEADER;
    tmpBuf[1] = JPEG_MARKER_SOI;
    if (bufStream.Write(tmpBuf, JPEG_HEADER_LENGTH) != JPEG_HEADER_LENGTH) {
        return false;
    }

    return true;
}

std::tuple<size_t, size_t> JpegExifMetadataAccessor::GetInsertPosAndMarkerAPP1()
{
    size_t markerCount = 0;
    size_t skipExifSeqNum = -1;
    size_t insertPos = 0;

    imageStream_->Seek(0, SeekPos::BEGIN);

    byte marker = static_cast<byte>(FindNextMarker());
    while ((marker != JPEG_MARKER_SOS) && (marker != JPEG_MARKER_EOI)) {
        DataBuf buf = ReadNextSegment(marker);
        if (marker == JPEG_MARKER_APP0) {
            insertPos = markerCount + 1;
        } else if ((marker == JPEG_MARKER_APP1) && (buf.Size() >= APP1_EXIF_LENGTH) &&
            (buf.CmpBytes(EXIF_BLOB_OFFSET, EXIF_ID, EXIF_ID_SIZE) == 0)) {
            skipExifSeqNum = markerCount;
        }

        marker = FindNextMarker();
        ++markerCount;
    }

    return std::make_tuple(insertPos, skipExifSeqNum);
}

bool JpegExifMetadataAccessor::WriteData(BufferMetadataStream &bufStream, uint8_t *dataBlob, uint32_t size)
{
    std::array<byte, APP1_HEADER_LENGTH> tmpBuf;
    tmpBuf[0] = JPEG_MARKER_HEADER;
    tmpBuf[1] = JPEG_MARKER_APP1;

    if (size > (JPEG_DATA_MAX_SIZE - APP1_EXIF_LENGTH)) {
        IMAGE_LOGE("JPEG EXIF size exceeds maximum limit. Size: %{public}u", size);
        return false;
    }

    ssize_t writeHeaderLength = MARKER_LENGTH_SIZE;
    ssize_t exifHeaderLength = EXIF_ID_LENGTH;

    if (memcmp((char *)dataBlob, EXIF_ID, EXIF_ID_SIZE) != 0) {
        writeHeaderLength = APP1_HEADER_LENGTH;
        exifHeaderLength = APP1_EXIF_LENGTH;
        std::copy_n(EXIF_ID, EXIF_ID_SIZE, tmpBuf.data() + MARKER_LENGTH_SIZE);
    }

    US2Data(tmpBuf.data() + EXIF_BLOB_OFFSET, static_cast<uint16_t>(size + exifHeaderLength), bigEndian);
    if (bufStream.Write(tmpBuf.data(), writeHeaderLength) != writeHeaderLength) {
        IMAGE_LOGE("Failed to write EXIF_ID to temporary stream. Expected length: %{public}zu", writeHeaderLength);
        return false;
    }

    if (bufStream.Write(dataBlob, size) != size) {
        IMAGE_LOGE("Failed to write data blob to temporary stream. Expected size: %{public}u", size);
        return false;
    }

    return true;
}

bool JpegExifMetadataAccessor::WriteSegment(BufferMetadataStream &bufStream, uint8_t marker, const DataBuf &buf)
{
    std::array<byte, SEGMENT_LENGTH_SIZE> tmpBuf;
    tmpBuf[0] = JPEG_MARKER_HEADER;
    tmpBuf[1] = marker;
    if (bufStream.Write(tmpBuf.data(), SEGMENT_LENGTH_SIZE) != SEGMENT_LENGTH_SIZE) {
        IMAGE_LOGE("Failed to write marker and segment. Marker: %{public}u", marker);
        return false;
    }
    if (bufStream.Write((byte *)buf.CData(), buf.Size()) != static_cast<int>(buf.Size())) {
        IMAGE_LOGE("Failed to write buffer. Buffer size: %{public}zu", buf.Size());
        return false;
    }

    return true;
}

bool JpegExifMetadataAccessor::WriteTail(BufferMetadataStream &bufStream)
{
    std::array<byte, SEGMENT_LENGTH_SIZE> tmpBuf;
    tmpBuf[0] = JPEG_MARKER_HEADER;
    tmpBuf[1] = JPEG_MARKER_SOS;
    if (bufStream.Write(tmpBuf.data(), SEGMENT_LENGTH_SIZE) != SEGMENT_LENGTH_SIZE) {
        IMAGE_LOGE("Failed to write the final marker. Expected length: %{public}d",
                   static_cast<int>(SEGMENT_LENGTH_SIZE));
        return false;
    }

    return true;
}

bool JpegExifMetadataAccessor::CopyRestData(BufferMetadataStream &bufStream)
{
    DataBuf buf(READ_WRITE_BLOCK_SIZE * READ_WRITE_BLOCK_SIZE_NUM);
    ssize_t readSize = imageStream_->Read(buf.Data(), buf.Size());
    while (readSize > 0) {
        if (bufStream.Write((byte *)buf.CData(), readSize) != readSize) {
            IMAGE_LOGE("Failed to write block data to temporary stream. Expected size: %{public}zd", readSize);
            return false;
        }
        readSize = imageStream_->Read(buf.Data(), buf.Size());
    }

    return true;
}

bool JpegExifMetadataAccessor::UpdateExifMetadata(BufferMetadataStream &bufStream, uint8_t *dataBlob, uint32_t size)
{
    size_t markerCount = 0;
    auto [insertPos, skipExifSeqNum] = GetInsertPosAndMarkerAPP1();

    if (!WriteHeader(bufStream)) {
        IMAGE_LOGE("Failed to write header to output image stream");
        return false;
    }

    imageStream_->Seek(0, SeekPos::BEGIN);

    byte marker = static_cast<byte>(FindNextMarker());
    while (marker != JPEG_MARKER_SOS) {
        DataBuf buf = ReadNextSegment(marker);
        if (markerCount == insertPos) {
            WriteData(bufStream, dataBlob, size);
        }

        if (marker == JPEG_MARKER_EOI) {
            break;
        }

        if ((markerCount != skipExifSeqNum) && (marker != JPEG_MARKER_SOI)) {
            WriteSegment(bufStream, marker, buf);
        } else {
            IMAGE_LOGD("Skipping existing exifApp segment number.");
        }

        marker = FindNextMarker();
        ++markerCount;
    }

    WriteTail(bufStream);

    return CopyRestData(bufStream);
}

uint32_t JpegExifMetadataAccessor::UpdateData(uint8_t *dataBlob, uint32_t size)
{
    BufferMetadataStream tmpBufStream;
    if (!tmpBufStream.Open(OpenMode::ReadWrite)) {
        IMAGE_LOGE("Failed to open temporary image stream");
        return ERR_IMAGE_SOURCE_DATA;
    }

    if (!imageStream_->IsOpen()) {
        IMAGE_LOGE("The output image stream is not open");
        return ERR_IMAGE_SOURCE_DATA;
    }

    if (!UpdateExifMetadata(tmpBufStream, dataBlob, size)) {
        IMAGE_LOGE("Failed to write to temporary image stream");
        return ERROR;
    }

    imageStream_->Seek(0, SeekPos::BEGIN);
    imageStream_->CopyFrom(tmpBufStream);

    return SUCCESS;
}
} // namespace Media
} // namespace OHOS