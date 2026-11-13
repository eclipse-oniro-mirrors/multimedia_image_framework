/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#if !defined(CROSS_PLATFORM) && !defined(_WIN32) && !defined(_APPLE)

#include "metadata_accessor_factory.h"

#include <cstring>

#include "cr3_parser.h"
#include "dng/dng_sdk_helper.h"
#include "image_log.h"
#include "media_errors.h"
#include "raw_preview_piex_stream.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "RawPreviewOrientation"

namespace OHOS {
namespace Media {
namespace {
constexpr uint16_t EXIF_ORIENTATION_TAG = 0x0112;
constexpr uint16_t EXIF_SUB_IFD_TAG = 0x8769;
constexpr uint16_t EXIF_TYPE_SHORT = 3;
constexpr uint16_t EXIF_TYPE_LONG = 4;
constexpr uint16_t EXIF_TIFF_MAGIC = 42;
constexpr uint16_t ORIENTATION_MIN = 1;
constexpr uint16_t ORIENTATION_MAX = 8;
constexpr size_t EXIF_TIFF_HEADER_SIZE = 8;
constexpr size_t EXIF_IFD_ENTRY_SIZE = 12;
constexpr size_t EXIF_VALUE_FIELD_OFFSET = 8;
constexpr size_t EXIF_APP1_HEADER_SIZE = 6;
constexpr size_t JPEG_SEGMENT_LENGTH_SIZE = 2;
constexpr size_t JPEG_SEGMENT_HEADER_SIZE = 4;
constexpr uint8_t JPEG_MARKER_PREFIX = 0xFF;
constexpr uint8_t JPEG_MARKER_TEM = 0x01;
constexpr uint8_t JPEG_MARKER_SOI = 0xD8;
constexpr uint8_t JPEG_MARKER_EOI = 0xD9;
constexpr uint8_t JPEG_MARKER_SOS = 0xDA;
constexpr uint8_t JPEG_MARKER_APP1 = 0xE1;
constexpr uint8_t JPEG_MARKER_RST_FIRST = 0xD0;
constexpr uint8_t JPEG_MARKER_RST_LAST = 0xD7;
constexpr size_t MAX_JPEG_SEGMENTS = 1024;
constexpr size_t CR3_HEADER_SIZE = 12;
constexpr size_t CR3_BRAND_OFFSET = 4;
constexpr size_t BYTE_INDEX_2 = 2;
constexpr size_t BYTE_INDEX_3 = 3;
constexpr size_t BYTE_INDEX_4 = 4;
constexpr uint32_t BYTE_SHIFT_8 = 8;
constexpr uint32_t BYTE_SHIFT_16 = 16;
constexpr uint32_t BYTE_SHIFT_24 = 24;
constexpr size_t EXIF_TIFF_MAGIC_OFFSET = 2;
constexpr size_t EXIF_TIFF_IFD_OFFSET = 4;
constexpr size_t JPEG_SOI_SIZE = 2;
constexpr char CR3_BRAND[] = "ftypcrx ";
const char ORIENTATION_EXIF_KEY[] = "Orientation";

const char *GetOrientationName(int64_t orientation)
{
    static const char *const orientationNames[] = {
        "Top-left",
        "Top-right",
        "Bottom-right",
        "Bottom-left",
        "Left-top",
        "Right-top",
        "Right-bottom",
        "Left-bottom",
    };
    if (orientation < ORIENTATION_MIN || orientation > ORIENTATION_MAX) {
        return nullptr;
    }
    return orientationNames[orientation - 1];
}

struct RawPreviewInfo {
    uint64_t offset = 0;
    uint32_t length = 0;
    bool isDng = false;
};

bool ReadUint16(const uint8_t *buffer, size_t size, size_t offset, bool bigEndian, uint16_t &value)
{
    if (buffer == nullptr || offset > size || sizeof(uint16_t) > size - offset) {
        return false;
    }
    if (bigEndian) {
        value = static_cast<uint16_t>((static_cast<uint16_t>(buffer[offset]) << BYTE_SHIFT_8) | buffer[offset + 1]);
    } else {
        value = static_cast<uint16_t>((static_cast<uint16_t>(buffer[offset + 1]) << BYTE_SHIFT_8) | buffer[offset]);
    }
    return true;
}

bool ReadUint32(const uint8_t *buffer, size_t size, size_t offset, bool bigEndian, uint32_t &value)
{
    if (buffer == nullptr || offset > size || sizeof(uint32_t) > size - offset) {
        return false;
    }
    if (bigEndian) {
        value = (static_cast<uint32_t>(buffer[offset]) << BYTE_SHIFT_24) |
            (static_cast<uint32_t>(buffer[offset + 1]) << BYTE_SHIFT_16) |
            (static_cast<uint32_t>(buffer[offset + BYTE_INDEX_2]) << BYTE_SHIFT_8) |
            buffer[offset + BYTE_INDEX_3];
    } else {
        value = (static_cast<uint32_t>(buffer[offset + BYTE_INDEX_3]) << BYTE_SHIFT_24) |
            (static_cast<uint32_t>(buffer[offset + BYTE_INDEX_2]) << BYTE_SHIFT_16) |
            (static_cast<uint32_t>(buffer[offset + 1]) << BYTE_SHIFT_8) | buffer[offset];
    }
    return true;
}

struct IfdEntry {
    uint16_t tag = 0;
    uint16_t type = 0;
    uint32_t count = 0;
    size_t offset = 0;
};

bool ReadIfdEntry(const uint8_t *buffer, size_t size, size_t entryOffset, bool bigEndian, IfdEntry &entry)
{
    entry.offset = entryOffset;
    return ReadUint16(buffer, size, entryOffset, bigEndian, entry.tag) &&
        ReadUint16(buffer, size, entryOffset + BYTE_INDEX_2, bigEndian, entry.type) &&
        ReadUint32(buffer, size, entryOffset + BYTE_INDEX_4, bigEndian, entry.count);
}

bool ReadIfdOrientation(const uint8_t *buffer, size_t size, bool bigEndian,
    const IfdEntry &entry, uint16_t &orientation)
{
    if (entry.count != 1 || (entry.type != EXIF_TYPE_SHORT && entry.type != EXIF_TYPE_LONG)) {
        return false;
    }
    size_t valueOffset = entry.offset + EXIF_VALUE_FIELD_OFFSET;
    uint32_t value = 0;
    if (entry.type == EXIF_TYPE_SHORT) {
        uint16_t shortValue = 0;
        if (!ReadUint16(buffer, size, valueOffset, bigEndian, shortValue)) {
            return false;
        }
        value = shortValue;
    } else if (!ReadUint32(buffer, size, valueOffset, bigEndian, value)) {
        return false;
    }
    if (value < ORIENTATION_MIN || value > ORIENTATION_MAX) {
        return false;
    }
    orientation = static_cast<uint16_t>(value);
    return true;
}

// Reads only the Orientation entry of one preview EXIF IFD. The Exif SubIFD offset is
// collected so an Orientation stored there can still be read without exposing other tags.
uint16_t ReadOrientationFromIfd(const uint8_t *buffer, size_t size, uint32_t ifdOffset, bool bigEndian,
    uint32_t &subIfdOffset)
{
    subIfdOffset = 0;
    if (ifdOffset < EXIF_TIFF_HEADER_SIZE || ifdOffset > size - sizeof(uint16_t)) {
        return 0;
    }
    uint16_t entryCount = 0;
    if (!ReadUint16(buffer, size, ifdOffset, bigEndian, entryCount)) {
        return 0;
    }
    size_t entriesStart = static_cast<size_t>(ifdOffset) + sizeof(uint16_t);
    if (entryCount > (size - entriesStart) / EXIF_IFD_ENTRY_SIZE) {
        return 0;
    }
    for (uint16_t i = 0; i < entryCount; ++i) {
        size_t entryOffset = entriesStart + static_cast<size_t>(i) * EXIF_IFD_ENTRY_SIZE;
        IfdEntry entry;
        if (!ReadIfdEntry(buffer, size, entryOffset, bigEndian, entry)) {
            return 0;
        }
        if (entry.tag == EXIF_ORIENTATION_TAG) {
            uint16_t orientation = 0;
            if (!ReadIfdOrientation(buffer, size, bigEndian, entry, orientation)) {
                return 0;
            }
            return orientation;
        }
        if (entry.tag == EXIF_SUB_IFD_TAG && entry.type == EXIF_TYPE_LONG && entry.count == 1) {
            uint32_t offset = 0;
            if (ReadUint32(buffer, size, entry.offset + EXIF_VALUE_FIELD_OFFSET, bigEndian, offset)) {
                subIfdOffset = offset;
            }
        }
    }
    return 0;
}

// Reads only the Orientation entry of the preview JPEG's EXIF IFD0, with a one-level
// fallback to the Exif SubIFD. No other tag is decoded.
uint16_t ParseExifOrientation(const uint8_t *buffer, size_t size)
{
    if (buffer == nullptr || size < EXIF_TIFF_HEADER_SIZE) {
        return 0;
    }
    bool bigEndian = false;
    if (buffer[0] == 0x49 && buffer[1] == 0x49) {
        bigEndian = false;
    } else if (buffer[0] == 0x4D && buffer[1] == 0x4D) {
        bigEndian = true;
    } else {
        return 0;
    }
    uint16_t magic = 0;
    uint32_t ifdOffset = 0;
    if (!ReadUint16(buffer, size, EXIF_TIFF_MAGIC_OFFSET, bigEndian, magic) || magic != EXIF_TIFF_MAGIC ||
        !ReadUint32(buffer, size, EXIF_TIFF_IFD_OFFSET, bigEndian, ifdOffset)) {
        return 0;
    }
    uint32_t subIfdOffset = 0;
    uint16_t orientation = ReadOrientationFromIfd(buffer, size, ifdOffset, bigEndian, subIfdOffset);
    if (orientation != 0 || subIfdOffset == 0 || subIfdOffset == ifdOffset) {
        return orientation;
    }
    uint32_t ignoredSubIfdOffset = 0;
    return ReadOrientationFromIfd(buffer, size, subIfdOffset, bigEndian, ignoredSubIfdOffset);
}

bool IsStandaloneJpegMarker(uint8_t marker)
{
    return marker == JPEG_MARKER_TEM || marker == JPEG_MARKER_SOI ||
        (marker >= JPEG_MARKER_RST_FIRST && marker <= JPEG_MARKER_RST_LAST);
}

bool ReadJpegSegmentLength(const uint8_t *buffer, size_t size, size_t markerPos, uint16_t &segmentLength)
{
    if (markerPos + 1 + JPEG_SEGMENT_LENGTH_SIZE > size) {
        return false;
    }
    segmentLength = static_cast<uint16_t>((static_cast<uint16_t>(buffer[markerPos + 1]) << BYTE_SHIFT_8) |
        buffer[markerPos + BYTE_INDEX_2]);
    return segmentLength >= JPEG_SEGMENT_LENGTH_SIZE && segmentLength <= size - markerPos - 1;
}

bool ParseExifApp1(const uint8_t *payload, size_t payloadSize, uint16_t &orientation)
{
    if (payloadSize < EXIF_APP1_HEADER_SIZE || std::memcmp(payload, "Exif\0\0", EXIF_APP1_HEADER_SIZE) != 0) {
        return false;
    }
    orientation = ParseExifOrientation(payload + EXIF_APP1_HEADER_SIZE, payloadSize - EXIF_APP1_HEADER_SIZE);
    return true;
}

// Locates the EXIF APP1 segment of a JPEG preview and extracts its Orientation.
uint16_t ParsePreviewJpegOrientation(const uint8_t *buffer, size_t size)
{
    if (buffer == nullptr || size < JPEG_SEGMENT_HEADER_SIZE ||
        buffer[0] != JPEG_MARKER_PREFIX || buffer[1] != JPEG_MARKER_SOI ||
        buffer[JPEG_SOI_SIZE] != JPEG_MARKER_PREFIX) {
        return 0;
    }
    size_t pos = JPEG_SOI_SIZE;
    for (size_t segment = 0; segment < MAX_JPEG_SEGMENTS && pos < size; ++segment) {
        if (buffer[pos] != JPEG_MARKER_PREFIX) {
            return 0;
        }
        size_t markerPos = pos + 1;
        while (markerPos < size && buffer[markerPos] == JPEG_MARKER_PREFIX) {
            ++markerPos;
        }
        if (markerPos >= size) {
            return 0;
        }
        uint8_t marker = buffer[markerPos];
        if (IsStandaloneJpegMarker(marker)) {
            pos = markerPos + 1;
            continue;
        }
        if (marker == JPEG_MARKER_EOI || marker == JPEG_MARKER_SOS) {
            return 0;
        }
        uint16_t segmentLength = 0;
        if (!ReadJpegSegmentLength(buffer, size, markerPos, segmentLength)) {
            return 0;
        }
        const uint8_t *payload = buffer + markerPos + 1 + JPEG_SEGMENT_LENGTH_SIZE;
        size_t payloadSize = segmentLength - JPEG_SEGMENT_LENGTH_SIZE;
        uint16_t orientation = 0;
        if (marker == JPEG_MARKER_APP1 && ParseExifApp1(payload, payloadSize, orientation)) {
            return orientation;
        }
        pos = markerPos + 1 + segmentLength;
    }
    return 0;
}

uint32_t GetCr3PreviewInfo(const std::shared_ptr<MetadataStream> &stream, RawPreviewInfo &info)
{
    ssize_t size = stream->GetSize();
    byte *data = stream->GetAddr();
    bool cond = data == nullptr || size <= 0 || stream->IsFileSizeChanged();
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_SOURCE_DATA, "Invalid CR3 source buffer.");
    std::shared_ptr<ImagePlugin::Cr3Parser> parser;
    auto result = ImagePlugin::Cr3Parser::MakeFromMemory(data, static_cast<size_t>(size), false, parser);
    cond = result != ImagePlugin::heif_error_ok || parser == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT, "Parse CR3 boxes failed.");
    auto preview = parser->GetPreviewImageInfo();
    cond = preview.size == 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT, "CR3 has no preview image.");
    info.offset = preview.fileOffset;
    info.length = preview.size;
    return SUCCESS;
}

uint32_t GetRawPreviewInfo(const std::shared_ptr<MetadataStream> &stream, RawPreviewInfo &info)
{
    RawPreviewPiexStream piexStream(*stream);
    uint8_t header[CR3_HEADER_SIZE] = {};
    if (piexStream.GetData(0, sizeof(header), header) != piex::kOk) {
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    if (std::memcmp(header + CR3_BRAND_OFFSET, CR3_BRAND, sizeof(CR3_BRAND) - 1) == 0) {
        return GetCr3PreviewInfo(stream, info);
    }
    if (!piex::IsRaw(&piexStream)) {
        return ERR_IMAGE_UNKNOWN_FORMAT;
    }
    piex::PreviewImageData previewData {};
    piex::image_type_recognition::RawImageTypes type = piex::image_type_recognition::kNonRawImage;
    piex::Error error = piex::GetPreviewImageData(&piexStream, &previewData, &type);
    if (type == piex::image_type_recognition::kDngImage) {
        // DNG previews are usually stored as a PreviewImage IFD without JPEG EXIF. The
        // existing DNG preview-first lookup below is reused instead of parsing the JPEG.
        info.isDng = true;
        return SUCCESS;
    }
    bool cond = error != piex::kOk || previewData.preview.format != piex::Image::kJpegCompressed ||
        previewData.preview.length == 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT, "RAW has no JPEG preview image.");
    info.offset = previewData.preview.offset;
    info.length = previewData.preview.length;
    return SUCCESS;
}

uint32_t GetDngPreviewOrientation(const std::shared_ptr<MetadataStream> &source, std::string &orientation)
{
    // Scans DNG preview IFDs only (sfPreviewImage / sfAltPreviewImage, including preview
    // IFDs stored in the chained IFD list). It never falls back to the main image, EXIF,
    // shared metadata or non-preview IFDs, and does not depend on the libexif container
    // parse used by the generic DNG metadata path.
    std::shared_ptr<MetadataStream> stream = source;
    std::unique_ptr<DngSdkInfo> info = DngSdkHelper::ParseInfoFromStream(stream);
    CHECK_ERROR_RETURN_RET_LOG(info == nullptr, ERR_IMAGE_DECODE_EXIF_UNSUPPORT,
        "DNG preview metadata is unavailable.");
    MetadataValue value;
    value.key = ORIENTATION_EXIF_KEY;
    uint32_t ret = DngSdkHelper::GetPreviewOrientation(info, value);
    bool cond = ret != SUCCESS || value.type != PropertyValueType::INT || value.intArrayValue.empty();
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT,
        "DNG preview has no valid Orientation, ret:%{public}u.", ret);
    int64_t dngOrientation = value.intArrayValue[0];
    cond = dngOrientation < ORIENTATION_MIN || dngOrientation > ORIENTATION_MAX;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT,
        "DNG preview Orientation is invalid.");
    const char *orientationName = GetOrientationName(dngOrientation);
    CHECK_ERROR_RETURN_RET_LOG(orientationName == nullptr, ERR_IMAGE_DECODE_EXIF_UNSUPPORT,
        "DNG preview Orientation name is invalid.");
    orientation = orientationName;
    return SUCCESS;
}
} // namespace

uint32_t MetadataAccessorFactory::GetRawPreviewOrientation(const DataInfo &dataInfo, std::string &orientation,
    int originalFd, const std::string &originalPath)
{
    orientation.clear();
    bool cond = dataInfo.buffer == nullptr || dataInfo.size == 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_SOURCE_DATA, "Invalid RAW data.");
    std::shared_ptr<MetadataStream> stream = std::make_shared<BufferMetadataStream>(dataInfo.buffer, dataInfo.size,
        BufferMetadataStream::Fix, originalFd, originalPath);
    CHECK_ERROR_RETURN_RET_LOG(stream == nullptr, ERR_IMAGE_SOURCE_DATA, "Create RAW metadata stream failed.");
    if (stream->IsFileSizeChanged()) {
        return ERR_MEDIA_MMAP_FILE_CHANGED;
    }
    RawPreviewInfo info;
    uint32_t ret = GetRawPreviewInfo(stream, info);
    if (stream->IsFileSizeChanged()) {
        return ERR_MEDIA_MMAP_FILE_CHANGED;
    }
    if (ret != SUCCESS) {
        return ret;
    }
    if (info.isDng) {
        uint32_t dngRet = GetDngPreviewOrientation(stream, orientation);
        if (stream->IsFileSizeChanged()) {
            return ERR_MEDIA_MMAP_FILE_CHANGED;
        }
        return dngRet;
    }
    ssize_t streamSize = stream->GetSize();
    cond = streamSize <= 0 || info.offset > static_cast<uint64_t>(streamSize) || info.length == 0 ||
        info.length > static_cast<uint64_t>(streamSize) - info.offset;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT, "RAW preview range is invalid.");
    byte *data = stream->GetAddr();
    CHECK_ERROR_RETURN_RET_LOG(data == nullptr, ERR_IMAGE_SOURCE_DATA, "RAW preview data is null.");
    uint16_t previewOrientation = ParsePreviewJpegOrientation(data + info.offset, info.length);
    if (stream->IsFileSizeChanged()) {
        return ERR_MEDIA_MMAP_FILE_CHANGED;
    }
    cond = previewOrientation < ORIENTATION_MIN || previewOrientation > ORIENTATION_MAX;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT,
        "RAW preview image has no valid Orientation.");
    const char *orientationName = GetOrientationName(previewOrientation);
    CHECK_ERROR_RETURN_RET_LOG(orientationName == nullptr, ERR_IMAGE_DECODE_EXIF_UNSUPPORT,
        "RAW preview Orientation name is invalid.");
    orientation = orientationName;
    return SUCCESS;
}
} // namespace Media
} // namespace OHOS

#endif
