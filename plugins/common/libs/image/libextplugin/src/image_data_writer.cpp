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

#include "image_data_writer.h"

#include <algorithm>
#include <limits>
#include <vector>

#include "include/core/SkStream.h"

#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "ImageDataWriter"

namespace OHOS::ImagePlugin {
namespace {
constexpr uint32_t MAX_C2PA_DATA_SIZE_IN_BYTES = 1U << 22; // 4MB
constexpr uint32_t JPEG_SOI_SIZE = 2;
constexpr uint32_t JPEG_LENGTH_FIELD_SIZE = 2;
constexpr uint32_t JPEG_APP11_HEADER_SIZE = 4;
constexpr uint32_t JPEG_SIGNATURE_SIZE = 8;
constexpr uint32_t JPEG_MIN_SEGMENT_LENGTH = JPEG_LENGTH_FIELD_SIZE + JPEG_SIGNATURE_SIZE;
constexpr uint32_t JPEG_MAX_SEGMENT_LENGTH = 65535;
constexpr uint8_t JPEG_MARKER_PREFIX = 0xFF;
constexpr uint8_t JPEG_MARKER_APP11 = 0xEB;
constexpr uint8_t JPEG_SOI_MARKER = 0xD8;
constexpr uint8_t JPEG_ZERO_FILL = 0;
constexpr uint8_t JPEG_BYTE_SHIFT = 8;
constexpr uint8_t JPEG_BYTE_MASK = 0xFF;
constexpr uint8_t JPEG_C2PA_HINT[] = {'c', '2', 'p', 'a'};

bool WriteBytes(SkWStream &output, const void *data, size_t size)
{
    return size == 0 || output.write(data, size);
}

bool IsValidJpeg(const uint8_t *data, uint32_t size)
{
    return data != nullptr && size >= JPEG_SOI_SIZE && data[0] == JPEG_MARKER_PREFIX &&
        data[1] == JPEG_SOI_MARKER;
}

bool CalculateReserveSize(uint32_t reservedSize, uint32_t &reserveSize)
{
    if (reservedSize == 0 || reservedSize > MAX_C2PA_DATA_SIZE_IN_BYTES) {
        return false;
    }
    if (reservedSize > std::numeric_limits<uint32_t>::max() - JPEG_LENGTH_FIELD_SIZE) {
        return false;
    }
    reserveSize = reservedSize + JPEG_LENGTH_FIELD_SIZE;
    return reserveSize >= JPEG_MIN_SEGMENT_LENGTH;
}

bool WriteSegment(SkWStream &output, uint32_t segmentLength, uint32_t segmentIndex)
{
    uint8_t header[JPEG_APP11_HEADER_SIZE] = {
        JPEG_MARKER_PREFIX,
        JPEG_MARKER_APP11,
        static_cast<uint8_t>((segmentLength >> JPEG_BYTE_SHIFT) & JPEG_BYTE_MASK),
        static_cast<uint8_t>(segmentLength & JPEG_BYTE_MASK),
    };
    if (!WriteBytes(output, header, sizeof(header))) {
        return false;
    }

    uint8_t signature[JPEG_SIGNATURE_SIZE] = {
        0x4A, 0x50, 0x02, 0x11,
        0x00, 0x00, 0x00, static_cast<uint8_t>(segmentIndex),
    };
    if (!WriteBytes(output, signature, sizeof(signature))) {
        return false;
    }

    uint32_t paddingSize = segmentLength - JPEG_LENGTH_FIELD_SIZE - JPEG_SIGNATURE_SIZE;
    uint32_t hintSize = std::min(paddingSize, static_cast<uint32_t>(sizeof(JPEG_C2PA_HINT)));
    if (!WriteBytes(output, JPEG_C2PA_HINT, hintSize)) {
        return false;
    }
    uint32_t zeroSize = paddingSize - hintSize;
    if (zeroSize == 0) {
        return true;
    }
    std::vector<uint8_t> zeros(zeroSize, JPEG_ZERO_FILL);
    return WriteBytes(output, zeros.data(), zeros.size());
}
} // namespace

bool ImageDataWriter::WriteJpegC2paDataToStream(SkWStream &output, const uint8_t *jpegData, uint32_t jpegSize,
    uint32_t reservedSize)
{
    uint32_t reserveSize = 0;
    if (!IsValidJpeg(jpegData, jpegSize) || !CalculateReserveSize(reservedSize, reserveSize)) {
        IMAGE_LOGE("WriteJpegC2paDataToStream input or reserve size is invalid");
        return false;
    }
    if (!WriteBytes(output, jpegData, JPEG_SOI_SIZE)) {
        return false;
    }

    uint32_t remaining = reserveSize;
    uint32_t segmentIndex = 0;
    while (remaining >= JPEG_MIN_SEGMENT_LENGTH) {
        uint32_t segmentLength = std::min(remaining, JPEG_MAX_SEGMENT_LENGTH);
        uint32_t remainder = remaining - segmentLength;
        if (remainder > 0 && remainder < JPEG_MIN_SEGMENT_LENGTH) {
            segmentLength -= JPEG_MIN_SEGMENT_LENGTH - remainder;
        }
        if (segmentLength < JPEG_MIN_SEGMENT_LENGTH) {
            return false;
        }
        if (!WriteSegment(output, segmentLength, ++segmentIndex)) {
            return false;
        }
        remaining -= segmentLength;
    }
    if (remaining != 0 || !WriteBytes(output, jpegData + JPEG_SOI_SIZE, jpegSize - JPEG_SOI_SIZE)) {
        return false;
    }
    return true;
}
} // namespace OHOS::ImagePlugin