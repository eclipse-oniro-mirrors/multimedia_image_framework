/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "cr3_format_agent.h"

#include "image_log.h"
#include "image_mime_type.h"
#include "plugin_service.h"
#include "securec.h"
#include "string"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "Cr3FormatAgent"

namespace OHOS {
namespace ImagePlugin {
using namespace MultimediaPlugin;

static constexpr uint32_t CR3_HEADER_SIZE = 94;
static constexpr uint32_t ATOM_SIZE_BYTE_SIZE = 4;
static constexpr uint32_t ATOM_NAME_BYTE_SIZE = 4;
static constexpr uint32_t ISO_UUID_BYTE_SIZE = 16;
static constexpr uint8_t MOVE_BITS_8 = 8;
static constexpr uint8_t MOVE_BITS_16 = 16;
static constexpr uint8_t MOVE_BITS_24 = 24;
static constexpr uint8_t BYTE_OFFSET_1 = 1;
static constexpr uint8_t BYTE_OFFSET_2 = 2;
static constexpr uint8_t BYTE_OFFSET_3 = 3;
static constexpr uint8_t UINT32_BYTE_SIZE = 4;

static constexpr uint8_t FILE_TYPE_CRX_FLAG[] = {
    'f', 't', 'y', 'p', 'c', 'r', 'x', ' '
};

static constexpr uint8_t CANON_UUID_FLAG[] = {
    0x85, 0xC0, 0xB6, 0x87, 0x82, 0x0F, 0x11, 0xE0, 0x81, 0x11, 0xF4, 0xCE, 0x46, 0x2B, 0x6A, 0x48
};

static constexpr uint8_t CANON_CR3_FLAG[] = {
    'C', 'a', 'n', 'o', 'n', 'C', 'R', '3'
};

std::string Cr3FormatAgent::GetFormatType()
{
    return Media::IMAGE_CR3_FORMAT;
}

uint32_t Cr3FormatAgent::GetHeaderSize()
{
    return CR3_HEADER_SIZE;
}

static inline uint32_t EndianReadUint32(const uint8_t* bytes, uint32_t offset, uint32_t size)
{
    CHECK_ERROR_RETURN_RET(bytes == nullptr, 0);
    CHECK_ERROR_RETURN_RET(offset + UINT32_BYTE_SIZE > size, 0);
    return (bytes[offset] << MOVE_BITS_24) | (bytes[offset + BYTE_OFFSET_1] << MOVE_BITS_16) |
        (bytes[offset + BYTE_OFFSET_2] << MOVE_BITS_8) | (bytes[offset + BYTE_OFFSET_3]);
}

bool Cr3FormatAgent::CheckFormat(const void *headerData, uint32_t dataSize)
{
    CHECK_ERROR_RETURN_RET_LOG(headerData == nullptr, false, "Cr3 header data is nullptr");
    CHECK_ERROR_RETURN_RET_LOG(dataSize < CR3_HEADER_SIZE, false,
        "Cr3 required header size: %{public}u, input size: %{public}u", CR3_HEADER_SIZE, dataSize);

    const uint8_t *u8Ptr = reinterpret_cast<const uint8_t*>(headerData);
    uint32_t offset = 0;
    uint32_t ftypSize = EndianReadUint32(u8Ptr, offset, dataSize);
    offset += ATOM_SIZE_BYTE_SIZE;
    CHECK_ERROR_RETURN_RET(offset + sizeof(FILE_TYPE_CRX_FLAG) > dataSize, false);
    // 1. Check file type "ftypcrx " at the (offset == 4) position of the file
    if (memcmp(u8Ptr + offset, FILE_TYPE_CRX_FLAG, sizeof(FILE_TYPE_CRX_FLAG)) != 0) {
        return false;
    }
    offset += (ftypSize - ATOM_SIZE_BYTE_SIZE);

    // Skip bytes: moovSize + moovName + uuidSize + uuidName
    offset += (ATOM_SIZE_BYTE_SIZE + ATOM_NAME_BYTE_SIZE + ATOM_SIZE_BYTE_SIZE + ATOM_NAME_BYTE_SIZE);
    CHECK_ERROR_RETURN_RET(offset + sizeof(CANON_UUID_FLAG) > dataSize, false);
    // 2. Check Canon uuid "85c0b687820f11e08111f4ce462b6a48" at the (offset == 40) position of the file
    if (memcmp(u8Ptr + offset, CANON_UUID_FLAG, sizeof(CANON_UUID_FLAG)) != 0) {
        return false;
    }
    offset += ISO_UUID_BYTE_SIZE;

    // Skip bytes: cncvSize + cncvName
    offset += (ATOM_SIZE_BYTE_SIZE + ATOM_NAME_BYTE_SIZE);
    CHECK_ERROR_RETURN_RET(offset + sizeof(CANON_CR3_FLAG) > dataSize, false);
    // 3. Canon compressor tag "CanonCR3" at the (offset == 64) position of the file
    if (memcmp(u8Ptr + offset, CANON_CR3_FLAG, sizeof(CANON_CR3_FLAG)) != 0) {
        return false;
    }
    return true;
}
} // namespace ImagePlugin
} // namespace OHOS
