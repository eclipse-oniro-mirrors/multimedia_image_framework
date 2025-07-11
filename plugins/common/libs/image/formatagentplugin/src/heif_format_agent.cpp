/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "heif_format_agent.h"

#include "image_log.h"
#include "plugin_service.h"
#include "string"
#include "securec.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "HeifFormatAgent"

namespace OHOS {
namespace ImagePlugin {
using namespace MultimediaPlugin;

const std::string FORMAT_TYPE = "image/heif";
constexpr uint32_t HEADER_SIZE = 32;
constexpr uint32_t HEADER_LEAST_SIZE = 8;
constexpr size_t HEADER_NEXT_SIZE = 16;
constexpr uint32_t OFFSET_SIZE = 8;

constexpr uint32_t SHIFT_BASE = 8;
constexpr uint32_t TIMES_SEVEN = 7;
constexpr uint32_t TIMES_FIVE = 5;
constexpr uint32_t TIMES_THREE = 3;
constexpr uint32_t TIMES_TWO = 2;
constexpr uint32_t MAX_LOOP_SIZE = 5;

std::string HeifFormatAgent::GetFormatType()
{
    return FORMAT_TYPE;
}

uint32_t HeifFormatAgent::GetHeaderSize()
{
    return HEADER_SIZE;
}

bool CheckFormatHead(const void *headerData, uint32_t dataSize)
{
    if (headerData == nullptr) {
        IMAGE_LOGE("check format failed: header data is null.");
        return false;
    }
    // Any valid ftyp box should have at least 8 bytes.
    if (dataSize < HEADER_LEAST_SIZE) {
        IMAGE_LOGE("data size[%{public}u] less than eight.", dataSize);
        return false;
    }
    return true;
}

bool HeifFormatAgent::CheckFormat(const void *headerData, uint32_t dataSize)
{
    if (!CheckFormatHead(headerData, dataSize)) {
        return false;
    }
    uint32_t tmpBuff[HEADER_SIZE];
    if (memcpy_s(tmpBuff, HEADER_SIZE, headerData, dataSize) != 0) {
        IMAGE_LOGE("memcpy headerData data size:[%{public}d] error.", dataSize);
        return false;
    }

    const uint32_t *ptr = reinterpret_cast<const uint32_t *>(tmpBuff);
    uint64_t chunkSize = EndianSwap32(ptr[0]);  // first item
    uint32_t chunkType = EndianSwap32(ptr[1]);  // second item
    if (chunkType != Fourcc('f', 't', 'y', 'p')) {
        IMAGE_LOGD("head type is not ftyp.");
        return false;
    }

    int64_t offset = OFFSET_SIZE;
    bool cond = !IsHeif64(tmpBuff, dataSize, offset, chunkSize);
    CHECK_ERROR_RETURN_RET(cond, false);
    int64_t chunkDataSize = static_cast<int64_t>(chunkSize) - offset;
    // It should at least have major brand (4-byte) and minor version (4-bytes).
    // The rest of the chunk (if any) is a list of (4-byte) compatible brands.
    CHECK_ERROR_RETURN_RET_LOG(chunkDataSize < HEADER_LEAST_SIZE, false,
        "chunk data size [%{public}lld] less than eight.", static_cast<long long>(chunkDataSize));
    uint32_t numCompatibleBrands = (chunkDataSize - OFFSET_SIZE) / sizeof(uint32_t);
    if (numCompatibleBrands != 0 && numCompatibleBrands + TIMES_TWO < HEADER_SIZE) {
        for (size_t i = 0; i < numCompatibleBrands + 2; ++i) {  // need next 2 item
            if (i == 1) {
                // Skip this index, it refers to the minorVersion, not a brand.
                continue;
            }
            // When numCompatibleBrands is 4, i equals 5, and there is no heif brand, it will be read out of bounds.
            CHECK_ERROR_RETURN_RET_LOG(i == MAX_LOOP_SIZE, false,
                "check heif format failed, the number of cycles exceeded expectations");
            auto *brandPtr = static_cast<const uint32_t *>(tmpBuff) + (numCompatibleBrands + i);
            uint32_t brand = EndianSwap32(*brandPtr);
            cond = brand == Fourcc('m', 'i', 'f', '1') || brand == Fourcc('h', 'e', 'i', 'c') ||
                   brand == Fourcc('m', 's', 'f', '1') || brand == Fourcc('h', 'e', 'v', 'c');
            CHECK_ERROR_RETURN_RET(cond, true);
        }
    }
    IMAGE_LOGI("check heif format failed.");
    return false;
}

bool HeifFormatAgent::IsHeif64(const void *buffer, const size_t bytesRead, int64_t &offset, uint64_t &chunkSize)
{
    // If it is 1, a 64-bit check is required.
    if (chunkSize == 1) {
        // This indicates that the next 8 bytes represent the chunk size,
        // and chunk data comes after that.
        if (bytesRead < HEADER_NEXT_SIZE) {
            IMAGE_LOGE("bytes read [%{public}zd] less than sixteen.", bytesRead);
            return false;
        }
        auto *chunkSizePtr = static_cast<const uint64_t *>(buffer) + (offset / sizeof(uint64_t));
        chunkSize = EndianSwap64(*chunkSizePtr);
        if (chunkSize < HEADER_NEXT_SIZE) {
            // The smallest valid chunk is 16 bytes long in this case.
            IMAGE_LOGE("chunk size [%{public}llu] less than sixteen.", static_cast<unsigned long long>(chunkSize));
            return false;
        }
        offset += OFFSET_SIZE;
    } else if (chunkSize < HEADER_LEAST_SIZE) {
        // The smallest valid chunk is 8 bytes long.
        IMAGE_LOGE("chunk size [%{public}llu] less than eight.", static_cast<unsigned long long>(chunkSize));
        return false;
    }

    if (chunkSize > bytesRead) {
        chunkSize = bytesRead;
    }
    return true;
}

uint32_t HeifFormatAgent::Fourcc(uint8_t c1, uint8_t c2, uint8_t c3, uint8_t c4)
{
    return (c1 << (SHIFT_BASE * TIMES_THREE)) | (c2 << (SHIFT_BASE * TIMES_TWO)) | (c3 << SHIFT_BASE) | (c4);
}

uint32_t HeifFormatAgent::EndianSwap32(uint32_t value)
{
    return ((value & 0xFF) << (SHIFT_BASE * TIMES_THREE)) | ((value & 0xFF00) << SHIFT_BASE) |
           ((value & 0xFF0000) >> SHIFT_BASE) | (value >> (SHIFT_BASE * TIMES_THREE));
}

uint64_t HeifFormatAgent::EndianSwap64(uint64_t value)
{
    return (((value & 0x00000000000000FFULL) << (SHIFT_BASE * TIMES_SEVEN)) |
            ((value & 0x000000000000FF00ULL) << (SHIFT_BASE * TIMES_FIVE)) |
            ((value & 0x0000000000FF0000ULL) << (SHIFT_BASE * TIMES_THREE)) |
            ((value & 0x00000000FF000000ULL) << (SHIFT_BASE)) | ((value & 0x000000FF00000000ULL) >> (SHIFT_BASE)) |
            ((value & 0x0000FF0000000000ULL) >> (SHIFT_BASE * TIMES_THREE)) |
            ((value & 0x00FF000000000000ULL) >> (SHIFT_BASE * TIMES_FIVE)) | ((value) >> (SHIFT_BASE * TIMES_SEVEN)));
}
} // namespace ImagePlugin
} // namespace OHOS
