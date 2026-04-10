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

#include "box/item_property_av1c_box.h"
#include "image_log.h"

namespace {
constexpr uint8_t BASE_BIT = 1;
constexpr uint8_t BIT_OFFSET_1 = 1;
constexpr uint8_t BIT_OFFSET_2 = 2;
constexpr uint8_t BIT_OFFSET_3 = 3;
constexpr uint8_t BIT_OFFSET_4 = 4;
constexpr uint8_t BIT_OFFSET_5 = 5;
constexpr uint8_t BIT_OFFSET_6 = 6;
constexpr uint8_t BIT_OFFSET_7 = 7;
constexpr uint64_t AV1C_BOX_FIXED_SIZE = 12;

constexpr uint8_t AND_BITS_1 = (BASE_BIT << BIT_OFFSET_1) - BIT_OFFSET_1;
constexpr uint8_t AND_BITS_2 = (BASE_BIT << BIT_OFFSET_2) - BIT_OFFSET_1;
constexpr uint8_t AND_BITS_3 = (BASE_BIT << BIT_OFFSET_3) - BIT_OFFSET_1;
constexpr uint8_t AND_BITS_4 = (BASE_BIT << BIT_OFFSET_4) - BIT_OFFSET_1;
constexpr uint8_t AND_BITS_5 = (BASE_BIT << BIT_OFFSET_5) - BIT_OFFSET_1;
constexpr uint8_t AND_BITS_7 = (BASE_BIT << BIT_OFFSET_7) - BIT_OFFSET_1;

uint8_t GetFlagValue(const uint8_t byte, const uint8_t shift, const uint8_t mask)
{
    return (byte >> shift) & mask;
}
}

namespace OHOS {
namespace ImagePlugin {
HeifPixelFormat HeifAv1CBox::GetAVIFPixelFormat()
{
    const auto &config = GetConfig();
    if (config.monochrome) {
        return HeifPixelFormat::MONOCHROME;
    } else if (config.chromaSubsamplingX != 0 && config.chromaSubsamplingY != 0) {
        return HeifPixelFormat::YUV420;
    } else if (config.chromaSubsamplingX != 0 && config.chromaSubsamplingY == 0) {
        return HeifPixelFormat::YUV422;
    } else if (config.chromaSubsamplingX == 0 && config.chromaSubsamplingY == 0) {
        return HeifPixelFormat::YUV444;
    } else {
        return HeifPixelFormat::UNDEFINED;
    }
}

AvifBitDepth HeifAv1CBox::GetBitDepth()
{
    const auto &config = GetConfig();
    if (config.twelveBit != 0) {
        return AvifBitDepth::Bit_12;
    } else if (config.highBitDepth != 0) {
        return AvifBitDepth::Bit_10;
    } else {
        return AvifBitDepth::Bit_8;
    }
}

heif_error HeifAv1CBox::ParseConfiguration(HeifStreamReader &reader)
{
    uint8_t byte = 0;
    byte = reader.Read8();
    config_.version = GetFlagValue(byte, 0, AND_BITS_7);

    byte = reader.Read8();
    config_.seqProfile = GetFlagValue(byte, BIT_OFFSET_5, AND_BITS_3);
    config_.seqLevelIdx0 = GetFlagValue(byte, 0, AND_BITS_5);

    byte = reader.Read8();
    config_.seqTier0 = GetFlagValue(byte, BIT_OFFSET_7, AND_BITS_1);
    config_.highBitDepth = GetFlagValue(byte, BIT_OFFSET_6, AND_BITS_1);
    config_.twelveBit = GetFlagValue(byte, BIT_OFFSET_5, AND_BITS_1);
    config_.monochrome = GetFlagValue(byte, BIT_OFFSET_4, AND_BITS_1);
    config_.chromaSubsamplingX = GetFlagValue(byte, BIT_OFFSET_3, AND_BITS_1);
    config_.chromaSubsamplingY = GetFlagValue(byte, BIT_OFFSET_2, AND_BITS_1);
    config_.chromaSamplePosition = GetFlagValue(byte, 0, AND_BITS_2);

    byte = reader.Read8();
    config_.initialPresentationDelayPresent = GetFlagValue(byte, BIT_OFFSET_4, AND_BITS_1);
    if (config_.initialPresentationDelayPresent) {
        config_.initialPresentationDelayPresent = GetFlagValue(byte, 0, AND_BITS_4);
    }

    return reader.GetError();
}

heif_error HeifAv1CBox::ParseConfigOBUS(HeifStreamReader &reader)
{
    CHECK_ERROR_RETURN_RET_LOG(GetBoxSize() < AV1C_BOX_FIXED_SIZE, heif_error_invalid_av1c,
        "HeifAv1CBox is invalid, HeifAv1CBox size less than 12");
    uint64_t remainingSize = GetBoxSize() - AV1C_BOX_FIXED_SIZE;
    CHECK_DEBUG_RETURN_RET_LOG(remainingSize == 0, heif_error_ok, "HeifAv1CBox configOBUS is equal to zero.");
    configOBUs_.resize(remainingSize);
    CHECK_ERROR_RETURN_RET_LOG(!reader.ReadData(configOBUs_.data(), remainingSize), heif_error_eof,
        "HeifAv1CBox read configOBUS failed.");
    return reader.GetError();
}

heif_error HeifAv1CBox::ParseContent(HeifStreamReader &reader)
{
    CHECK_ERROR_RETURN_RET_LOG(GetBoxSize() == 0, heif_error_invalid_av1c, "HeifAv1CBox is invalid.");
    auto readRet = heif_error_ok;
    readRet = ParseConfiguration(reader);
    CHECK_ERROR_RETURN_RET_LOG(readRet, readRet, "HeifAv1CBox ParseConfiguration read failed.");
    readRet = ParseConfigOBUS(reader);
    CHECK_ERROR_RETURN_RET_LOG(readRet, readRet, "HeifAv1CBox ParseConfigOBUS read failed.");
    return readRet;
}

} // namespace ImagePlugin
} // namespace OHOS
