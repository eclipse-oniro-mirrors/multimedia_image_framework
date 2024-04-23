/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "box/item_property_color_box.h"

namespace {
    const uint8_t FILL_RANGE_FLAG_SHIFT = 7;
}

namespace OHOS {
namespace ImagePlugin {
heif_error HeifColrBox::ParseContent(HeifStreamReader& reader)
{
    uint32_t colorType = reader.Read32();
    if (colorType == COLOR_TYPE_PROF || colorType == COLOR_TYPE_RICC) {
        uint64_t profileDataSize = GetBoxSize() - GetHeaderSize() - UINT32_BYTES_NUM;
        if (!reader.CheckSize(profileDataSize)) {
            return heif_error_eof;
        }

        std::vector<uint8_t> rawData(profileDataSize);
        reader.ReadData(rawData.data(), profileDataSize);
        colorProfile_ = std::make_shared<HeifRawColorProfile>(colorType, rawData);
    } else if (colorType == BOX_TYPE_NCLX) {
        if (!reader.CheckSize(UINT16_BYTES_NUM + UINT16_BYTES_NUM + UINT16_BYTES_NUM + UINT8_BYTES_NUM)) {
            return heif_error_eof;
        }

        uint16_t colorPrimaries = reader.Read16();
        uint16_t transferCharacteristics = reader.Read16();
        uint16_t matrixCoefficients = reader.Read16();
        uint8_t fullRangeFlag = (reader.Read8() & 0x80) >> FILL_RANGE_FLAG_SHIFT;
        colorProfile_ = std::make_shared<HeifNclxColorProfile>(colorPrimaries, transferCharacteristics,
            matrixCoefficients, fullRangeFlag);
    } else {
        return heif_error_invalid_color_profile;
    }
    return reader.GetError();
}

heif_error HeifNclxColorProfile::Write(HeifStreamWriter& writer) const
{
    writer.Write16(colorPrimaries_);
    writer.Write16(transferCharacteristics_);
    writer.Write16(matrixCoefficients_);
    writer.Write8((fullRangeFlag_ & 0x01) << FILL_RANGE_FLAG_SHIFT);
    return heif_error_ok;
}

heif_error HeifRawColorProfile::Write(HeifStreamWriter& writer) const
{
    writer.Write(data_);
    return heif_error_ok;
}

heif_error HeifColrBox::Write(HeifStreamWriter& writer) const
{
    size_t boxStart = ReserveHeader(writer);

    writer.Write32(colorProfile_->GetProfileType());
    heif_error err = colorProfile_->Write(writer);
    if (err) {
        return err;
    }

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}
} // namespace ImagePlugin
} // namespace OHOS
