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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_COLOR_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_COLOR_BOX_H

#include "box/heif_box.h"

namespace OHOS {
namespace ImagePlugin {
class HeifColorProfile {
public:
    virtual ~HeifColorProfile() = default;

    virtual uint32_t GetProfileType() const = 0;

    virtual heif_error Write(HeifStreamWriter& writer) const = 0;
};

class HeifRawColorProfile : public HeifColorProfile {
public:
    HeifRawColorProfile(uint32_t type, const std::vector<uint8_t>& data) : profileType_(type), data_(data) {}

    uint32_t GetProfileType() const override { return profileType_; }

    const std::vector<uint8_t>& GetData() const { return data_; }

    heif_error Write(HeifStreamWriter& writer) const override;

private:
    uint32_t profileType_;
    std::vector<uint8_t> data_;
};


class HeifNclxColorProfile : public HeifColorProfile {
public:
    HeifNclxColorProfile(uint16_t colorPrimaries, uint16_t transferCharacteristics,
        uint16_t matrixCoefficients, uint8_t fullRangeFlag)
        : colorPrimaries_(colorPrimaries), transferCharacteristics_(transferCharacteristics),
        matrixCoefficients_(matrixCoefficients), fullRangeFlag_(fullRangeFlag) {};

    uint32_t GetProfileType() const override { return BOX_TYPE_NCLX; }

    heif_error Write(HeifStreamWriter& writer) const override;
    uint16_t GetColorPrimaries() const { return colorPrimaries_; };
    uint16_t GetTransferCharacteristics() const { return transferCharacteristics_; };
    uint16_t GetMatrixCoefficients() const { return matrixCoefficients_; };
    uint8_t GetFullRangeFlag() const { return fullRangeFlag_; };

private:
    const static uint16_t NCLX_DATA_UNSPECIFIED = 2;
    uint16_t colorPrimaries_ = NCLX_DATA_UNSPECIFIED;
    uint16_t transferCharacteristics_ = NCLX_DATA_UNSPECIFIED;
    uint16_t matrixCoefficients_ = NCLX_DATA_UNSPECIFIED;
    uint8_t fullRangeFlag_ = 1;
};

class HeifColrBox : public HeifBox {
public:
    HeifColrBox() : HeifBox(BOX_TYPE_COLR) {}

    uint32_t GetColorProfileType() const { return colorProfile_->GetProfileType(); }

    const std::shared_ptr<const HeifColorProfile>& GetColorProfile() const { return colorProfile_; }

    void SetColorProfile(const std::shared_ptr<const HeifColorProfile>& prof) { colorProfile_ = prof; }

    heif_error Write(HeifStreamWriter& writer) const override;

protected:
    heif_error ParseContent(HeifStreamReader& reader) override;

private:
    std::shared_ptr<const HeifColorProfile> colorProfile_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_COLOR_BOX_H
