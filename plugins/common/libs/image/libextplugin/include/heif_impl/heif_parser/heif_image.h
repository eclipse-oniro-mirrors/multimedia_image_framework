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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_IMAGE_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_IMAGE_H

#include "box/item_property_color_box.h"
#include "box/item_property_display_box.h"
#include "heif_type.h"

namespace OHOS {
namespace ImagePlugin {
class HeifImage {
public:
    explicit HeifImage(heif_item_id itemId);

    ~HeifImage();

    heif_item_id GetItemId() const;

    bool IsPrimaryImage() const;

    void SetPrimaryImage(bool flag);

    uint32_t GetOriginalWidth() const;

    uint32_t GetOriginalHeight() const;

    void SetOriginalSize(uint32_t width, uint32_t height);

    int GetRotateDegrees() const;

    void SetRotateDegrees(int degrees);

    HeifTransformMirrorDirection GetMirrorDirection() const;

    void SetMirrorDirection(HeifTransformMirrorDirection direction);

    bool IsResolutionReverse() const;

    uint32_t GetWidth() const;

    uint32_t GetHeight() const;

    int GetLumaBitNum() const;

    void SetLumaBitNum(int bitNum);

    int GetChromaBitNum() const;

    void SetChromaBitNum(int bitNum);

    HeifColorFormat GetDefaultColorFormat() const;

    void SetDefaultColorFormat(HeifColorFormat format);

    HeifPixelFormat GetDefaultPixelFormat() const;

    void SetDefaultPixelFormat(HeifPixelFormat format);

    void SetThumbnailImage(heif_item_id id);

    void AddThumbnailImage(const std::shared_ptr<HeifImage> &img);

    bool IsThumbnailImage() const;

    const std::vector<std::shared_ptr<HeifImage>> &GetThumbnailImages() const;

    bool IsAuxImage() const;

    const std::string &GetAuxImageType() const;

    std::vector<std::shared_ptr<HeifImage>> GetAuxImages() const;

    void SetAuxImage(heif_item_id id, const std::string &aux_type);

    void AddAuxImage(std::shared_ptr<HeifImage> img);

    const std::vector<std::shared_ptr<HeifMetadata>> &GetAllMetadata() const;

    void AddMetadata(std::shared_ptr<HeifMetadata> metadata);

    const std::shared_ptr<const HeifNclxColorProfile> &GetNclxColorProfile() const;

    const std::shared_ptr<const HeifRawColorProfile> &GetRawColorProfile() const;

    void SetColorProfile(const std::shared_ptr<const HeifColorProfile> &profile);
    void SetGainmapMasterImage(heif_item_id id);
    void AddGainmapImage(std::shared_ptr<HeifImage>& img);
    std::shared_ptr<HeifImage> GetGainmapImage() const;
    void SetTmapBoxId(heif_item_id id);
    void SetStaticMetadata(std::vector<uint8_t>& display, std::vector<uint8_t>& lightInfo);
    void SetUWAInfo(std::vector<uint8_t>& uwaInfo);
    void SetISOMetadata(std::vector<uint8_t>& isoMetadata);
    std::vector<uint8_t> GetDisplayInfo();
    std::vector<uint8_t> GetLightInfo();
    std::vector<uint8_t> GetUWAInfo();
    std::vector<uint8_t> GetISOMetadata();

private:
    heif_item_id itemId_ = 0;
    bool isPrimaryImage_ = false;

    uint32_t originalWidth_ = 0;
    uint32_t originalHeight_ = 0;
    int rotateDegrees_ = 0;
    HeifTransformMirrorDirection mirrorDirection_ = HeifTransformMirrorDirection::INVALID;

    HeifColorFormat defaultColorFormat_ = HeifColorFormat::UNDEDEFINED;
    HeifPixelFormat defaultPixelFormat_ = HeifPixelFormat::UNDEFINED;

    int lumaBitNum_ = -1;
    int chromaBitNum_ = -1;

    heif_item_id thumbnailMasterItemId_ = 0;
    std::vector<std::shared_ptr<HeifImage>> m_thumbnails;

    heif_item_id auxMasterItemId_ = 0;
    std::string auxType_;
    std::vector<std::shared_ptr<HeifImage>> auxImages_;

    std::vector<std::shared_ptr<HeifMetadata>> allMetadata_;

    std::shared_ptr<const HeifNclxColorProfile> nclxColorProfile_;
    std::shared_ptr<const HeifRawColorProfile> rawColorProfile_;

    heif_item_id gainmapMasterItemid_ = 0;
    std::shared_ptr<HeifImage> gainmapImage_;
    heif_item_id tmapId_;
    std::vector<uint8_t> lightInfo_;
    std::vector<uint8_t> displayInfo_;
    std::vector<uint8_t> uwaInfo_;
    std::vector<uint8_t> isoMetadata_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_IMAGE_H
