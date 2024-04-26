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

#include "heif_image.h"

const int ROTATE_90_DEGRESS = 90;
const int ROTATE_270_DEGRESS = 270;

namespace OHOS {
namespace ImagePlugin {
HeifImage::HeifImage(heif_item_id itemId) : itemId_(itemId) {}

HeifImage::~HeifImage()
{
    m_thumbnails.clear();
    allMetadata_.clear();
    auxImages_.clear();
    nclxColorProfile_.reset();
    rawColorProfile_.reset();
}

heif_item_id HeifImage::GetItemId() const
{
    return itemId_;
}

bool HeifImage::IsPrimaryImage() const
{
    return isPrimaryImage_;
}

void HeifImage::SetPrimaryImage(bool flag)
{
    isPrimaryImage_ = flag;
}

uint32_t HeifImage::GetOriginalWidth() const
{
    return originalWidth_;
}

uint32_t HeifImage::GetOriginalHeight() const
{
    return originalHeight_;
}

void HeifImage::SetOriginalSize(uint32_t width, uint32_t height)
{
    originalWidth_ = width;
    originalHeight_ = height;
}

int HeifImage::GetRotateDegrees() const
{
    return rotateDegrees_;
}

void HeifImage::SetRotateDegrees(int degrees)
{
    rotateDegrees_ = degrees;
}

HeifTransformMirrorDirection HeifImage::GetMirrorDirection() const
{
    return mirrorDirection_;
}

void HeifImage::SetMirrorDirection(HeifTransformMirrorDirection direction)
{
    mirrorDirection_ = direction;
}

bool HeifImage::IsResolutionReverse() const
{
    return rotateDegrees_ == ROTATE_90_DEGRESS || rotateDegrees_ == ROTATE_270_DEGRESS;
}

uint32_t HeifImage::GetWidth() const
{
    return IsResolutionReverse() ? originalHeight_ : originalWidth_;
}

uint32_t HeifImage::GetHeight() const
{
    return IsResolutionReverse() ? originalWidth_ : originalHeight_;
}

int HeifImage::GetLumaBitNum() const
{
    return lumaBitNum_;
}

void HeifImage::SetLumaBitNum(int bitNum)
{
    lumaBitNum_ = bitNum;
}

int HeifImage::GetChromaBitNum() const
{
    return chromaBitNum_;
}

void HeifImage::SetChromaBitNum(int bitNum)
{
    chromaBitNum_ = bitNum;
}

HeifColorFormat HeifImage::GetDefaultColorFormat() const
{
    return defaultColorFormat_;
}

void HeifImage::SetDefaultColorFormat(HeifColorFormat format)
{
    defaultColorFormat_ = format;
}

HeifPixelFormat HeifImage::GetDefaultPixelFormat() const
{
    return defaultPixelFormat_;
}

void HeifImage::SetDefaultPixelFormat(HeifPixelFormat format)
{
    defaultPixelFormat_ = format;
}

void HeifImage::SetThumbnailImage(heif_item_id id)
{
    thumbnailMasterItemId_ = id;
}

void HeifImage::AddThumbnailImage(const std::shared_ptr<HeifImage> &img)
{
    m_thumbnails.push_back(img);
}

bool HeifImage::IsThumbnailImage() const
{
    return thumbnailMasterItemId_ != 0;
}

const std::vector<std::shared_ptr<HeifImage>> &HeifImage::GetThumbnailImages() const
{
    return m_thumbnails;
}

bool HeifImage::IsAuxImage() const
{
    return auxMasterItemId_ != 0;
}

const std::string &HeifImage::GetAuxImageType() const
{
    return auxType_;
}

std::vector<std::shared_ptr<HeifImage>> HeifImage::GetAuxImages() const
{
    return auxImages_;
}

void HeifImage::SetAuxImage(heif_item_id id, const std::string &aux_type)
{
    auxMasterItemId_ = id;
    auxType_ = aux_type;
}

void HeifImage::AddAuxImage(std::shared_ptr<HeifImage> img)
{
    auxImages_.push_back(std::move(img));
}

const std::vector<std::shared_ptr<HeifMetadata>> &HeifImage::GetAllMetadata() const
{
    return allMetadata_;
}

void HeifImage::AddMetadata(std::shared_ptr<HeifMetadata> metadata)
{
    allMetadata_.push_back(std::move(metadata));
}

const std::shared_ptr<const HeifNclxColorProfile> &HeifImage::GetNclxColorProfile() const
{
    return nclxColorProfile_;
}

const std::shared_ptr<const HeifRawColorProfile> &HeifImage::GetRawColorProfile() const
{
    return rawColorProfile_;
}

void HeifImage::SetColorProfile(const std::shared_ptr<const HeifColorProfile> &profile)
{
    auto icc = std::dynamic_pointer_cast<const HeifRawColorProfile>(profile);
    if (icc) {
        rawColorProfile_ = std::move(icc);
    }

    auto nclx = std::dynamic_pointer_cast<const HeifNclxColorProfile>(profile);
    if (nclx) {
        nclxColorProfile_ = std::move(nclx);
    }
}

void HeifImage::SetGainmapMasterImage(heif_item_id id)
{
    gainmapMasterItemid_ = id;
}

void HeifImage::AddGainmapImage(std::shared_ptr<HeifImage>& img)
{
    gainmapImage_ = img;
}

std::shared_ptr<HeifImage> HeifImage::GetGainmapImage() const
{
    return gainmapImage_;
}

void HeifImage::SetTmapBoxId(heif_item_id id)
{
    tmapId_ = id;
}

void HeifImage::SetStaticMetadata(std::vector<uint8_t>& displayInfo, std::vector<uint8_t>& lightInfo)
{
    displayInfo_ = displayInfo;
    lightInfo_ = lightInfo;
}

void HeifImage::SetUWAInfo(std::vector<uint8_t>& uwaInfo)
{
    uwaInfo_ = uwaInfo;
}

void HeifImage::SetISOMetadata(std::vector<uint8_t>& isoMetadata)
{
    isoMetadata_ = isoMetadata;
}

std::vector<uint8_t> HeifImage::GetDisplayInfo()
{
    return displayInfo_;
}

std::vector<uint8_t> HeifImage::GetLightInfo()
{
    return lightInfo_;
}

std::vector<uint8_t> HeifImage::GetUWAInfo()
{
    return uwaInfo_;
}

std::vector<uint8_t> HeifImage::GetISOMetadata()
{
    return isoMetadata_;
}
} // namespace ImagePlugin
} // namespace OHOS
