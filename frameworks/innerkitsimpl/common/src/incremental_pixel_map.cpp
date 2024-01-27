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

#include "incremental_pixel_map.h"
#include "image_log.h"
#include "image_source.h"
#include "media_errors.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IncrementalPixelMap"

namespace OHOS {
namespace Media {

static IncrementalDecodingState ConvertImageStateToIncrementalState(ImageDecodingState imageState)
{
    switch (imageState) {
        case ImageDecodingState::UNRESOLVED: {
            return IncrementalDecodingState::UNRESOLVED;
        }
        case ImageDecodingState::BASE_INFO_ERROR: {
            return IncrementalDecodingState::BASE_INFO_ERROR;
        }
        case ImageDecodingState::BASE_INFO_PARSED: {
            return IncrementalDecodingState::BASE_INFO_PARSED;
        }
        case ImageDecodingState::IMAGE_DECODING: {
            return IncrementalDecodingState::IMAGE_DECODING;
        }
        case ImageDecodingState::IMAGE_ERROR: {
            return IncrementalDecodingState::IMAGE_ERROR;
        }
        case ImageDecodingState::PARTIAL_IMAGE: {
            return IncrementalDecodingState::PARTIAL_IMAGE;
        }
        case ImageDecodingState::IMAGE_DECODED: {
            return IncrementalDecodingState::IMAGE_DECODED;
        }
        default: {
            IMAGE_LOGE("unexpected imageState %{public}d.", imageState);
            return IncrementalDecodingState::UNRESOLVED;
        }
    }
}

IncrementalPixelMap::~IncrementalPixelMap()
{
    if (imageSource_ == nullptr) {
        return;
    }
    DetachSource();
}

IncrementalPixelMap::IncrementalPixelMap(uint32_t index, const DecodeOptions opts, ImageSource *imageSource)
    : index_(index), opts_(opts), imageSource_(imageSource)
{
    if (imageSource_ != nullptr) {
        imageSource_->RegisterListener(static_cast<PeerListener *>(this));
    }
}

uint32_t IncrementalPixelMap::PromoteDecoding(uint8_t &decodeProgress)
{
    if (imageSource_ == nullptr) {
        if (decodingStatus_.state == IncrementalDecodingState::BASE_INFO_ERROR ||
            decodingStatus_.state == IncrementalDecodingState::IMAGE_ERROR) {
            IMAGE_LOGE("promote decode failed for state %{public}d, errorDetail %{public}u.", decodingStatus_.state,
                decodingStatus_.errorDetail);
            return decodingStatus_.errorDetail;
        }
        IMAGE_LOGE("promote decode failed or terminated, image source is null.");
        return ERR_IMAGE_SOURCE_DATA;
    }
    ImageDecodingState imageState = ImageDecodingState::UNRESOLVED;
    uint32_t ret =
        imageSource_->PromoteDecoding(index_, opts_, *(static_cast<PixelMap *>(this)), imageState, decodeProgress);
    decodingStatus_.state = ConvertImageStateToIncrementalState(imageState);
    if (decodeProgress > decodingStatus_.decodingProgress) {
        decodingStatus_.decodingProgress = decodeProgress;
    }
    if (ret != SUCCESS && ret != ERR_IMAGE_SOURCE_DATA_INCOMPLETE) {
        DetachSource();
        decodingStatus_.errorDetail = ret;
        IMAGE_LOGE("promote decode failed, ret=%{public}u.", ret);
    }
    if (ret == SUCCESS) {
        DetachSource();
    }
    return ret;
}

void IncrementalPixelMap::DetachFromDecoding()
{
    if (imageSource_ == nullptr) {
        return;
    }
    DetachSource();
}

const IncrementalDecodingStatus &IncrementalPixelMap::GetDecodingStatus()
{
    return decodingStatus_;
}

void IncrementalPixelMap::OnPeerDestory()
{
    imageSource_ = nullptr;
}

void IncrementalPixelMap::DetachSource()
{
    imageSource_->DetachIncrementalDecoding(*(static_cast<PixelMap *>(this)));
    imageSource_->UnRegisterListener(this);
    imageSource_ = nullptr;
}
} // namespace Media
} // namespace OHOS
