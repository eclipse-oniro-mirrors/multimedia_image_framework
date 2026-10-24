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

#include "nine_patch_listener.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include "image_log.h"
#ifndef _WIN32
#include "securec.h"
#else
#include "memory.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "NinePatchListener"

namespace OHOS {
namespace ImagePlugin {

namespace {
const std::string CHUNK_NAME = "npTc";
constexpr float FLOAT_NEAR_ZERO = (1.0f / (1 << 12));
constexpr float FHALF = 0.5f;
constexpr float NO_SCALE = 1.0f;

// divs must be non-negative and strictly increasing, otherwise nine-patch consumers
// (ArkUI drawing) index outside the image.
bool ValidateDivs(const int32_t *divs, uint8_t count)
{
    if (count == 0) {
        return true;
    }
    if (divs == nullptr) {
        return false;
    }
    for (uint8_t i = 0; i < count; i++) {
        if (divs[i] < 0) {
            return false;
        }
        if (i > 0 && divs[i] <= divs[i - 1]) {
            return false;
        }
    }
    return true;
}
} // namespace

static void ScaleDivRange(int32_t *divs, int32_t count, float scale, int32_t maxValue)
{
    if (divs == nullptr || count <= 0) {
        return;
    }
    if (maxValue < 0) {
        maxValue = 0;
    }
    for (int i = 0; i < count; i++) {
        // Clamp before converting so even an oversized scaled value cannot overflow int32_t.
        double scaled = static_cast<double>(divs[i]) * scale + FHALF;
        scaled = std::max(0.0, std::min(scaled, static_cast<double>(maxValue)));
        divs[i] = static_cast<int32_t>(scaled);
        if (i > 0 && divs[i] <= divs[i - 1]) {
            divs[i] = (divs[i - 1] < maxValue) ? (divs[i - 1] + 1) : divs[i - 1];
        }
    }

    // Forward adjustment can reach the upper bound; move preceding divs back to keep space.
    for (int i = count - 2; i >= 0; i--) {
        if (divs[i] >= divs[i + 1]) {
            divs[i] = std::max(0, divs[i + 1] - 1);
        }
    }
}

bool NinePatchListener::ReadChunk(const std::string &tag, void *data, size_t length)
{
    if (tag == CHUNK_NAME && length >= sizeof(PngNinePatchRes)) {
        if (data == nullptr) {
            IMAGE_LOGE("data is null");
            return false;
        }
        PngNinePatchRes *patch = static_cast<PngNinePatchRes *>(data);
        size_t patchSize = patch->SerializedSize();
        if (length != patchSize) {
            IMAGE_LOGE("length(%{public}zu) not equals patchSize(%{public}zu)", length, patchSize);
            return false;
        }
        // copy the data because it is owned by the png reader
        PngNinePatchRes *patchNew = static_cast<PngNinePatchRes *>(malloc(patchSize));
        if (patchNew == nullptr) {
            IMAGE_LOGE("malloc failed");
            return false;
        }
        errno_t err = memcpy_s(patchNew, patchSize, patch, patchSize);
        if (err != EOK) {
            IMAGE_LOGE("memcpy failed. errno:%{public}d", err);
            free(patchNew);
            patchNew = nullptr;
            return false;
        }
        PngNinePatchRes::Deserialize(patchNew);
        patchNew->FileToDevice();
        // reject semantically invalid chunks instead of forwarding them to nine-patch consumers
        bool validPatch = (patchNew->paddingLeft >= 0) && (patchNew->paddingRight >= 0) &&
            (patchNew->paddingTop >= 0) && (patchNew->paddingBottom >= 0) &&
            ValidateDivs(patchNew->GetXDivs(), patchNew->numXDivs) &&
            ValidateDivs(patchNew->GetYDivs(), patchNew->numYDivs);
        if (!validPatch) {
            IMAGE_LOGE("npTc chunk content is invalid, drop it.");
            free(patchNew);
            patchNew = nullptr;
            return false;
        }
        if (patch_ != nullptr) {
            free(patch_);
        }
        patch_ = patchNew;
        patchSize_ = patchSize;
    }

    return true;
}

void NinePatchListener::Scale(float scaleX, float scaleY, int32_t scaledWidth, int32_t scaledHeight)
{
    if (patch_ == nullptr) {
        IMAGE_LOGE("patch is null");
        return;
    }

    if (fabsf(scaleX - NO_SCALE) > FLOAT_NEAR_ZERO) {
        patch_->paddingLeft = static_cast<int32_t>(patch_->paddingLeft * scaleX + FHALF);
        patch_->paddingRight = static_cast<int32_t>(patch_->paddingRight * scaleX + FHALF);
        ScaleDivRange(patch_->GetXDivs(), patch_->numXDivs, scaleX, scaledWidth - 1);
    }

    if (fabsf(scaleY - NO_SCALE) > FLOAT_NEAR_ZERO) {
        patch_->paddingTop = static_cast<int32_t>(patch_->paddingTop * scaleY + FHALF);
        patch_->paddingBottom = static_cast<int32_t>(patch_->paddingBottom * scaleY + FHALF);
        ScaleDivRange(patch_->GetYDivs(), patch_->numYDivs, scaleY, scaledHeight - 1);
    }
}
} // namespace ImagePlugin
} // namespace OHOS
