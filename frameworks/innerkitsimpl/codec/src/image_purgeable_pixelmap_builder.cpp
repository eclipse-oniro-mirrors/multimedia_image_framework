/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef IMAGE_PURGEABLE_PIXELMAP

#include "image_purgeable_pixelmap_builder.h"

#include <cstdint>
#include <utility>

#include "image_log.h"
#include "image_trace.h"
#include "image_utils.h"
#include "media_errors.h"
#include "pixel_map_utils.h"
#include "securec.h"

namespace OHOS {
namespace Media {

DecodeRebuilder::DecodeRebuilder(std::unique_ptr<ImageSource> backupImageSource, uint32_t index,
    const DecodeOptions &options)
    : backupImageSource_(std::move(backupImageSource)), index_(index), options_(options)
{
    // Rebuild must allocate a temporary PixelMap and must not recursively attach purgeable metadata.
    options_.reusePixelmap = nullptr;
    options_.purgeableMode = PurgeableMode::NONE;
}

bool DecodeRebuilder::Rebuild(std::shared_ptr<PixelMap> &temporaryPixelmap)
{
    if (backupImageSource_ == nullptr) {
        return false;
    }
    uint32_t errorCode = SUCCESS;
    auto rebuilt = backupImageSource_->CreatePixelMapEx(index_, options_, errorCode);
    if (rebuilt == nullptr || errorCode != SUCCESS) {
        IMAGE_LOGE("PurgeablePixelMapBuilder decode failed: %{public}u", errorCode);
        return false;
    }
    temporaryPixelmap = std::move(rebuilt);
    return true;
}

PurgeablePixelMapBuilder::PurgeablePixelMapBuilder(std::shared_ptr<PixelMapRebuildState> state, PixelMap &pixelMap)
    : state_(std::move(state)), pixelMap_(pixelMap)
{}

namespace {
bool IsSameYuvLayout(const YUVDataInfo &left, const YUVDataInfo &right)
{
    return left.imageSize.width == right.imageSize.width && left.imageSize.height == right.imageSize.height &&
        left.yWidth == right.yWidth && left.yHeight == right.yHeight && left.uvWidth == right.uvWidth &&
        left.uvHeight == right.uvHeight && left.yStride == right.yStride && left.uStride == right.uStride &&
        left.vStride == right.vStride && left.uvStride == right.uvStride && left.yOffset == right.yOffset &&
        left.uOffset == right.uOffset && left.vOffset == right.vOffset && left.uvOffset == right.uvOffset;
}

bool IsSameTransform(const TransformData &left, const TransformData &right)
{
    return left.scaleX == right.scaleX && left.scaleY == right.scaleY && left.rotateD == right.rotateD &&
        left.cropLeft == right.cropLeft && left.cropTop == right.cropTop && left.cropWidth == right.cropWidth &&
        left.cropHeight == right.cropHeight && left.translateX == right.translateX &&
        left.translateY == right.translateY && left.flipX == right.flipX && left.flipY == right.flipY;
}
} // namespace

bool PurgeablePixelMapBuilder::Build(void *data, size_t size)
{
    ImageTrace imageTrace("PurgeablePixelMapBuilder::Build, size:%zu", size);
    if (data == nullptr || state_ == nullptr) {
        IMAGE_LOGE("PurgeablePixelMapBuilder received invalid rebuild parameters");
        return false;
    }
    if (PixelMapRebuildScope::IsRebuilding(&pixelMap_)) {
        IMAGE_LOGE("PurgeablePixelMapBuilder rejected recursive rebuild");
        return false;
    }
    std::lock_guard<std::mutex> lock(state_->mutex);
    if (state_->current == nullptr) {
        return false;
    }
    PixelMapRebuildScope rebuildScope(&pixelMap_);
    uint32_t bufferSize = pixelMap_.GetAllocationByteCount();
    if (bufferSize == 0 || size < bufferSize) {
        IMAGE_LOGE("PurgeablePixelMapBuilder received insufficient target capacity");
        return false;
    }
    std::shared_ptr<PixelMap> rebuilt;
    if (!state_->current->Rebuild(rebuilt) || rebuilt == nullptr || rebuilt.get() == &pixelMap_) {
        IMAGE_LOGE("PurgeablePixelMapBuilder failed to obtain an independent rebuilt PixelMap");
        return false;
    }

    ImageInfo expectedInfo;
    pixelMap_.GetImageInfo(expectedInfo);
    Size expectedAstcRealSize;
    pixelMap_.GetAstcRealSize(expectedAstcRealSize);
    TransformData expectedTransformData;
    pixelMap_.GetTransformData(expectedTransformData);
    YUVDataInfo expectedYuvInfo;
    pixelMap_.GetImageYUVInfo(expectedYuvInfo);
    ImageInfo rebuiltInfo;
    rebuilt->GetImageInfo(rebuiltInfo);
    Size rebuiltAstcRealSize;
    rebuilt->GetAstcRealSize(rebuiltAstcRealSize);
    TransformData rebuiltTransformData;
    rebuilt->GetTransformData(rebuiltTransformData);
    YUVDataInfo rebuiltYuvInfo;
    rebuilt->GetImageYUVInfo(rebuiltYuvInfo);
    if (rebuiltInfo.size.width != expectedInfo.size.width || rebuiltInfo.size.height != expectedInfo.size.height ||
        rebuiltInfo.pixelFormat != expectedInfo.pixelFormat || rebuiltInfo.colorSpace != expectedInfo.colorSpace ||
        rebuiltInfo.alphaType != expectedInfo.alphaType ||
        rebuilt->GetAllocatorType() != pixelMap_.GetAllocatorType() ||
        rebuilt->GetAllocationByteCount() != bufferSize || rebuilt->GetRowStride() != pixelMap_.GetRowStride() ||
        rebuilt->GetRowBytes() != pixelMap_.GetRowBytes() || rebuilt->IsAstc() != pixelMap_.IsAstc() ||
        rebuilt->IsYuvFormat() != pixelMap_.IsYuvFormat() || rebuilt->IsHdr() != pixelMap_.IsHdr() ||
        rebuilt->GetHdrType() != pixelMap_.GetHdrType() ||
        (pixelMap_.IsAstc() && (rebuiltAstcRealSize.width != expectedAstcRealSize.width ||
            rebuiltAstcRealSize.height != expectedAstcRealSize.height ||
            !IsSameTransform(rebuiltTransformData, expectedTransformData))) ||
        (pixelMap_.IsYuvFormat() && !IsSameYuvLayout(rebuiltYuvInfo, expectedYuvInfo))) {
        IMAGE_LOGE("PurgeablePixelMapBuilder output layout changed during rebuild");
        return false;
    }

    const uint8_t *source = rebuilt->GetPixels();
    if (source == nullptr || source == data) {
        IMAGE_LOGE("PurgeablePixelMapBuilder rebuilt PixelMap has an invalid pixel address");
        return false;
    }
    if (memcpy_s(data, size, source, bufferSize) != EOK) {
        IMAGE_LOGE("PurgeablePixelMapBuilder failed to restore pixel buffer");
        return false;
    }
    ImageUtils::FlushSurfaceBuffer(&pixelMap_);
    return true;
}

} // namespace Media
} // namespace OHOS

#endif // IMAGE_PURGEABLE_PIXELMAP
