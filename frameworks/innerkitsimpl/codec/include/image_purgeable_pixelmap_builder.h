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

#ifndef FRAMEWORKS_INNERKITSIMPL_CODEC_INCLUDE_IMAGE_PURGEABLE_PIXELMAP_BUILDER_H
#define FRAMEWORKS_INNERKITSIMPL_CODEC_INCLUDE_IMAGE_PURGEABLE_PIXELMAP_BUILDER_H

#ifdef IMAGE_PURGEABLE_PIXELMAP

#include <cstddef>
#include <cstdint>
#include <memory>

#include "image_source.h"
#include "pixel_map.h"
#include "purgeable_mem_builder.h"

namespace OHOS {
namespace Media {

class DecodeRebuilder final : public PixelMapRebuilder {
public:
    DecodeRebuilder(std::unique_ptr<ImageSource> backupImageSource, uint32_t index, const DecodeOptions &options);
    bool Rebuild(std::shared_ptr<PixelMap> &temporaryPixelmap) override;

private:
    std::unique_ptr<ImageSource> backupImageSource_;
    uint32_t index_ = 0;
    DecodeOptions options_;
};

class PurgeablePixelMapBuilder final : public PurgeableMem::PurgeableMemBuilder {
public:
    PurgeablePixelMapBuilder(std::shared_ptr<PixelMapRebuildState> state, PixelMap &pixelMap);
    bool Build(void *data, size_t size) override;

private:
    std::shared_ptr<PixelMapRebuildState> state_;
    // FreePixelMap clears state_->current under its mutex before releasing the target.
    PixelMap &pixelMap_;
};

} // namespace Media
} // namespace OHOS

#endif // IMAGE_PURGEABLE_PIXELMAP
#endif // FRAMEWORKS_INNERKITSIMPL_CODEC_INCLUDE_IMAGE_PURGEABLE_PIXELMAP_BUILDER_H
