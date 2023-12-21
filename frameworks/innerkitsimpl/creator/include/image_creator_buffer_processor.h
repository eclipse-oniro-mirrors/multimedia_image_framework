/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_CREATOR_INCLUDE_IMAGE_CREATOR_BUFFER_PROCESSOR_H
#define FRAMEWORKS_INNERKITSIMPL_CREATOR_INCLUDE_IMAGE_CREATOR_BUFFER_PROCESSOR_H

#include "native_image.h"
#include "image_creator.h"
namespace OHOS {
namespace Media {
class ImageCreatorBufferProcessor : public IBufferProcessor {
public:
    explicit ImageCreatorBufferProcessor(ImageCreator* creator) : creator_(creator)
    {
    }
    ~ImageCreatorBufferProcessor()
    {
        creator_ = nullptr;
    }
    void BufferRelease(sptr<SurfaceBuffer>& buffer) override
    {
        // Do not release heare.
        (void)buffer;
    }
private:
    ImageCreator* creator_ = nullptr;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_CREATOR_INCLUDE_IMAGE_CREATOR_BUFFER_PROCESSOR_H
