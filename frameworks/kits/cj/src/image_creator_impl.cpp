/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "image_creator_impl.h"

namespace OHOS {
    namespace Media {
        extern "C" {
            ImageCreatorImpl::ImageCreatorImpl(int32_t width, int32_t height, int32_t format, int32_t capacity)
            {
                real_ = ImageCreator::CreateImageCreator(width, height, format, capacity);
            }

            std::shared_ptr<ImageCreator> ImageCreatorImpl::GetImageCreator()
            {
                return real_;
            }
        }
    }  // namespace Media
}  // namespace OHOS
