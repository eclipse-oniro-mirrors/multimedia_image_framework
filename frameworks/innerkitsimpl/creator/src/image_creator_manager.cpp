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

#include "image_creator_manager.h"
namespace OHOS {
namespace Media {
using namespace std;
string ImageCreatorManager::SaveImageCreator(shared_ptr<ImageCreator> imageCreator)
{
    return creatorManager_.save(imageCreator);
}
sptr<IConsumerSurface> ImageCreatorManager::GetSurfaceByKeyId(string keyId)
{
    auto creator = GetImageCreatorByKeyId(keyId);
    if (creator == nullptr) {
        return nullptr;
    }
    return creator->GetCreatorSurface();
}
shared_ptr<ImageCreator> ImageCreatorManager::GetImageCreatorByKeyId(string keyId)
{
    return creatorManager_.get(keyId);
}
void ImageCreatorManager::ReleaseCreatorById(string id)
{
    ImageCreatorManager& manager = ImageCreatorManager::getInstance();
    manager.creatorManager_.release(id);
}
} // namespace Media
} // namespace OHOS
