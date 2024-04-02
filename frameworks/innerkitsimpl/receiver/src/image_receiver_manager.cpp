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

#include "image_receiver_manager.h"
namespace OHOS {
namespace Media {
using namespace std;

ImageReceiverManager& ImageReceiverManager::getInstance()
{
    static ImageReceiverManager instance;
    return instance;
}

string ImageReceiverManager::SaveImageReceiver(shared_ptr<ImageReceiver> imageReceiver)
{
    if (imageReceiver != nullptr && imageReceiver->GetReceiverSurface() != nullptr) {
        return receiverManager_.save(imageReceiver, imageReceiver->GetReceiverSurface()->GetUniqueId());
    }
    return receiverManager_.save(imageReceiver);
}
shared_ptr<ImageReceiver> ImageReceiverManager::getImageReceiverByKeyId(string keyId)
{
    return receiverManager_.get(keyId);
}
sptr<Surface> ImageReceiverManager::getSurfaceByKeyId(string keyId)
{
    shared_ptr<ImageReceiver> imageReceiver = getImageReceiverByKeyId(keyId);
    if (imageReceiver != nullptr) {
        return imageReceiver->GetReceiverSurface();
    }
    return nullptr;
}
void ImageReceiverManager::ReleaseReceiverById(string id)
{
    ImageReceiverManager& manager = ImageReceiverManager::getInstance();
    manager.receiverManager_.release(id);
}
} // namespace Media
} // namespace OHOS
