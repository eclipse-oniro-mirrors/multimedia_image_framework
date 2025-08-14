/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_KITS_TAIHE_INCLUDE_TRANSFER_TAIHE_H
#define FRAMEWORKS_KITS_TAIHE_INCLUDE_TRANSFER_TAIHE_H

#include "ohos.multimedia.image.image.proj.hpp"
#include "ohos.multimedia.image.image.impl.hpp"
#include "taihe/runtime.hpp"

namespace ANI::Image {
using namespace taihe;
using namespace ohos::multimedia::image::image;

void* GetNapiFunction(const char* name);

ImageSource ImageSourceTransferStaticImpl(uintptr_t input);
uintptr_t ImageSourceTransferDynamicImpl(ImageSource input);

ImagePacker ImagePackerTransferStaticImpl(uintptr_t input);
uintptr_t ImagePackerTransferDynamicImpl(ImagePacker input);

Picture PictureTransferStaticImpl(uintptr_t input);
uintptr_t PictureTransferDynamicImpl(Picture input);

AuxiliaryPicture AuxiliaryPictureTransferStaticImpl(uintptr_t input);
uintptr_t AuxiliaryPictureTransferDynamicImpl(AuxiliaryPicture input);

ImageReceiver ImageReceiverTransferStaticImpl(uintptr_t input);
uintptr_t ImageReceiverTransferDynamicImpl(ImageReceiver input);

ImageCreator ImageCreatorTransferStaticImpl(uintptr_t input);
uintptr_t ImageCreatorTransferDynamicImpl(ImageCreator input);

PixelMap PixelMapTransferStaticImpl(uintptr_t input);
uintptr_t PixelMapTransferDynamicImpl(weak::PixelMap input);
} // namespace ANI::Image

#endif // FRAMEWORKS_KITS_TAIHE_INCLUDE_TRANSFER_TAIHE_H