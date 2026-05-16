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
 
#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_COMMON_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_COMMON_H
 
#include "heif_type.h"
#include "image_type.h"
 
namespace OHOS {
namespace ImagePlugin {
using namespace Media;
constexpr inline Media::MetadataType MetadataTypeConvertFromHeif(ImagePlugin::HeifMetadataType type)
{
    return static_cast<Media::MetadataType>(static_cast<int>(type));
}
constexpr inline ImagePlugin::HeifMetadataType MetadataTypeConvertToHeif(Media::MetadataType type)
{
    return static_cast<ImagePlugin::HeifMetadataType>(static_cast<int>(type));
}
} // namespace ImagePlugin
} // namespace OHOS
 
#endif