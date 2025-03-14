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

#ifndef ANI_SRC_INCLUDE_IMAGE_ANI_UTILS_H
#define ANI_SRC_INCLUDE_IMAGE_ANI_UTILS_H
 
#include <ani.h>
#include "image_source_ani.h"
#include "pixel_map.h"
#include "pixel_map_ani.h"
 
namespace OHOS {
namespace Media {

class ImageAniUtils {
public:
    static PixelMap* GetPixelMapFromEnv([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj);
    static ani_object CreateImageInfoValueFromNative(ani_env* env, const ImageInfo &imgInfo, PixelMap* pixelmap);
    static ani_object CreateAniPixelMap(ani_env* env, std::unique_ptr<PixelMapAni>& pPixelMapAni);
    static ani_object CreateAniImageSource(ani_env* env, std::unique_ptr<ImageSourceAni>& pImageSourceAni);
    static ani_string GetAniString(ani_env *env, const std::string& str);
};

} // namespace Media
} // namespace OHOS
 
#endif // ANI_SRC_INCLUDE_IMAGE_ANI_UTILS_H