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

#ifndef INTERFACES_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_NAPI_H
#define INTERFACES_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_NAPI_H

#include "pixel_map.h"
#include "image_type.h"
#include "image_source.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "pixel_map_napi.h"
#include "incremental_pixel_map.h"
#include "image_resource_utils.h"
#include "picture.h"
#include "picture_napi.h"

namespace OHOS {
namespace Media {
class ImageSourceNapi {
public:
    ImageSourceNapi();
    ~ImageSourceNapi();

    static napi_value Init(napi_env env, napi_value exports);
    std::shared_ptr<ImageSource> nativeImgSrc = nullptr;
    std::shared_ptr<IncrementalPixelMap> GetIncrementalPixelMap()
    {
        return navIncPixelMap_;
    }

    static thread_local std::string filePath_;
    static thread_local int fileDescriptor_;
    static thread_local void* fileBuffer_;
    static thread_local size_t fileBufferSize_;
    static int32_t CreateImageSourceNapi(napi_env env, napi_value* result);
    static napi_value CreateImageSourceNapi(napi_env env, std::shared_ptr<ImageSource> imageSource);
    void SetIncrementalPixelMap(std::shared_ptr<IncrementalPixelMap> incrementalPixelMap);
    void SetNativeImageSource(std::shared_ptr<ImageSource> imageSource);
    void SetImageResource(ImageResource resource);
    ImageResource GetImageResource();

private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize);

    // readonly property
    static napi_value GetSupportedFormats(napi_env env, napi_callback_info info);

    // static methods
    static napi_value CreateImageSource(napi_env env, napi_callback_info info);
    static napi_value CreateIncrementalSource(napi_env env, napi_callback_info info);
    static napi_value GetImageSourceSupportedFormats(napi_env env, napi_callback_info info);

    static napi_value CreateImageSourceComplete(napi_env env, napi_status status, void *data);
    // methods
    static napi_value GetImageInfo(napi_env env, napi_callback_info info);
    static napi_value GetImageInfoSync(napi_env env, napi_callback_info info);
    static napi_value CreatePixelMap(napi_env env, napi_callback_info info);
    static napi_value CreatePixelMapSync(napi_env env, napi_callback_info info);
    static napi_value WriteImageMetadata(napi_env env, napi_callback_info info);
    static napi_value ModifyImageProperty(napi_env env, napi_callback_info info);
    static napi_value ModifyImagePropertiesEnhanced(napi_env env, napi_callback_info info);
    static napi_value ReadImageMetadata(napi_env env, napi_callback_info info);
    static napi_value ReadImageMetadataByType(napi_env env, napi_callback_info info);
    static napi_value GetImageProperty(napi_env env, napi_callback_info info);
    static napi_value GetImagePropertySync(napi_env env, napi_callback_info info);
    static napi_value UpdateData(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value CreatePixelMapList(napi_env env, napi_callback_info info);
    static napi_value GetDelayTime(napi_env env, napi_callback_info info);
    static napi_value GetDisposalType(napi_env env, napi_callback_info info);
    static napi_value GetFrameCount(napi_env env, napi_callback_info info);
    static napi_value IsJpegProgressive(napi_env env, napi_callback_info info);
    static std::vector<napi_property_descriptor> RegisterNapi();
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    static napi_value CreatePicture(napi_env env, napi_callback_info info);
    static napi_value CreatePictureAtIndex(napi_env env, napi_callback_info info);
    static napi_value CreateThumbnail(napi_env env, napi_callback_info info);
    static napi_value CreateThumbnailSync(napi_env env, napi_callback_info info);
#endif
    static napi_value CreatePixelMapUsingAllocator(napi_env env, napi_callback_info info);
    static napi_value CreatePixelMapUsingAllocatorSync(napi_env env, napi_callback_info info);
    static napi_value CreateWideGamutSdrPixelMap(napi_env env, napi_callback_info info);

    void release();
    static thread_local napi_ref sConstructor_;
    static thread_local std::shared_ptr<ImageSource> sImgSrc_;
    static thread_local std::shared_ptr<IncrementalPixelMap> sIncPixelMap_;
    std::shared_ptr<IncrementalPixelMap> navIncPixelMap_ = nullptr;

    napi_env env_ = nullptr;
    bool isRelease = false;
    ImageResource resource_;
};

extern "C" {
    napi_value GetImageSourceNapi(napi_env env, std::shared_ptr<ImageSource> imageSource);
    bool GetNativeImageSource(void *imageSourceNapi, std::shared_ptr<ImageSource> &imageSource);
}
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_NAPI_H
