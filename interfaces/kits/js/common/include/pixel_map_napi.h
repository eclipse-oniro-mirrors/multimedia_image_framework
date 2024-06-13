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

#ifndef INTERFACES_KITS_JS_COMMON_INCLUDE_PIXEL_MAP_NAPI_H
#define INTERFACES_KITS_JS_COMMON_INCLUDE_PIXEL_MAP_NAPI_H

#include "pixel_map.h"
#include "image_type.h"
#include "image_source.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Media {
enum class ImageType {
    TYPE_UNKNOWN = 0,
    TYPE_PIXEL_MAP = 1
};
class PixelMapNapi {
public:
    PixelMapNapi();
    ~PixelMapNapi();

    static napi_value Init(napi_env env, napi_value exports);

    static napi_value CreatePixelMap(napi_env env, std::shared_ptr<PixelMap> pixelmap);
    static std::shared_ptr<PixelMap> GetPixelMap(napi_env env, napi_value pixelmap);
    std::shared_ptr<PixelMap>* GetPixelMap();
    std::shared_ptr<PixelMap> GetPixelNapiInner()
    {
        return nativePixelMap_;
    }
    void ReleasePixelNapiInner()
    {
        setPixelNapiEditable(false);
        nativePixelMap_ = nullptr;
    }
    void setPixelNapiEditable(bool isEditable)
    {
        isPixelNapiEditable = isEditable;
    }
    bool GetPixelNapiEditable()
    {
        return isPixelNapiEditable;
    }
    uint32_t GetUniqueId()
    {
        return uniqueId_;
    }
    bool IsLockPixelMap();
    bool LockPixelMap();
    void UnlockPixelMap();
    static napi_ref GetConstructor()
    {
        return sConstructor_;
    }
private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize);

    // readonly property
    static napi_value GetIsEditable(napi_env env, napi_callback_info info);
    static napi_value GetIsStrideAlignment(napi_env env, napi_callback_info info);

    /* stattic method */
    static napi_value CreatePixelMap(napi_env env, napi_callback_info info);
    static napi_value CreatePremultipliedPixelMap(napi_env env, napi_callback_info info);
    static napi_value CreateUnpremultipliedPixelMap(napi_env env, napi_callback_info info);
    /* stattic method */
    static napi_value CreatePixelMapSync(napi_env env, napi_callback_info info);
    static void CreatePixelMapComplete(napi_env env, napi_status status, void *data);
    static napi_value Unmarshalling(napi_env env, napi_callback_info info);
    static void UnmarshallingComplete(napi_env env, napi_status status, void *data);
    static napi_value CreatePixelMapFromParcel(napi_env env, napi_callback_info info);
    static napi_value CreatePixelMapFromSurface(napi_env env, napi_callback_info info);
    static napi_value CreatePixelMapFromSurfaceSync(napi_env env, napi_callback_info info);
    static void CreatePixelMapFromSurfaceComplete(napi_env env, napi_status status, void *data);
    static napi_value ThrowExceptionError(napi_env env,
        const std::string &tag, const std::uint32_t &code, const std::string &info);

    // methods
    static napi_value ReadPixelsToBuffer(napi_env env, napi_callback_info info);
    static napi_value ReadPixelsToBufferSync(napi_env env, napi_callback_info info);
    static napi_value ReadPixels(napi_env env, napi_callback_info info);
    static napi_value ReadPixelsSync(napi_env env, napi_callback_info info);
    static napi_value WritePixels(napi_env env, napi_callback_info info);
    static napi_value WritePixelsSync(napi_env env, napi_callback_info info);
    static napi_value WriteBufferToPixels(napi_env env, napi_callback_info info);
    static napi_value WriteBufferToPixelsSync(napi_env env, napi_callback_info info);
    static napi_value GetImageInfo(napi_env env, napi_callback_info info);
    static napi_value GetImageInfoSync(napi_env env, napi_callback_info info);
    static napi_value GetBytesNumberPerRow(napi_env env, napi_callback_info info);
    static napi_value GetPixelBytesNumber(napi_env env, napi_callback_info info);
    static napi_value getPixelBytesCount(napi_env env, napi_callback_info info);
    static napi_value IsSupportAlpha(napi_env env, napi_callback_info info);
    static napi_value SetAlphaAble(napi_env env, napi_callback_info info);
    static napi_value CreateAlphaPixelmap(napi_env env, napi_callback_info info);
    static napi_value CreateAlphaPixelmapSync(napi_env env, napi_callback_info info);
    static napi_value GetDensity(napi_env env, napi_callback_info info);
    static napi_value SetDensity(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value SetAlpha(napi_env env, napi_callback_info info);
    static napi_value SetAlphaSync(napi_env env, napi_callback_info info);

    static napi_value Scale(napi_env env, napi_callback_info info);
    static napi_value ScaleSync(napi_env env, napi_callback_info info);
    static napi_value Translate(napi_env env, napi_callback_info info);
    static napi_value TranslateSync(napi_env env, napi_callback_info info);
    static napi_value Rotate(napi_env env, napi_callback_info info);
    static napi_value RotateSync(napi_env env, napi_callback_info info);
    static napi_value Flip(napi_env env, napi_callback_info info);
    static napi_value FlipSync(napi_env env, napi_callback_info info);
    static napi_value Crop(napi_env env, napi_callback_info info);
    static napi_value CropSync(napi_env env, napi_callback_info info);

    static napi_value GetColorSpace(napi_env env, napi_callback_info info);
    static napi_value SetColorSpace(napi_env env, napi_callback_info info);
    static napi_value Marshalling(napi_env env, napi_callback_info info);
    static napi_value ApplyColorSpace(napi_env env, napi_callback_info info);
    static ImageType ParserImageType(napi_env env, napi_value argv);

    void release();
    static thread_local napi_ref sConstructor_;
    napi_env env_ = nullptr;
    std::shared_ptr<PixelMap> nativePixelMap_;
    int32_t lockCount = 0;
    bool isRelease = false;
    bool isPixelNapiEditable = true;
    uint32_t uniqueId_ = 0;
};

class PixelMapContainer {
public:
    static PixelMapContainer& GetInstance()
    {
        static PixelMapContainer source;
        return source;
    }

    std::shared_ptr<PixelMap>& operator[](const uint32_t &key)
    {
        return map_[key];
    }

    bool IsEmpty()
    {
        return map_.empty();
    }

    bool Insert(const uint32_t &key, const std::shared_ptr<PixelMap> &value)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!IsEmpty() && (map_.find(key) != map_.end())) map_.erase(key);
        auto ret = map_.insert(std::pair<uint32_t, std::shared_ptr<PixelMap>>(key, value));
        return ret.second;
    }

    bool Find(const uint32_t &key)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = map_.find(key);
        return it != map_.end() ? true : false;
    }

    void Erase(const uint32_t &key)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (map_.find(key) != map_.end()) {
            map_.erase(key);
        }
        return;
    }

    void Clear()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        map_.clear();
        return;
    }

private:
    PixelMapContainer() = default;
    PixelMapContainer(const PixelMapContainer&) = delete;
    PixelMapContainer(const PixelMapContainer&&) = delete;
    PixelMapContainer &operator=(const PixelMapContainer&) = delete;
    std::mutex mutex_;
    std::map<uint32_t, std::shared_ptr<PixelMap>> map_;
};
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_JS_COMMON_INCLUDE_PIXEL_MAP_NAPI_H
