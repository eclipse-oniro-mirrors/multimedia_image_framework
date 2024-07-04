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
#ifndef PIXEL_MAP_H
#define PIXEL_MAP_H
 
#include "ffi_remote_data.h"
#include "pixel_map.h"
#include "image_source_impl.h"
#include <string>
 
namespace OHOS {
namespace Media {
class FFI_EXPORT PixelMapImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(PixelMapImpl, OHOS::FFI::FFIData)
public:
    explicit PixelMapImpl(std::shared_ptr<PixelMap> ptr_);
    std::shared_ptr<PixelMap> GetRealPixelMap();
    uint32_t ReadPixelsToBuffer(uint64_t &bufferSize, uint8_t *dst);
    uint32_t WriteBufferToPixels(uint8_t *source, uint64_t &bufferSize);
    int32_t GetDensity();
    uint32_t Opacity(float percent);
    uint32_t Crop(Rect &rect);
    uint32_t GetPixelBytesNumber();
    uint32_t GetBytesNumberPerRow();
    uint32_t ReadPixels(uint64_t &bufferSize, uint32_t &offset, uint32_t &stride,
                                Rect &region, uint8_t *dst);
    uint32_t WritePixels(uint8_t *source, uint64_t &bufferSize, uint32_t &offset,
                        uint32_t &stride, Rect &region);
    uint32_t SetColorSpace(std::shared_ptr<OHOS::ColorManager::ColorSpace> colorSpace);
    std::shared_ptr<OHOS::ColorManager::ColorSpace> GetColorSpace();
    uint32_t ApplyColorSpace(std::shared_ptr<OHOS::ColorManager::ColorSpace> colorSpace);

    void GetImageInfo(ImageInfo &imageInfo);
    void Scale(float xAxis, float yAxis);
    void Flip(bool xAxis, bool yAxis);
    void Rotate(float degrees);
    void Translate(float xAxis, float yAxis);

    bool GetIsEditable();
    bool GetIsStrideAlignment();

    static std::unique_ptr<PixelMap> CreatePixelMap(const InitializationOptions &opts);
    static std::unique_ptr<PixelMap> CreatePixelMap(uint32_t *colors, uint32_t colorLength,
        InitializationOptions &opts);
    static std::unique_ptr<PixelMap> CreateAlphaPixelMap(PixelMap &source, InitializationOptions &opts);
private:
    std::shared_ptr<PixelMap> real_;
};
}
}
 
#endif
