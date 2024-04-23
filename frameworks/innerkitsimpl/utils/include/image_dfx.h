/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_DFX_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_DFX_H

#include <string>

namespace OHOS {
namespace Media {
const uint16_t INNER_INTERFACE = 0;
const uint16_t JS_INTERFACE = 1;
const uint16_t C_INTERFACE = 2;

struct DecodeInfoOptions {
    uint32_t sampleSize;
    float rotate;
    bool editable;
    int32_t sourceWidth;
    int32_t sourceHeight;
    int32_t desireSizeWidth;
    int32_t desireSizeHeight;
    int32_t desireRegionWidth;
    int32_t desireRegionHeight;
    int32_t desireRegionX;
    int32_t desireRegionY;
    int32_t desirePixelFormat;
    uint32_t index;
    int32_t fitDensity;
    int32_t desireColorSpace;
    std::string mimeType;
    uint32_t memorySize;
    int32_t memoryType;
    std::string imageSource;
    uint16_t invokeType;
    bool isIncrementalDecode = false;
    bool isHardDecode;
    std::string hardDecodeError;
    std::string errorMsg;
};

class ImageEvent {
public:
    ImageEvent();
    ~ImageEvent();
    void SetDecodeInfoOptions(const DecodeInfoOptions &options);
    void SetDecodeErrorMsg(std::string msg);
    void ReportDecodeFault();
    void ReportDecodeInfo();
    void SetIncrementalDecode()
    {
        options_.isIncrementalDecode = true;
    }
    DecodeInfoOptions &GetDecodeInfoOptions();
private:
    DecodeInfoOptions options_ = {};
    uint64_t startTime_;
};

void ReportCreateImageSourceFault(uint32_t width, uint32_t height, std::string type, std::string message);
void ReportEncodeFault(uint32_t width, uint32_t height, std::string mimeType, std::string message);
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_DFX_H
