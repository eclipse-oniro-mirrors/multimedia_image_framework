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
#ifndef IMAGE_SOURCE_H
#define IMAGE_SOURCE_H

#include "ffi_remote_data.h"
#include "image_source.h"
#include "image_ffi.h"
#include "image_type.h"

 
namespace OHOS {
namespace Media {
class ImageSourceImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(ImageSourceImpl, OHOS::FFI::FFIData)
public:
    explicit ImageSourceImpl(std::unique_ptr<ImageSource> ptr_);
    ~ImageSourceImpl() override
    {
        nativeImgSrc = nullptr;
    }
    ImageSourceImpl(std::unique_ptr<ImageSource> imageSource, std::unique_ptr<IncrementalPixelMap> pixelMap);
    std::shared_ptr<ImageSource> nativeImgSrc = nullptr;
    std::shared_ptr<IncrementalPixelMap> GetIncrementalPixelMap()
    {
        return navIncPixelMap_;
    }
    uint32_t GetImageInfo(uint32_t index, ImageInfo &imageInfo);
    uint32_t GetSupportedFormats(std::set<std::string> &formats);

    uint32_t GetImageProperty(std::string key, uint32_t index, std::string &defaultValue);
    uint32_t ModifyImageProperty(std::string key, std::string value);
    uint32_t GetFrameCount(uint32_t &errorCode);
    uint32_t UpdateData(uint8_t *data, uint32_t size, bool isCompleted);
    int64_t CreatePixelMap(uint32_t index, DecodeOptions &opts, uint32_t &errorCode);
    std::vector<int64_t> CreatePixelMapList(uint32_t index, DecodeOptions opts, uint32_t* errorCode);
    std::unique_ptr<std::vector<int32_t>> GetDelayTime(uint32_t* errorCode);

    void SetPathName(std::string pathName);
    void SetFd(int fd);
    void SetBuffer(uint8_t *data, uint32_t size);
    void Release() {}

    static std::unique_ptr<ImageSource> CreateImageSource(std::string uri, uint32_t* errCode);
    static std::unique_ptr<ImageSource> CreateImageSourceWithOption(std::string uri, SourceOptions &opts,
        uint32_t* errCode);
    static std::unique_ptr<ImageSource> CreateImageSource(int fd, uint32_t* errCode);
    static std::unique_ptr<ImageSource> CreateImageSourceWithOption(int fd, SourceOptions &opts, uint32_t* errCode);
    static std::unique_ptr<ImageSource> CreateImageSource(uint8_t *data, uint32_t size, uint32_t* errCode);
    static std::unique_ptr<ImageSource> CreateImageSourceWithOption(uint8_t *data, uint32_t size, SourceOptions &opts,
        uint32_t* errCode);
    static std::unique_ptr<ImageSource> CreateImageSource(const int fd, int32_t offset,
        int32_t length, const SourceOptions &opts, uint32_t &errorCode);
    static std::tuple<std::unique_ptr<ImageSource>,
        std::unique_ptr<IncrementalPixelMap>> CreateIncrementalSource(const uint8_t *data, uint32_t size,
                                                                      SourceOptions &opts, uint32_t &errorCode);

private:
    std::shared_ptr<IncrementalPixelMap> navIncPixelMap_ = nullptr;
    uint32_t index_ = 0;
    std::string pathName_ = "";
    int fd_ = -1; // INVALID_FD
    uint8_t* buffer_ = nullptr;
    size_t bufferSize_ = 0;
};
}
}
 
#endif