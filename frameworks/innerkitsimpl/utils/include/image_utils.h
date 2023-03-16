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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_UTILS_H_
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_UTILS_H_

#include <cstdlib>
#include <cstdio>
#include <string>
#include "image_type.h"
#include "iosfwd"

namespace OHOS { namespace MultimediaPlugin { class PluginServer; } }
namespace OHOS {
namespace Media {
const std::string IMAGE_ENCODE_FORMAT = "encodeFormat";
constexpr uint32_t MALLOC_MAX_LENTH = 0x40000000;

class ImageUtils {
public:
    static bool GetFileSize(const std::string &pathName, size_t &size);
    static bool GetFileSize(const int fd, size_t &size);
    static bool GetInputStreamSize(std::istream &inputStream, size_t &size);
    static int32_t GetPixelBytes(const PixelFormat &pixelFormat);
    static bool PathToRealPath(const std::string &path, std::string &realPath);
    static bool FloatCompareZero(float src);
    static AlphaType GetValidAlphaTypeByFormat(const AlphaType &dstType, const PixelFormat &format);
    static bool IsValidImageInfo(const ImageInfo &info);
    static MultimediaPlugin::PluginServer& GetPluginServer();
    static bool CheckMulOverflow(int32_t width, int32_t bytesPerPixel);
    static bool CheckMulOverflow(int32_t width, int32_t height, int32_t bytesPerPixel);
    static void BGRAToARGB(uint8_t* srcPixels, uint8_t* dstPixels, uint32_t byteCount);
    static void ARGBToBGRA(uint8_t* srcPixels, uint8_t* dstPixels, uint32_t byteCount);

private:
    static uint32_t RegisterPluginServer();
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_UTILS_H_
