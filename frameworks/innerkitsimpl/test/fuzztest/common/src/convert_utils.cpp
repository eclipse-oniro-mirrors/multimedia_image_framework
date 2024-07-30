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

#include "convert_utils.h"

#include <chrono>
#include <unistd.h>
#include <fcntl.h>

#include "pixel_map.h"
#include "image_packer.h"
#include "media_errors.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "CONVERT_UTILS"

static const int FOUR_BYTES_PER_PIXEL = 4;
static const int NUM_TWO = 2;
using namespace OHOS::Media;

int ConvertDataToFd(const uint8_t* data, size_t size, std::string encodeFormat)
{
    if (size < FOUR_BYTES_PER_PIXEL) {
        return -1;
    }
    int picturePixels = size / FOUR_BYTES_PER_PIXEL;
    InitializationOptions opts = {};
    if (picturePixels % NUM_TWO == 0) {
        opts.size.width = picturePixels / NUM_TWO;
        opts.size.height = NUM_TWO;
    } else {
        opts.size.width = picturePixels;
        opts.size.height = 1;
    }
    auto pixelMap = PixelMap::Create(reinterpret_cast<const uint32_t*>(data),
        static_cast<uint32_t>(picturePixels * FOUR_BYTES_PER_PIXEL), opts);
    if (pixelMap == nullptr) {
        return -1;
    }

    std::string pathName = "/data/local/tmp/testFile_" + GetNowTimeStr() + ".dat";
    IMAGE_LOGI("%{public}s pathName is %{public}s", __func__, pathName.c_str());
    std::remove(pathName.c_str());
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return -1;
    }
    ImagePacker packer;
    PackOption option;
    option.format = encodeFormat;
    packer.StartPacking(fd, option);
    packer.AddImage(*(pixelMap.get()));
    uint32_t errorCode = packer.FinalizePacking();
    if (errorCode != SUCCESS) {
        return -1;
    }
    return fd;
}

std::string GetNowTimeStr()
{
    auto now = std::chrono::system_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch());
    return std::to_string(us.count());
}