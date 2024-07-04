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

#ifndef OHOS_IMAGE_UTILS_H
#define OHOS_IMAGE_UTILS_H

#include <cstdint>
#include <memory>
#include <string>

const int64_t INIT_FAILED = -1;

extern "C" {
    typedef struct {
        int32_t height;
        int32_t width;
    } CSize;

    typedef struct {
        CSize size;
        int32_t x;
        int32_t y;
    } CRegion;

    typedef struct {
        int32_t componentType;
        int32_t rowStride;
        int32_t pixelStride;
        uint8_t *byteBuffer;
        int64_t bufSize;
    } CRetComponent;

    typedef struct {
        uint64_t bufferSize;
        uint32_t offset;
        uint32_t stride;
        CRegion region;
        uint8_t* dst;
    } CPositionArea;

    typedef struct {
        uint8_t* data;
        size_t arrSize;
        uint32_t offset;
        uint32_t updateLen;
        bool isCompleted;
    } UpdateDataInfo;
}

#define FFI_EXPORT __attribute__((visibility("default")))

#endif