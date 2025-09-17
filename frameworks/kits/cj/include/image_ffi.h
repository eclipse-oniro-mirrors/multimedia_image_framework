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
#ifndef IMAGE_FFI_H
#define IMAGE_FFI_H

#include "cj_image_utils.h"

extern "C" {
struct CImageInfo {
    int32_t height;
    int32_t width;
    int32_t density;
};

struct CImageInfoV2 {
    int32_t height;
    int32_t width;
    int32_t density;
    int32_t stride;
    int32_t pixelFormat;
    int32_t alphaType;
    char* mimeType;
    bool isHdr;
};

struct CSourceOptions {
    int32_t baseDensity;
    int32_t pixelFormat;
    int32_t height;
    int32_t width;
};

struct CInitializationOptions {
    int32_t alphaType;
    bool editable = false;
    int32_t pixelFormat;
    int32_t scaleMode;
    int32_t width;
    int32_t height;
};

struct CInitializationOptionsV2 {
    int32_t alphaType;
    bool editable = false;
    int32_t srcPixelFormat;
    int32_t pixelFormat;
    int32_t scaleMode;
    int32_t width;
    int32_t height;
};

struct CDecodingOptions {
    int32_t fitDensity;
    CSize desiredSize;
    CRegion desiredRegion;
    float rotateDegrees;
    uint32_t sampleSize;
    int32_t desiredPixelFormat;
    bool editable;
    int64_t desiredColorSpace;
};

struct CDecodingOptionsV2 {
    int32_t fitDensity;
    CSize desiredSize;
    CRegion desiredRegion;
    float rotateDegrees;
    uint32_t sampleSize;
    int32_t desiredPixelFormat;
    bool editable;
    int64_t desiredColorSpace;
    int32_t desiredDynamicRange;
};

struct CPackingOption {
    const char* format;
    uint8_t quality;
    uint64_t bufferSize;
};

struct CPackingOptionV2 {
    const char* format;
    uint8_t quality;
    uint64_t bufferSize;
    int32_t desiredDynamicRange;
    bool needsPackProperties;
};

struct CjProperties {
    char** key;
    char** value;
    int64_t size;
};
}
#endif