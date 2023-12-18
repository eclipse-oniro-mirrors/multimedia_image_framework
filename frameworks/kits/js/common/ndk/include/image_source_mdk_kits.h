/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_MDK_KITS_H
#define FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_MDK_KITS_H

#include "common_utils.h"
#include "image_source_napi.h"
#include "image_source_mdk.h"
#include "raw_file.h"

namespace OHOS {
namespace Media {
#ifdef __cplusplus
extern "C" {
#endif

struct DataArray {
    uint8_t* data = nullptr;
    uint32_t dataSize = 0;
};

struct ImageSourceArgs {
    struct OhosImageSource* source;
    struct OhosImageSourceOps* sourceOps;
    struct OhosImageDecodingOps* decodingOps;
    struct OhosImageSourceDelayTimeList* outDelayTimes;
    struct OhosImageSourceSupportedFormatList* outFormats;
    struct OhosImageSourceInfo* outInfo;
    struct OhosImageSourceProperty* inPropertyKey;
    struct OhosImageSourceProperty* propertyVal;
    struct OhosImageSourceUpdateData* inUpdateData;
    DataArray dataArray;
    std::string uri;
    int32_t fd = -1;
    RawFileDescriptor rawFile;
    ImageSourceNapi* napi;
    napi_env inEnv;
    napi_value inVal;
    int32_t inInt32;
    napi_value *outVal;
    uint32_t* outUint32;
};

enum {
    ENV_FUNC_IMAGE_SOURCE_CREATE,
    ENV_FUNC_IMAGE_SOURCE_CREATE_FROM_URI,
    ENV_FUNC_IMAGE_SOURCE_CREATE_FROM_FD,
    ENV_FUNC_IMAGE_SOURCE_CREATE_FROM_DATA,
    ENV_FUNC_IMAGE_SOURCE_CREATE_FROM_RAW_FILE,
    ENV_FUNC_IMAGE_SOURCE_CREATE_INCREMENTAL,
    ENV_FUNC_IMAGE_SOURCE_UNWRAP,
    STA_FUNC_IMAGE_SOURCE_GET_SUPPORTED_FORMATS,
    CTX_FUNC_IMAGE_SOURCE_CREATE_PIXELMAP,
    CTX_FUNC_IMAGE_SOURCE_CREATE_PIXELMAP_LIST,
    CTX_FUNC_IMAGE_SOURCE_GET_DELAY_TIME,
    CTX_FUNC_IMAGE_SOURCE_GET_FRAME_COUNT,
    CTX_FUNC_IMAGE_SOURCE_GET_IMAGE_INFO,
    CTX_FUNC_IMAGE_SOURCE_GET_IMAGE_PROPERTY,
    CTX_FUNC_IMAGE_SOURCE_MODIFY_IMAGE_PROPERTY,
    CTX_FUNC_IMAGE_SOURCE_UPDATE_DATA
};

int32_t ImageSourceNativeCall(int32_t mode, struct ImageSourceArgs* args);
#ifdef __cplusplus
};
#endif
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_MDK_KITS_H