/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef COMMON_H
#define COMMON_H
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "securectype.h"
#include "securec.h"

#include "image_log.h"

namespace OHOS {
namespace ImagePlugin {
#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "TextureEncode"

#define MAX_CHAR_LEN (256)
#define HWE_HANDLE int32_t *
#ifndef DFX_FILE
#define DFX_FILE (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#endif

#define DFX_LINE __LINE__

#define GET_TIME 0
constexpr char g_version[MAX_CHAR_LEN] = "Texture Encoder(MIT Video Engineering Department) DEBUG v1.0";

int Clamp3(int x, int xmin, int xmax)
{
    if (x > xmax) {
        return xmax;
    } else if (x < xmin) {
        return xmin;
    } else {
        return x;
    }
}

int Min2(int a, int b)
{
    return a < b ? a : b;
}

int Max2(int a, int b)
{
    return a > b ? a : b;
}

typedef union UNION_TYPE {
    int32_t i32;
    uint32_t u32;
    int16_t i16[2];
    uint16_t u16[2];
    int8_t i8[4];
    uint8_t u8[4];
} UNION_TYPE;

typedef enum {
    HWE_LOG_OFF = 0,
    HWE_LOG_ERROR = 1,
    HWE_LOG_WARNING = 2,
    HWE_LOG_INFO = 3,
    HWE_LOG_DEBUG = 4,
} HWELogLevel;

typedef enum HWE_ReturnVal {
    HWE_RET_OK = 0,
    HWE_RET_FAILED = 1,
} HWE_ReturnVal;

#define HWE_FILE __FILE__
#define HWE_LINE __LINE__
#define HWE_FUNC __FUNCTION__
void HWE_Log(const char *fileName, int line, HWELogLevel level.const char *msg, ...);

#define HWE_LOGE(...) \
    IMAGE_LOGE(__VA_ARGS__)

#define HWE_LOGW(...) \
    IMAGE_LOGW(__VA_ARGS__)

#define HWE_LOGI(...) \
    IMAGE_LOGI(__VA_ARGS__)

#define HWE_LOGD(...) \
    IMAGE_LOGD(__VA_ARGS__)

#define HWE_LOGF(...) \
    IMAGE_LOGF(__VA_ARGS__)

int HWE_ReturnIfCheck(int32_t ret, int32_t exp, const char* msg)
{
    if (!msg) {
        HWE_LOGE("HWE_ReturnIfCheck msg is nullptr");
        return HWE_RET_FAILED;
    }
    if (ret != exp) {
        HWE_LOGE(msg);
        return HWE_RET_FAILED;
    }
    return HWE_RET_OK;
}

int HWE_ReturnIfNull(const void* pointer, const char* msg)
{
    if (!msg) {
        HWE_LOGE("HWE_ReturnIfCheck msg is nullptr");
        return HWE_RET_FAILED;
    }
    if (pointer == nullptr) {
        HWE_LOGE(msg);
        return HWE_RET_FAILED;
    }
    return HWE_RET_OK;
}
} // namespace ImagePlugin
} // namespace OHOS
#endif