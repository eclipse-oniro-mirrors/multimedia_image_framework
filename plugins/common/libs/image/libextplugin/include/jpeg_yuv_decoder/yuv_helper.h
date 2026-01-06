/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_YUV_HELPER_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_YUV_HELPER_H

#include <cstdint>

namespace OHOS {
namespace ImagePlugin {

typedef int (*FUNC_I444ToI420)(const uint8_t* src_y, int src_stride_y, const uint8_t* src_u, int src_stride_u,
    const uint8_t* src_v, int src_stride_v, uint8_t* dst_y, int dst_stride_y, uint8_t* dst_u,
    int dst_stride_u, uint8_t* dst_v, int dst_stride_v, int width, int height);
typedef int (*FUNC_I444ToNV21)(const uint8_t* src_y, int src_stride_y, const uint8_t* src_u, int src_stride_u,
    const uint8_t* src_v, int src_stride_v, uint8_t* dst_y, int dst_stride_y, uint8_t* dst_vu,
    int dst_stride_vu, int width, int height);
typedef int (*FUNC_I422ToI420)(const uint8_t* src_y, int src_stride_y, const uint8_t* src_u, int src_stride_u,
    const uint8_t* src_v, int src_stride_v, uint8_t* dst_y, int dst_stride_y, uint8_t* dst_u,
    int dst_stride_u, uint8_t* dst_v, int dst_stride_v, int width, int height);
typedef int (*FUNC_I422ToNV21)(const uint8_t* src_y, int src_stride_y, const uint8_t* src_u, int src_stride_u,
    const uint8_t* src_v, int src_stride_v, uint8_t* dst_y, int dst_stride_y, uint8_t* dst_vu,
    int dst_stride_vu, int width, int height);
typedef int (*FUNC_I420ToNV21)(const uint8_t* src_y, int src_stride_y, const uint8_t* src_u, int src_stride_u,
    const uint8_t* src_v, int src_stride_v, uint8_t* dst_y, int dst_stride_y, uint8_t* dst_vu,
    int dst_stride_vu, int width, int height);
typedef int (*FUNC_I400ToI420)(const uint8_t* src_y, int src_stride_y, uint8_t* dst_y, int dst_stride_y,
    uint8_t* dst_u, int dst_stride_u, uint8_t* dst_v, int dst_stride_v, int width, int height);

class YuvHelper {
public:
    static YuvHelper& GetInstance();
    FUNC_I444ToI420 I444ToI420 = nullptr;
    FUNC_I444ToNV21 I444ToNV21 = nullptr;
    FUNC_I422ToI420 I422ToI420 = nullptr;
    FUNC_I422ToNV21 I422ToNV21 = nullptr;
    FUNC_I420ToNV21 I420ToNV21 = nullptr;
    FUNC_I400ToI420 I400ToI420 = nullptr;

private:
    YuvHelper(const YuvHelper&) = delete;
    YuvHelper& operator= (const YuvHelper&) = delete;
    YuvHelper(YuvHelper&&) = delete;
    YuvHelper& operator= (YuvHelper&&) = delete;
    YuvHelper();
    ~YuvHelper();

    void* dlHandler_;
};
}
}
#endif