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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_TEXTURE_ENCODE_IMAGE_COMPRESSOR_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_TEXTURE_ENCODE_IMAGE_COMPRESSOR_H

#include <cstdint>
#include <functional>
#include <mutex>

#ifndef USE_OPENCL_WRAPPER
#define USE_OPENCL_WRAPPER
#endif
#include "CL/cl_ext.h"
#include "opencl_wrapper.h"

namespace OHOS {
namespace ImagePlugin {
namespace AstcEncBasedCl {

#define CL_ASTC_SHARE_LIB_API

extern std::mutex checkClBinPathMutex;

constexpr uint32_t ASTC_CL_KERNEL_TIMEOUT_MS = 1000;
constexpr uint32_t ASTC_CL_KERNEL_POLL_INTERVAL_US = 10000;
constexpr uint32_t ASTC_CL_MAX_CONCURRENCY = 4;

enum CL_ASTC_STATUS {
    CL_ASTC_ENC_SUCCESS = 0,
    CL_ASTC_ENC_FAILED,
    CL_ASTC_ENC_TIMEOUT
};

enum class ClJobState {
    RUNNING = 0,
    COMPLETE,
    JOB_ERROR,
    UNKNOWN
};

struct ClAstcImageOption {
    uint8_t *data = nullptr;
    int32_t stride = 0;
    int32_t width = 0;
    int32_t height = 0;
};

struct ClAstcObjEnc {
    uint32_t *blockErrs_ = nullptr;
    size_t astcSize = 0;
    cl_mem inputImage = nullptr;
    cl_mem astcResult = nullptr;
    cl_mem errBuffer = nullptr;
    cl_event kernelEvent = nullptr;
};

struct ClAstcHandle {
    cl_device_id deviceID = 0;
    cl_context context = nullptr;
    cl_command_queue queue = nullptr;
    cl_kernel kernel = nullptr;
    ClAstcObjEnc encObj;
};

CL_ASTC_SHARE_LIB_API CL_ASTC_STATUS AstcClCreate(ClAstcHandle **handle, const std::string &clBinPath);

CL_ASTC_SHARE_LIB_API CL_ASTC_STATUS AstcClFillImage(ClAstcImageOption *imageIn, uint8_t *data,
    int32_t stride, int32_t width, int32_t height);

CL_ASTC_SHARE_LIB_API CL_ASTC_STATUS AstcClWaitWithDeadline(const std::function<ClJobState()> &probe,
    uint32_t timeoutMs, uint32_t pollIntervalUs);

CL_ASTC_SHARE_LIB_API CL_ASTC_STATUS AstcClEncImage(ClAstcHandle *handle, const ClAstcImageOption *imageIn,
    uint8_t *buffer);

CL_ASTC_SHARE_LIB_API CL_ASTC_STATUS AstcClClose(ClAstcHandle *handle);

// At most four GPU jobs are admitted. Once any timed-out handle is retained, no new GPU job is
// admitted until process exit; the OS then reclaims the still-driver-owned objects.
CL_ASTC_SHARE_LIB_API bool AstcClTryAcquireSlot();
CL_ASTC_SHARE_LIB_API void AstcClReleaseSlot();
CL_ASTC_SHARE_LIB_API void AstcClDisableGpuPath();
CL_ASTC_SHARE_LIB_API bool AstcClGpuPathIsOpen();
CL_ASTC_SHARE_LIB_API void AstcClAbandonHandle(ClAstcHandle *handle);
CL_ASTC_SHARE_LIB_API void AstcClResetAdmissionStateForTest();
}
}
}
#endif
