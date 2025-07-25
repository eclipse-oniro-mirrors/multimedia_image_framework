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

#include "image_system_properties.h"

#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <set>

#include <parameter.h>
#include <parameters.h>
#endif

extern "C" {
extern char* __progname;
}
namespace OHOS {
namespace Media {
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
std::string getCurrentProcessName()
{
    std::string processName;

    std::ifstream cmdlineFile("/proc/self/cmdline");
    if (cmdlineFile.is_open()) {
        std::ostringstream oss;
        oss << cmdlineFile.rdbuf();
        cmdlineFile.close();

        // Extract process name from the command line
        std::string cmdline = oss.str();
        size_t pos = cmdline.find_first_of('\0');
        if (pos != std::string::npos) {
            processName = cmdline.substr(0, pos);
        }
    }
    return processName;
}
#endif

bool ImageSystemProperties::UseGPUScalingCapabilities()
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.UseGPUscalingCapabilities.endabled", false);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetSkiaEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.skdecode.enabled", true);
#else
    return true;
#endif
}

// surfacebuffer tmp switch, only used for test
bool ImageSystemProperties::GetSurfaceBufferEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.surfacebuffer.enabled", false);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetDmaEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.dma.enabled", false);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetDecodeDmaEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.decodeDma.enabled", false);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetAstcEnabled()
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.AstcZeroCopy.enabled", true);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetAntiAliasingEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.AntiAliasing.enabled", true);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetDumpImageEnabled()
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.dumpimage.enabled", false);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetDumpPictureEnabled()
{
#if !defined(CROSS_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.dumppicture.enabled", false);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetHardWareDecodeEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.hardwaredecode.enabled", false);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetHardWareEncodeEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.hardwareencode.enabled", true);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetHeifHardwareDecodeEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.heifhardwaredecode.enabled", true);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetAstcHardWareEncodeEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.AstcHardWareEncode.enabled", false);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetSutEncodeEnabled()
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.SutEncode.enabled", true);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetMediaLibraryAstcEnabled()
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.GenAstc.enabled", true);
#else
    return false;
#endif
}

bool ImageSystemProperties::GetSLRParallelEnabled()
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    return system::GetBoolParameter("persist.multimedia.image.Parallel.endabled", true);
#else
    return true;
#endif
}

bool ImageSystemProperties::GetGenThumbWithGpu()
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    static bool ret = system::GetBoolParameter("persist.multimedia.image.GenThumbWithGpu.endabled", false);
    return ret;
#else
    return false;
#endif
}

bool ImageSystemProperties::GetSLRLaplacianEnabled()
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    static bool ret = system::GetBoolParameter("persist.multimedia.image.PostProcLaplacian.endabled", false);
    return ret;
#else
    return false;
#endif
}

bool ImageSystemProperties::GetNoPaddingEnabled()
{
#if !defined(CROSS_PLATFORM)
    static bool ret = system::GetBoolParameter("persist.gralloc.nopadding.enabled", false);
    return ret;
#else
    return false;
#endif
}

bool ImageSystemProperties::GetPngSampleDecodeEnabled()
{
#if !defined(CROSS_PLATFORM)
    static bool ret = system::GetBoolParameter("persist.multimedia.image.pngSampleDecode.enabled", true);
    return ret;
#else
    return true;
#endif
}

bool ImageSystemProperties::IsSupportOpaqueOpt()
{
    return false;
}
} // namespace Media
} // namespace OHOS
