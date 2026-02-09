/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_UTILS_INCLUDE_XMP_HELPER_H
#define INTERFACES_INNERKITS_UTILS_INCLUDE_XMP_HELPER_H

#include <string>
#include <string_view>
#include <utility>
#include "image_log.h"

class XMP_Error;

// Helper macros to simplify XMP exception handling patterns.
#define XMP_TRY() try {

#define XMP_CATCH_RETURN_RET(retExpr)                                            \
    } catch (const XMP_Error &error) {                                           \
        OHOS::Media::XMPHelper::LogXMPError(__func__, error);                    \
        return (retExpr);                                                        \
    } catch (...) {                                                              \
        IMAGE_LOGE("%{public}s unknown exception", __func__);                    \
        return (retExpr);                                                        \
    }

#define XMP_CATCH_RETURN_CODE(defaultErrorCode)                                  \
    } catch (const XMP_Error &error) {                                           \
        OHOS::Media::XMPHelper::LogXMPError(__func__, error);                    \
        return OHOS::Media::XMPHelper::MapXMPErrorToMediaError(error);           \
    } catch (...) {                                                              \
        IMAGE_LOGE("%{public}s unknown exception", __func__);                    \
        return (defaultErrorCode);                                               \
    }

#define XMP_CATCH_NO_RETURN()                                                    \
    } catch (const XMP_Error &error) {                                           \
        OHOS::Media::XMPHelper::LogXMPError(__func__, error);                    \
    } catch (...) {                                                              \
        IMAGE_LOGE("%{public}s unknown exception", __func__);                    \
    }

namespace OHOS {
namespace Media {
class XMPHelper {
public:
    static std::pair<std::string, std::string> SplitOnce(std::string_view path, std::string_view delim);
    static std::string Trim(std::string_view str, std::string_view trimChars);

    static std::string ExtractProperty(std::string_view pathExpression);
    static std::pair<std::string, std::string> ExtractSplitProperty(std::string_view pathExpression);

    static uint32_t MapXMPErrorToMediaError(const XMP_Error &error);
    static void LogXMPError(const char *funcName, const XMP_Error &error);
};
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_INNERKITS_UTILS_INCLUDE_XMP_HELPER_H