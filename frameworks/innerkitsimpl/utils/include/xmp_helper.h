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

#ifndef INTERFACES_INNERKITS_UTILS_INCLUDE_XMP_HELPER_H
#define INTERFACES_INNERKITS_UTILS_INCLUDE_XMP_HELPER_H

#include <string>
#include <utility>

namespace {
static const std::string WHITE_SPACE_STRING = " \t\r\n";
}

namespace OHOS {
namespace Media {
class XMPHelper {
public:
    static std::pair<std::string, std::string> SplitOnce(std::string_view path, std::string_view delim);
    static std::string ExtractProperty(const std::string &path);
    static std::pair<std::string, std::string> ExtractSplitProperty(const std::string &path);

    static std::string Trim(const std::string &str, const std::string &trimString = WHITE_SPACE_STRING);

private:
    static std::string ExtractLocalName(const std::string &name);
    static std::string ExtractQualifierFromSelector(const std::string &selector);
    static std::string ExtractLastPathComponent(const std::string &path);
};
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_INNERKITS_UTILS_INCLUDE_XMP_HELPER_H