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

#include <regex>

#include "image_log.h"
#include "xmp_helper.h"

namespace {
static const char *COLON = ":";
static const std::string KEY_LANG = "lang";
static const int NEXT_COLON_POS = 1;
}

namespace OHOS {
namespace Media {

std::pair<std::string, std::string> XMPHelper::SplitPrefixPath(const std::string &path)
{
    std::pair<std::string, std::string> result;
    CHECK_ERROR_RETURN_RET_LOG(path.empty(), result, "%{public}s path is empty", __func__);

    size_t colonPos = path.find_first_of(COLON);
    CHECK_ERROR_RETURN_RET_LOG(colonPos == std::string::npos, result, "%{public}s path is invalid", __func__);

    result.first = path.substr(0, colonPos);
    result.second = path.substr(colonPos + NEXT_COLON_POS);
    return result;
}

std::string XMPHelper::Trim(const std::string &str, const std::string &whiteSpaceString)
{
    size_t start = str.find_first_not_of(whiteSpaceString);
    if (start == std::string::npos) return "";
    
    size_t end = str.find_last_not_of(whiteSpaceString);
    return str.substr(start, end - start + 1);
}

std::string XMPHelper::ExtractLocalName(const std::string &qualifiedName)
{
    size_t colonPos = qualifiedName.find(':');
    if (colonPos != std::string::npos) {
        if (colonPos < qualifiedName.length() - 1) {
            return qualifiedName.substr(colonPos + 1);
        } else {
            // 对于 "ns:" 这种情况，返回空字符串
            return "";
        }
    }
    return qualifiedName;
}

/**
 * 从选择器中提取限定符名称
 * 例如: "[?xml:lang=\"zh-CN\"]" → "lang"
 * 例如: "[?book:lastUpdated=\"2023\"]" → "lastUpdated"
 */
std::string XMPHelper::ExtractQualifierFromSelector(const std::string &selector)
{
    // 查找 [? 开始
    size_t start = selector.find("[?");
    if (start == std::string::npos) return "";
    
    start += 2; // 跳过 "[?"
    
    // 查找 = 或 ] 结束
    size_t end = selector.find_first_of("=]", start);
    if (end == std::string::npos) return "";
    
    std::string qualifier = selector.substr(start, end - start);
    qualifier = Trim(qualifier);
    
    // 提取本地名称
    return ExtractLocalName(qualifier);
}

/**
 * 从路径中提取最后一个组件
 * 例如: "exif:Flash/exif:Fired" → "exif:Fired"
 */
std::string XMPHelper::ExtractLastPathComponent(const std::string &path)
{
    size_t lastSlash = path.find_last_of('/');
    if (lastSlash != std::string::npos && lastSlash < path.length() - 1) {
        return path.substr(lastSlash + 1);
    }
    return path;
}

std::string XMPHelper::ExtractPropertyKey(const std::string &pathExpression)
{
    CHECK_DEBUG_RETURN_RET_LOG(pathExpression.empty(), "", "%{public}s pathExpression is empty", __func__);

    std::string path = Trim(pathExpression);
    CHECK_DEBUG_RETURN_RET_LOG(path.empty(), "", "%{public}s path is empty after trim", __func__);

    // 处理 [@xml:lang="value"] 选择器: dc:title[@xml:lang="zh-CN"] → lang
    if (path.find("[@xml:lang=") != std::string::npos) {
        return KEY_LANG;
    }
    
    // 处理 [?xml:lang="value"] 选择器: dc:title[?xml:lang="zh-CN"] → lang
    if (path.find("[?xml:lang=") != std::string::npos) {
        return KEY_LANG;
    }

    // 处理其他限定符选择器: dc:title[?book:lastUpdated="2023"] → lastUpdated
    if (path.find("[?") != std::string::npos) {
        size_t selectorStart = path.find("[?");
        size_t selectorEnd = path.find(']', selectorStart);
        if (selectorEnd != std::string::npos) {
            std::string selector = path.substr(selectorStart, selectorEnd - selectorStart + 1);
            std::string qualifierKey = ExtractQualifierFromSelector(selector);
            if (!qualifierKey.empty()) {
                return qualifierKey;
            }
        }
    }

    // 处理 @xml:lang 限定符: QualProp2/@xml:lang → lang
    if (path.find("/@xml:lang") != std::string::npos) {
        return KEY_LANG;
    }

    // 处理XML语言限定符: dc:title[1]/?xml:lang → lang
    if (path.find("/?xml:lang") != std::string::npos) {
        return KEY_LANG;
    }

    // 处理一般限定符: dc:title/?book:lastUpdated → lastUpdated
    if (path.find("/?") != std::string::npos) {
        size_t qualifierStart = path.find("/?");
        if (qualifierStart != std::string::npos) {
            std::string qualifier = path.substr(qualifierStart + 2);
            return ExtractLocalName(qualifier);
        }
    }

    // 对于结构体路径，需要先找到最后一个路径组件，再移除数组索引
    // 例如: xmp:Thumbnails[1]/xmp:Format → xmp:Format
    std::string lastComponent = ExtractLastPathComponent(path);

    // 移除数组索引: dc:subject[2] → dc:subject
    size_t bracketPos = lastComponent.find('[');
    if (bracketPos != std::string::npos) {
        lastComponent = lastComponent.substr(0, bracketPos);
    }

    // 提取本地名称: exif:Fired → Fired
    std::string localName = ExtractLocalName(lastComponent);

    // 处理边界情况：如果提取后为空或者包含特殊字符，返回原始处理后的结果
    if (localName.empty() && !lastComponent.empty()) {
        // 对于 "ns:" 这种情况，返回空字符串
        if (lastComponent.back() == ':') {
            return "";
        }
        // 对于其他情况，返回清理后的结果
        std::string cleaned = lastComponent;
        // 移除末尾的特殊字符
        while (!cleaned.empty() && (cleaned.back() == '/' || cleaned.back() == ']')) {
            cleaned.pop_back();
        }
        return cleaned;
    }

    // 对于包含特殊字符的情况，进行清理
    if (!localName.empty()) {
        std::string cleaned = localName;
        // 移除末尾的特殊字符
        while (!cleaned.empty() && (cleaned.back() == '/' || cleaned.back() == ']')) {
            cleaned.pop_back();
        }
        return cleaned;
    }
    return localName;
}

} // namespace Media
} // namespace OHOS