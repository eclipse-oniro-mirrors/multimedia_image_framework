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
}

namespace OHOS {
namespace Media {

std::pair<std::string, std::string> XMPHelper::SplitOnce(std::string_view path, std::string_view delim)
{
    CHECK_ERROR_RETURN_RET_LOG(path.empty(), {}, "%{public}s path is empty", __func__);

    size_t delimPos = path.find(delim);
    CHECK_ERROR_RETURN_RET_LOG(delimPos == std::string_view::npos, {}, "%{public}s path is invalid", __func__);

    return {
        std::string(path.substr(0, delimPos)),
        std::string(path.substr(delimPos + delim.size()))
    };
}

std::string XMPHelper::Trim(const std::string &str, const std::string &trimString)
{
    size_t start = str.find_first_not_of(trimString);
    if (start == std::string::npos) {
        return "";
    }

    size_t end = str.find_last_not_of(trimString);
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
    if (start == std::string::npos) {
        return "";
    }

    start += 2; // 跳过 "[?"

    // 查找 = 或 ] 结束
    size_t end = selector.find_first_of("=]", start);
    if (end == std::string::npos) {
        return "";
    }

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

std::string XMPHelper::ExtractProperty(const std::string &pathExpression)
{
    CHECK_DEBUG_RETURN_RET_LOG(pathExpression.empty(), "", "%{public}s pathExpression is empty", __func__);

    std::string path = Trim(pathExpression);
    CHECK_DEBUG_RETURN_RET_LOG(path.empty(), "", "%{public}s path is empty after trim", __func__);

    // Case 1: 数组选择器形式 - 多语言文本: dc:title[@xml:lang="en-US"] 或 dc:title[?xml:lang="zh-CN"]
    // 返回数组元素本身 dc:title
    if (path.find("[@xml:lang=") != std::string::npos || path.find("[?xml:lang=") != std::string::npos) {
        size_t bracketPos = path.find('[');
        if (bracketPos != std::string::npos) {
            return path.substr(0, bracketPos);
        }
    }

    // Case 2: 数组选择器形式 - 限定符: dc:title[?book:lastUpdated="2023"]
    // 返回数组元素本身 dc:title
    if (path.find("[?") != std::string::npos) {
        size_t bracketPos = path.find('[');
        size_t equalPos = path.find('=', bracketPos);
        // 确保是选择器形式 (包含 =)，而非纯数组索引
        if (bracketPos != std::string::npos && equalPos != std::string::npos) {
            return path.substr(0, bracketPos);
        }
    }

    // Case 3: 路径分隔符形式 - 多语言文本: dc:title[1]/@xml:lang 或 dc:title[1]/?xml:lang
    // 返回限定符 xml:lang
    size_t atXmlLangPos = path.find("/@xml:lang");
    if (atXmlLangPos != std::string::npos) {
        return "xml:lang";
    }
    size_t qXmlLangPos = path.find("/?xml:lang");
    if (qXmlLangPos != std::string::npos) {
        return "xml:lang";
    }

    // Case 4: 路径分隔符形式 - 限定符: dc:title[1]/?book:lastUpdated
    // 返回限定符 book:lastUpdated
    size_t qualifierPos = path.find("/?");
    if (qualifierPos != std::string::npos) {
        return path.substr(qualifierPos + 2);
    }

    // Case 5: 结构体字段或深层嵌套路径: exif:Flash/exif:Fired, dc:first[1]/dc:second[1]/dc:third[1]
    // 返回最后一个字段（移除数组索引）: exif:Fired, dc:third
    size_t lastSlashPos = path.find_last_of('/');
    if (lastSlashPos != std::string::npos && lastSlashPos < path.length() - 1) {
        std::string lastComponent = path.substr(lastSlashPos + 1);
        // 移除数组索引: dc:third[1] -> dc:third
        size_t bracketPos = lastComponent.find('[');
        if (bracketPos != std::string::npos) {
            return lastComponent.substr(0, bracketPos);
        }
        return lastComponent;
    }

    // Case 6: 数组索引（无路径分隔符）: dc:subject[2]
    // 返回数组名 dc:subject
    size_t bracketPos = path.find('[');
    if (bracketPos != std::string::npos) {
        return path.substr(0, bracketPos);
    }

    // Case 7: 命名空间字段: dc:creator
    // 返回原路径 dc:creator
    return path;
}

std::pair<std::string, std::string> XMPHelper::ExtractSplitProperty(const std::string &pathExpression)
{
    std::string property = ExtractProperty(pathExpression);
    CHECK_ERROR_RETURN_RET_LOG(property.empty(), {}, "%{public}s extract property failed", __func__);
    return SplitOnce(property, COLON); 
}
} // namespace Media
} // namespace OHOS