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

#include "image_log.h"
#include "xmp_helper.h"

namespace {
constexpr std::string_view WHITE_SPACE_CHARS = " \t\r\n";
constexpr std::string_view COLON = ":";
constexpr std::string_view SELECTOR_XML_LANG_AT = "[@xml:lang=";
constexpr std::string_view SELECTOR_XML_LANG_Q = "[?xml:lang=";
constexpr std::string_view QUALIFIER_SELECTOR = "[?";
constexpr std::string_view PATH_QUALIFIER_Q = "/?";
constexpr std::string_view PATH_QUALIFIER_AT = "/@";
constexpr std::string_view PATH_XML_LANG_AT = "/@xml:lang";
constexpr std::string_view PATH_XML_LANG_Q = "/?xml:lang";
constexpr std::string_view XML_LANG = "xml:lang";
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

std::string XMPHelper::Trim(std::string_view str, std::string_view trimChars)
{
    size_t start = str.find_first_not_of(trimChars);
    if (start == std::string_view::npos) {
        return "";
    }

    size_t end = str.find_last_not_of(trimChars);
    return std::string(str.substr(start, end - start + 1));
}

/**
 * Check if the bracket content is a selector expression
 * Selector form:     [dc:source="network"], [?book:lastUpdated="2023"], [@xml:lang="en-US"]
 * Non-selector form: [1], [2], [last()]
 */
static bool IsSelectorExpression(std::string_view path, size_t bracketPos)
{
    size_t closeBracketPos = path.find(']', bracketPos);
    if (closeBracketPos == std::string_view::npos) {
        return false;
    }
    std::string_view bracketContent = path.substr(bracketPos + 1, closeBracketPos - bracketPos - 1);
    return bracketContent.find('=') != std::string_view::npos;
}

// Normalize array index path (single-pass optimization)
// dc:subject/[2] -> dc:subject[2]
// dc:subject*[2] -> dc:subject[2]
// dc:subject/*[2] -> dc:subject[2]
static std::string NormalizeArrayIndexPath(std::string_view path)
{
    std::string result;
    result.reserve(path.size());

    for (size_t i = 0; i < path.size(); ++i) {
        char c = path[i];
        // Check for patterns ending with '['
        if (c == '[') {
            // Remove trailing "/*", "/", or "*" before '['
            while (!result.empty()) {
                char last = result.back();
                if (last == '/' || last == '*') {
                    result.pop_back();
                } else {
                    break;
                }
            }
        }
        result.push_back(c);
    }
    return result;
}

// Property Extract Rule:
// | Path Expression Type       | Format Example                                 | Property          |
// | -------------------------- | ---------------------------------------------- | ----------------- |
// | Namespace Field            | dc:creator                                     | dc:creator        |
// | Array Index                | dc:subject[2], dc:subject/[2],                 | dc:subject        |
// |                            | dc:subject*[2], dc:subject/*[2]                |                   |
// | Array Last Item            | dc:subject[last()]                             | dc:subject        |
// | Structure Field            | exif:Flash/exif:Fired                          | exif:Fired        |
// | Qualifier(Path)            | dc:title[1]/?book:lastUpdated                  | book:lastUpdated  |
// | Qualifier(Selector)        | dc:title[?book:lastUpdated="2023"]             | dc:title          |
// | Localization Text(Path)    | dc:title[1]/@xml:lang, dc:title[1]/?xml:lang   | xml:lang          |
// | Localization Text(Selector)| dc:title[@xml:lang="en-US"]                    | dc:title          |
// | Structure Array(Selector)  | dc:subject[dc:source="network"]                | dc:subject        |
std::string XMPHelper::ExtractProperty(std::string_view pathExpression)
{
    CHECK_DEBUG_RETURN_RET_LOG(pathExpression.empty(), "", "%{public}s pathExpression is empty", __func__);

    std::string trimmed = Trim(pathExpression, WHITE_SPACE_CHARS);
    CHECK_DEBUG_RETURN_RET_LOG(trimmed.empty(), "", "%{public}s path is empty after trim", __func__);

    // Normalize array index path variant format
    std::string path = NormalizeArrayIndexPath(trimmed);

    // Case 1: 数组选择器形式 - 多语言文本: dc:title[@xml:lang="en-US"] 或 dc:title[?xml:lang="zh-CN"]
    // 返回数组元素本身 dc:title
    if (path.find(SELECTOR_XML_LANG_AT) != std::string::npos ||
        path.find(SELECTOR_XML_LANG_Q) != std::string::npos) {
        size_t bracketPos = path.find('[');
        if (bracketPos != std::string::npos) {
            return path.substr(0, bracketPos);
        }
    }

    // Case 2: 数组选择器形式 - 限定符选择器: dc:title[?book:lastUpdated="2023"]
    // 返回数组元素本身 dc:title
    if (path.find(QUALIFIER_SELECTOR) != std::string::npos) {
        size_t bracketPos = path.find('[');
        if (bracketPos != std::string::npos && IsSelectorExpression(path, bracketPos)) {
            return path.substr(0, bracketPos);
        }
    }

    // Case 3: 数组选择器形式 - 字段选择器: dc:subject[dc:source="network"]
    // 返回数组元素本身 dc:subject
    size_t bracketPos = path.find('[');
    if (bracketPos != std::string::npos && IsSelectorExpression(path, bracketPos)) {
        // 确保不是路径分隔符形式的限定符访问（如 dc:title[1]/?book:xxx）
        if (path.find(PATH_QUALIFIER_Q) == std::string::npos &&
            path.find(PATH_QUALIFIER_AT) == std::string::npos) {
            return path.substr(0, bracketPos);
        }
    }

    // Case 4: 路径分隔符形式 - 多语言文本: dc:title[1]/@xml:lang 或 dc:title[1]/?xml:lang
    // 返回限定符 xml:lang
    if (path.find(PATH_XML_LANG_AT) != std::string::npos ||
        path.find(PATH_XML_LANG_Q) != std::string::npos) {
        return std::string(XML_LANG);
    }

    // Case 5: 路径分隔符形式 - 限定符: dc:title[1]/?book:lastUpdated
    // 返回限定符 book:lastUpdated
    size_t qualifierPos = path.find(PATH_QUALIFIER_Q);
    if (qualifierPos != std::string::npos) {
        return path.substr(qualifierPos + PATH_QUALIFIER_Q.size());
    }

    // Case 6: 结构体字段或深层嵌套路径: exif:Flash/exif:Fired, dc:first[1]/dc:second[1]/dc:third[1]
    // 返回最后一个字段（移除数组索引）: exif:Fired, dc:third
    size_t lastSlashPos = path.find_last_of('/');
    if (lastSlashPos != std::string::npos && lastSlashPos < path.length() - 1) {
        std::string_view lastComponent(path.data() + lastSlashPos + 1, path.length() - lastSlashPos - 1);
        // 移除数组索引: dc:third[1] -> dc:third
        size_t compBracketPos = lastComponent.find('[');
        if (compBracketPos != std::string_view::npos) {
            return std::string(lastComponent.substr(0, compBracketPos));
        }
        return std::string(lastComponent);
    }

    // Case 7: 数组索引（无路径分隔符）: dc:subject[2], dc:subject[last()]
    // 返回数组名 dc:subject
    bracketPos = path.find('[');
    if (bracketPos != std::string::npos) {
        return path.substr(0, bracketPos);
    }

    // Case 8: 命名空间字段: dc:creator
    // 返回原路径 dc:creator
    return path;
}

std::pair<std::string, std::string> XMPHelper::ExtractSplitProperty(std::string_view pathExpression)
{
    std::string property = ExtractProperty(pathExpression);
    CHECK_ERROR_RETURN_RET_LOG(property.empty(), {}, "%{public}s extract property failed", __func__);
    return SplitOnce(property, COLON); 
}
} // namespace Media
} // namespace OHOS