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
#include "media_errors.h"
#include "XMP_Const.h"
#include "xmp_helper.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "XMPHelper"

namespace {
constexpr size_t NUM_1 = 1;
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

/**
 * @brief Split the string once
 * @param path: the string to be split
 * @param delim: the delimiter to split
 * @return: the split string
 */
std::pair<std::string, std::string> XMPHelper::SplitOnce(std::string_view path, std::string_view delim)
{
    CHECK_ERROR_RETURN_RET_LOG(path.empty() || delim.empty(), {}, "%{public}s path or delim is empty", __func__);

    size_t delimPos = path.find(delim);
    CHECK_ERROR_RETURN_RET_LOG(delimPos == std::string_view::npos, {}, "%{public}s path is invalid", __func__);

    return {
        std::string(path.substr(0, delimPos)),
        std::string(path.substr(delimPos + delim.size()))
    };
}

/**
 * @brief Trim the characters in the string (only support trimming single character)
 * @param str: the string to be trimmed
 * @param trimChars: the characters to trim
 * @return: the trimmed string
 */
std::string XMPHelper::Trim(std::string_view str, std::string_view trimChars)
{
    CHECK_ERROR_RETURN_RET_LOG(str.empty() || trimChars.empty(), "", "%{public}s str or trimChars is empty", __func__);

    size_t start = str.find_first_not_of(trimChars);
    if (start == std::string_view::npos) {
        return "";
    }

    size_t end = str.find_last_not_of(trimChars);
    return std::string(str.substr(start, end - start + NUM_1));
}

uint32_t XMPHelper::MapXMPErrorToMediaError(const XMP_Error &error)
{
    XMP_Int32 id = error.GetID();
    switch (id) {
        case kXMPErr_BadParam:
        case kXMPErr_BadValue:
            return ERR_IMAGE_INVALID_PARAMETER;
        case kXMPErr_Unimplemented:
            return ERR_MEDIA_UNSUPPORT_OPERATION;
        default:
            return ERR_XMP_DECODE_FAILED;
    }
}

void XMPHelper::LogXMPError(const char *funcName, const XMP_Error &error)
{
    const char *msg = error.GetErrMsg();
    if (msg == nullptr) {
        msg = "";
    }
    IMAGE_LOGE("%{public}s XMP exception, id=%{public}d, msg=%{public}s", funcName,
        static_cast<int32_t>(error.GetID()), msg);
}

/**
 * @brief Check if the bracket content is a selector expression
 * Selector form:     [dc:source="network"], [?book:lastUpdated="2023"], [@xml:lang="en-US"]
 * Non-selector form: [1], [2], [last()]
 */
static bool IsSelectorExpression(std::string_view path, size_t bracketPos)
{
    size_t closeBracketPos = path.find(']', bracketPos);
    if (closeBracketPos == std::string_view::npos) {
        return false;
    }
    std::string_view bracketContent = path.substr(bracketPos + NUM_1, closeBracketPos - bracketPos - NUM_1);
    return bracketContent.find('=') != std::string_view::npos;
}

// Normalize array index path (single-pass optimization)
// dc:subject/[2] -> dc:subject[2]
// dc:subject*[2] -> dc:subject[2]
// dc:subject/*[2] -> dc:subject[2]
static void NormalizeArrayIndexPath(std::string &path)
{
    if (path.find('[') == std::string::npos) {
        return;
    }

    size_t writePos = 0;
    bool inBracket = false;
    for (size_t i = 0; i < path.size(); ++i) {
        char c = path[i];
        if (c == '[') {
            // Remove trailing "/*", "/", or "*" before '['
            while (writePos > 0) {
                char prev = path[writePos - NUM_1];
                if (prev == '/' || prev == '*') {
                    writePos--;
                } else {
                    break;
                }
            }
            inBracket = true;
        } else if (c == ']') {
            inBracket = false;
        }
        path[writePos++] = c;
    }
    path.resize(writePos);
}

// Property Extract Rule:
// | -------------------------- | ---------------------------------------------- | ----------------- |
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
// | -------------------------- | ---------------------------------------------- | ----------------- |
std::string XMPHelper::ExtractProperty(std::string_view pathExpression)
{
    CHECK_DEBUG_RETURN_RET_LOG(pathExpression.empty(), "", "%{public}s pathExpression is empty", __func__);

    std::string trimmed = Trim(pathExpression, WHITE_SPACE_CHARS);
    CHECK_DEBUG_RETURN_RET_LOG(trimmed.empty(), "", "%{public}s path is empty after trim", __func__);

    // Normalize array index path variant format
    NormalizeArrayIndexPath(trimmed);
    std::string_view path = trimmed;

    // Case 0: Namespace Field: xmp:CreatorTool (Without '[' and '/')
    // Return local name: xmp:CreatorTool
    if (path.find('[') == std::string_view::npos && path.find('/') == std::string_view::npos) {
        return std::string(path);
    }

    // Combined Case 1/2/3: All selector expressions
    // Case 1: Localization Text(Selector): dc:title[@xml:lang="en-US"] OR dc:title[?xml:lang="zh-CN"]
    // Case 2: Qualifier(Selector):         dc:title[?book:lastUpdated="2023"]
    // Case 3: Structure Array(Selector):   dc:subject[dc:source="network"]
    // Returns the array name: the part before the opening bracket (e.g., dc:subject)
    size_t bracketPos = path.rfind('[');
    if (bracketPos != std::string_view::npos && IsSelectorExpression(path, bracketPos)) {
        // Ensure it is not a path separator form qualifier access (e.g., dc:subject[dc:source="network"]/?book:lastUpdated)
        if (path.find(PATH_QUALIFIER_Q) == std::string_view::npos &&
            path.find(PATH_QUALIFIER_AT) == std::string_view::npos) {
            std::string_view prefix = path.substr(0, bracketPos);
            size_t lastSlashPos = prefix.rfind('/');
            if (lastSlashPos != std::string_view::npos) {
                return std::string(prefix.substr(lastSlashPos + NUM_1));
            }
            return std::string(prefix);
        }
    }

    // Case 4: Localization Text(Path): dc:title[1]/@xml:lang OR dc:title[1]/?xml:lang
    // Return qualifier: xml:lang
    if (path.find(PATH_XML_LANG_AT) != std::string_view::npos ||
        path.find(PATH_XML_LANG_Q) != std::string_view::npos) {
        return std::string(XML_LANG);
    }

    // Case 5: Qualifier(Path): dc:title[1]/?book:lastUpdated
    // Return qualifier: book:lastUpdated
    size_t qualifierPos = path.find(PATH_QUALIFIER_Q);
    if (qualifierPos != std::string_view::npos) {
        return std::string(path.substr(qualifierPos + PATH_QUALIFIER_Q.size()));
    }

    // Case 6: Structure Field or Deep Nested Path: exif:Flash/exif:Fired, dc:first[1]/dc:second[1]/dc:third[1]
    // Return last field (remove array index): exif:Fired, dc:third
    size_t lastSlashPos = path.rfind('/');
    if (lastSlashPos != std::string_view::npos && lastSlashPos < path.size() - NUM_1) {
        std::string_view lastComponent(path.data() + lastSlashPos + NUM_1, path.size() - lastSlashPos - NUM_1);
        // Remove array index: dc:third[1] -> dc:third
        size_t compBracketPos = lastComponent.find('[');
        if (compBracketPos != std::string_view::npos) {
            return std::string(lastComponent.substr(0, compBracketPos));
        }
        return std::string(lastComponent);
    }

    // Case 7: Array Index (no path separator): dc:subject[2], dc:subject[last()], dc:subject[2][3]
    // Return array name: dc:subject
    bracketPos = path.find('[');
    if (bracketPos != std::string_view::npos) {
        return std::string(path.substr(0, bracketPos));
    }

    // Case 8: Unknown case - return empty string
    IMAGE_LOGD("%{public}s: Unknown case for path: %{public}s", __func__, trimmed.c_str());
    return "";
}

/**
 * @brief Extract the property from the path expression
 * @param pathExpression: the path expression to extract the property from
 * @return: the extracted property: {Namespace, PropertyKey}
 */
std::pair<std::string, std::string> XMPHelper::ExtractSplitProperty(std::string_view pathExpression)
{
    std::string property = ExtractProperty(pathExpression);
    CHECK_ERROR_RETURN_RET_LOG(property.empty(), {}, "%{public}s extract property failed", __func__);
    return SplitOnce(property, COLON);
}
} // namespace Media
} // namespace OHOS