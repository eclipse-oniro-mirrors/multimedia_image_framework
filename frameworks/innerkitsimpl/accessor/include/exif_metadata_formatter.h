/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_EXIF_METADATA_FORMATTER_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_EXIF_METADATA_FORMATTER_H

#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace Media {
struct TagDetails {
    int64_t val_;       // Tag value
    const char *label_;
}; // struct TagDetails

using ValueFormatDelegate = std::pair<std::function<int32_t (std::string&, const std::string&)>, std::string>;

class ExifMetadatFormatter {
public:
    static std::pair<int32_t, std::string> Format(const std::string &keyName, const std::string &value);
    static int32_t Validate(const std::string &keyName, const std::string &value);
    static bool IsModifyAllowed(const std::string &keyName);

private:
    static int32_t ValidateValueRange(const std::string &keyName, const std::string &value);
    static int32_t ConvertValueFormat(const std::string &keyName, std::string &value);
    static int32_t ValidateValueFormat(const std::string &keyName, const std::string &value);
    static bool IsKeySupported(const std::string &keyName);
    static bool IsFormatValidationConfigExisting(const std::string &keyName);
    static int Gcd(int a, int b)
    {
        if (b == 0) {
            return a;
        }
        return Gcd(b, a % b);
    }
    static bool IsValidValue(const TagDetails *array, const size_t &size, const int64_t &key);
    static bool ValidRegex(const std::string &value, const std::string &regex);
    static bool ValidRegexWithComma(std::string &value, const std::string &regex);
    static bool ValidRegexWithRationalFormat(std::string &value, const std::string &regex);
    static bool ValidRegexWithCommaRationalFormat(std::string &value, const std::string &regex);
    static bool ValidRegexWithColonRationalFormat(std::string &value, const std::string &regex);
    static bool ValidRegexWithDot(std::string &value, const std::string &regex);
    static bool ValidRegxWithCommaDecimalRationalFormat(std::string &value, const std::string &regex);
    static bool ValidRegexWithDecimalRationalFormat(std::string &value, const std::string &regex);
    static bool ValidRegexWithGpsOneRationalFormat(std::string &value, const std::string &regex);
    static void ReplaceAsSpace(std::string &value, const std::string &regex);
    static void ReplaceAsContent(std::string &value, const std::string &regex, const std::string &content);
    static void RationalFormat(std::string &value);
    static std::string GetFractionFromStr(const std::string &decimal);
    static void DecimalRationalFormat(std::string &value);
    static ValueFormatDelegate doubleIntToOneRationalWithComma;
    static ValueFormatDelegate doubleIntWithBlank;
    static ValueFormatDelegate doubleIntWithComma;
    static ValueFormatDelegate tribleIntWithBlank;
    static ValueFormatDelegate tribleIntWithComma;
    static ValueFormatDelegate fourIntWithBlank;
    static ValueFormatDelegate fourIntWithComma;
    static ValueFormatDelegate singleInt;
    static ValueFormatDelegate singleRational;
    static ValueFormatDelegate singleIntToRational;
    static ValueFormatDelegate singleDecimalToRational;
    static ValueFormatDelegate tribleRationalWithBlank;
    static ValueFormatDelegate tribleIntToRationalWithBlank;
    static ValueFormatDelegate tribleIntToRationalWithComma;
    static ValueFormatDelegate tribleDecimalToRationalWithBlank;
    static ValueFormatDelegate tribleDecimalToRatiionalWithComma;
    static ValueFormatDelegate tribleMixToRationalWithComma;
    static ValueFormatDelegate fourRationalWithBlank;
    static ValueFormatDelegate fourIntToRationalWithBlank;
    static ValueFormatDelegate fourIntToRationalWithComma;
    static ValueFormatDelegate decimal4Ratiional4;
    static ValueFormatDelegate fourDecimalToRationalWithComma;
    static ValueFormatDelegate dateTimeValidation;
    static ValueFormatDelegate dateValidation;
    static ValueFormatDelegate tribleIntToRationalWithColon;
    static ValueFormatDelegate fourIntWithDot;
    static ValueFormatDelegate fourDecimalToRationalWithBlank;
    static ValueFormatDelegate sixDecimalToRationalWithBlank;
    static std::multimap<std::string, ValueFormatDelegate> valueFormatConvertConfig;
    static std::multimap<std::string, std::string> valueFormatValidateConfig;
    static std::map<std::string, std::tuple<const TagDetails*, const size_t>> valueRangeValidateConfig;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_EXIF_METADATA_FORMATTER_H
