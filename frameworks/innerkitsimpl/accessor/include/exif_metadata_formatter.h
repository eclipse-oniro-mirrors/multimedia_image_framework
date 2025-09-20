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
    static ExifMetadatFormatter &GetInstance();

    static std::pair<int32_t, std::string> Format(const std::string &keyName, const std::string &value);
    static int32_t Validate(const std::string &keyName, const std::string &value);
    static bool IsModifyAllowed(const std::string &keyName);
    static bool IsKeySupported(const std::string &keyName);
    static const std::set<std::string> &GetRWKeys();
    static const std::set<std::string> &GetROKeys();
    static bool IsSensitiveInfo(const std::string &keyName);

private:
    ExifMetadatFormatter();
    void InitDelegates();
    void InitValueRangeValidateConfig();
    void InitValueFormatConvertConfig();
    void InitValueTemplateConfig();

    static int32_t ValidateValueRange(const std::string &keyName, const std::string &value);
    static void ConvertRangeValue(const std::string &keyName, std::string &value);
    static void ExtractValue(const std::string &keyName, std::string &value);
    static int32_t ConvertValueFormat(const std::string &keyName, std::string &value);
    static int32_t ValidateValueFormat(const std::string &keyName, const std::string &value);
    static bool IsFormatValidationConfigExisting(const std::string &keyName);
    static bool IsForbiddenValue(const std::string &value);
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
    static bool ValidRegexWithVersionFormat(std::string &value, const std::string &regex);
    static bool ValidRegxAndConvertRationalFormat(std::string &value, const std::string &regex);
    static bool ValidRegexWithDecimalRationalFormat(std::string &value, const std::string &regex);
    static bool ValidRegexWithGpsOneRationalFormat(std::string &value, const std::string &regex);
    static bool ValidRegexWithChannelFormat(std::string &value, const std::string &regex);
    static void ReplaceAsSpace(std::string &value, const std::string &regex);
    static void ReplaceAsContent(std::string &value, const std::string &regex, const std::string &content);
    static void RationalFormat(std::string &value);
    static std::string GetFractionFromStr(const std::string &decimal, bool &isOutRange);
    static bool ValidDecimalRationalFormat(std::string &value);
    static bool ValidConvertRationalFormat(std::string &value);
    ValueFormatDelegate doubleIntToOneRationalWithComma_;
    ValueFormatDelegate doubleIntWithBlank_;
    ValueFormatDelegate doubleIntWithComma_;
    ValueFormatDelegate doubleValueToRational_;
    ValueFormatDelegate tribleIntWithBlank_;
    ValueFormatDelegate tribleIntWithComma_;
    ValueFormatDelegate fourIntWithBlank_;
    ValueFormatDelegate fourIntWithComma_;
    ValueFormatDelegate singleInt_;
    ValueFormatDelegate singleRational_;
    ValueFormatDelegate singleIntToRational_;
    ValueFormatDelegate singleDecimalToRational_;
    ValueFormatDelegate tribleRationalWithBlank_;
    ValueFormatDelegate tribleIntToRationalWithBlank_;
    ValueFormatDelegate tribleIntToRationalWithComma_;
    ValueFormatDelegate tribleDecimalToRationalWithBlank_;
    ValueFormatDelegate tribleDecimalToRatiionalWithComma_;
    ValueFormatDelegate tribleMixToRationalWithComma_;
    ValueFormatDelegate fourRationalWithBlank_;
    ValueFormatDelegate fourIntToRationalWithBlank_;
    ValueFormatDelegate fourIntToRationalWithComma_;
    ValueFormatDelegate decimal4Ratiional4_;
    ValueFormatDelegate fourDecimalToRationalWithComma_;
    ValueFormatDelegate dateTimeValidation_;
    ValueFormatDelegate dateValidation_;
    ValueFormatDelegate tribleIntToRationalWithColon_;
    ValueFormatDelegate fourIntWithDot_;
    ValueFormatDelegate fourDecimalToRationalWithBlank_;
    ValueFormatDelegate sixDecimalToRationalWithBlank_;
    ValueFormatDelegate sixDecimalToRationalWithComma_;
    ValueFormatDelegate timeStamp_;
    ValueFormatDelegate version_;
    ValueFormatDelegate channel_;
    std::multimap<std::string, ValueFormatDelegate> valueFormatConvertConfig_;
    std::multimap<std::string, std::string> valueFormatValidateConfig_;
    std::multimap<std::string, std::string> valueTemplateConfig_;
    std::map<std::string, std::tuple<const TagDetails*, const size_t>> valueRangeValidateConfig_;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_EXIF_METADATA_FORMATTER_H
