/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <string>
#include <vector>

namespace OHOS {
/**
 * The IsNumericStr function judge all characters of the string are numbers,
 * return true if all are numbers, else false.
 */
bool IsNumericStr(const std::string& str);

/**
 * The TrimStr function will trim str by cTrim front and end.
 */
std::string TrimStr(const std::string& str, const char cTrim = ' ');

/**
 * The UpperStr function convert all letters of str to uppercase.
 */
std::string UpperStr(const std::string& str);

/**
 * The SplitStr function will split str by strSep.
 */
void SplitStr(const std::string& str, const std::string& sep, std::vector<std::string>& strs,
              bool canEmpty = false, bool needTrim = true);

/**
 * The IsSameTextStr function judge the first's letter is same with second,
 * return true if same, else false.
 */
bool IsSameTextStr(const std::string& first, const std::string& second);
}
