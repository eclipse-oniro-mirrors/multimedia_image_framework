/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "string_ex.h"
using namespace std;

namespace OHOS {
bool IsNumericStr(const string& str)
{
    if (str.empty()) {
        return false;
    }

    for (const auto& c : str) {
        if (!isdigit(c)) {
            return false;
        }
    }
    return true;
}

string TrimStr(const string& str, const char cTrim)
{
    string strTmp = str;
    strTmp.erase(0, strTmp.find_first_not_of(cTrim));
    strTmp.erase(strTmp.find_last_not_of(cTrim) + sizeof(char));
    return strTmp;
}

string UpperStr(const string& str)
{
    string upperString = str;
    transform(upperString.begin(), upperString.end(), upperString.begin(), ::toupper);
    return upperString;
}

bool IsSameTextStr(const string& first, const string& second)
{
    return UpperStr(first) == UpperStr(second);
}

void SplitStr(const string& str, const string& sep, vector<string>& strs, bool canEmpty, bool needTrim)
{
    strs.clear();
    string strTmp = needTrim ? TrimStr(str) : str;
    string strPart;
    while (true) {
        string::size_type pos = strTmp.find(sep);
        if (string::npos == pos || sep.empty()) {
            strPart = needTrim ? TrimStr(strTmp) : strTmp;
            if (!strPart.empty() || canEmpty) {
                strs.push_back(strPart);
            }
            break;
        } else {
            strPart = needTrim ? TrimStr(strTmp.substr(0, pos)) : strTmp.substr(0, pos);
            if (!strPart.empty() || canEmpty) {
                strs.push_back(strPart);
            }
            strTmp = strTmp.substr(sep.size() + pos, strTmp.size() - sep.size() - pos);
        }
    }
}
}