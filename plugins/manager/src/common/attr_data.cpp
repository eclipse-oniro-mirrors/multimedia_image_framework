/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "attr_data.h"
#include <cstdint>
#include <memory>
#include <utility>
#include <functional>
#include "__tree"
#include "cstdint"
#include "image_log.h"
#include "iosfwd"
#include "iterator"
#include "new"
#include "plugin_errors.h"
#ifndef _WIN32
#include "securec.h"
#else
#include "memory.h"
#endif
#include "set"
#include "string"
#include "type_traits"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "AttrData"

namespace OHOS {
namespace MultimediaPlugin {
using std::set;
using std::string;

AttrData::AttrData() : type_(AttrDataType::ATTR_DATA_NULL)
{}

AttrData::AttrData(bool value) : type_(AttrDataType::ATTR_DATA_BOOL)
{
    value_.boolValue = value;
}

AttrData::AttrData(uint32_t value) : type_(AttrDataType::ATTR_DATA_UINT32)
{
    value_.uint32Value = value;
}

AttrData::AttrData(const string &value) : type_(AttrDataType::ATTR_DATA_STRING)
{
    value_.stringValue = new (std::nothrow) string(value);
    if (value_.stringValue == nullptr) {
        IMAGE_LOGE("AttrData: alloc stringValue result null!");
        type_ = AttrDataType::ATTR_DATA_NULL;
    }
}

AttrData::AttrData(string &&value) : type_(AttrDataType::ATTR_DATA_STRING)
{
    value_.stringValue = new (std::nothrow) string(std::move(value));
    if (value_.stringValue == nullptr) {
        IMAGE_LOGE("AttrData: alloc stringValue result null!");
        type_ = AttrDataType::ATTR_DATA_NULL;
    }
}

AttrData::AttrData(uint32_t lowerBound, uint32_t upperBound) : type_(AttrDataType::ATTR_DATA_UINT32_RANGE)
{
    if (lowerBound > upperBound) {
        type_ = AttrDataType::ATTR_DATA_NULL;
    }

    value_.uint32Rang[LOWER_BOUND_INDEX] = lowerBound;
    value_.uint32Rang[UPPER_BOUND_INDEX] = upperBound;
}

AttrData::AttrData(const AttrData &data)
{
    switch (data.type_) {
        case AttrDataType::ATTR_DATA_BOOL: {
            value_.boolValue = data.value_.boolValue;
            type_ = AttrDataType::ATTR_DATA_BOOL;
            break;
        }
        case AttrDataType::ATTR_DATA_UINT32: {
            value_.uint32Value = data.value_.uint32Value;
            type_ = AttrDataType::ATTR_DATA_UINT32;
            break;
        }
        case AttrDataType::ATTR_DATA_STRING: {
            (void)InitStringAttrData(data);
            break;
        }
        case AttrDataType::ATTR_DATA_UINT32_SET: {
            (void)InitUint32SetAttrData(data);
            break;
        }
        case AttrDataType::ATTR_DATA_STRING_SET: {
            (void)InitStringSetAttrData(data);
            break;
        }
        case AttrDataType::ATTR_DATA_UINT32_RANGE: {
            value_.uint32Rang[LOWER_BOUND_INDEX] = data.value_.uint32Rang[LOWER_BOUND_INDEX];
            value_.uint32Rang[UPPER_BOUND_INDEX] = data.value_.uint32Rang[UPPER_BOUND_INDEX];
            type_ = AttrDataType::ATTR_DATA_UINT32_RANGE;
            break;
        }
        default: {
            IMAGE_LOGD("AttrData: null or unexpected type in copy constructor: %{public}d.", data.type_);
            type_ = AttrDataType::ATTR_DATA_NULL;
        }
    }
}

AttrData::AttrData(AttrData &&data) noexcept
{
    if (memcpy_s(&value_, sizeof(value_), &data.value_, sizeof(data.value_)) == EOK) {
        type_ = data.type_;
        data.type_ = AttrDataType::ATTR_DATA_NULL;
    } else {
        type_ = AttrDataType::ATTR_DATA_NULL;
        IMAGE_LOGE("memcpy error in assignment operator!");
    }
}

AttrData::~AttrData()
{
    ClearData();
}

AttrData &AttrData::operator=(const AttrData &data)
{
    // make a copy, avoid self-assignment problems.
    AttrData temp(data);
    ClearData();
    if (memcpy_s(&value_, sizeof(value_), &temp.value_, sizeof(temp.value_)) == 0) {
        type_ = temp.type_;
        temp.type_ = AttrDataType::ATTR_DATA_NULL;
    } else {
        type_ = AttrDataType::ATTR_DATA_NULL;
        IMAGE_LOGE("memcpy error in assignment operator!");
    }

    return *this;
}

AttrData &AttrData::operator=(AttrData &&data) noexcept
{
    // case if self-assignment.
    if (&data == this) {
        return *this;
    }

    ClearData();
    if (memcpy_s(&value_, sizeof(value_), &data.value_, sizeof(data.value_)) == EOK) {
        type_ = data.type_;
        data.type_ = AttrDataType::ATTR_DATA_NULL;
    } else {
        type_ = AttrDataType::ATTR_DATA_NULL;
        IMAGE_LOGE("memcpy error in assignment operator!");
    }

    return *this;
}

void AttrData::SetData(bool value)
{
    ClearData();
    value_.boolValue = value;
    type_ = AttrDataType::ATTR_DATA_BOOL;
}

void AttrData::SetData(uint32_t value)
{
    ClearData();
    value_.uint32Value = value;
    type_ = AttrDataType::ATTR_DATA_UINT32;
}

uint32_t AttrData::SetData(const string &value)
{
    if (type_ == AttrDataType::ATTR_DATA_STRING) {
        *(value_.stringValue) = value;
        return SUCCESS;
    }

    string *newValue = new (std::nothrow) string(value);
    if (newValue == nullptr) {
        IMAGE_LOGE("SetData: alloc string result null!");
        return ERR_INTERNAL;
    }

    ClearData();
    value_.stringValue = newValue;
    type_ = AttrDataType::ATTR_DATA_STRING;
    return SUCCESS;
}

uint32_t AttrData::SetData(string &&value)
{
    if (type_ == AttrDataType::ATTR_DATA_STRING) {
        *(value_.stringValue) = std::move(value);
        return SUCCESS;
    }

    string *newValue = new (std::nothrow) string(std::move(value));
    if (newValue == nullptr) {
        IMAGE_LOGE("SetData: alloc string result null!");
        return ERR_INTERNAL;
    }

    ClearData();
    value_.stringValue = newValue;
    type_ = AttrDataType::ATTR_DATA_STRING;
    return SUCCESS;
}

uint32_t AttrData::SetData(uint32_t lowerBound, uint32_t upperBound)
{
    if (lowerBound > upperBound) {
        IMAGE_LOGE("SetData: lowerBound is upper than upperBound, lower: %{public}u, upper: %{public}u.",
            lowerBound, upperBound);
        return ERR_INVALID_PARAMETER;
    }

    ClearData();
    value_.uint32Rang[LOWER_BOUND_INDEX] = lowerBound;
    value_.uint32Rang[UPPER_BOUND_INDEX] = upperBound;
    type_ = AttrDataType::ATTR_DATA_UINT32_RANGE;
    return SUCCESS;
}

void AttrData::ClearData()
{
    switch (type_) {
        case AttrDataType::ATTR_DATA_STRING: {
            if (value_.stringValue != nullptr) {
                delete value_.stringValue;
                value_.stringValue = nullptr;
            }
            break;
        }
        case AttrDataType::ATTR_DATA_UINT32_SET: {
            if (value_.uint32Set != nullptr) {
                delete value_.uint32Set;
                value_.uint32Set = nullptr;
            }
            break;
        }
        case AttrDataType::ATTR_DATA_STRING_SET: {
            if (value_.stringSet != nullptr) {
                delete value_.stringSet;
                value_.stringSet = nullptr;
            }
            break;
        }
        default: {
            // do nothing
            IMAGE_LOGD("ClearData: do nothing for type %{public}d.", type_);
            break;
        }
    }

    type_ = AttrDataType::ATTR_DATA_NULL;
}

uint32_t AttrData::InsertSet(uint32_t value)
{
    if (type_ == AttrDataType::ATTR_DATA_NULL) {
        value_.uint32Set = new (std::nothrow) set<uint32_t>({ value });
        if (value_.uint32Set == nullptr) {
            IMAGE_LOGE("InsertSet: alloc uint32Set result null!");
            return ERR_INTERNAL;
        }

        type_ = AttrDataType::ATTR_DATA_UINT32_SET;
        return SUCCESS;
    }

    if (type_ != AttrDataType::ATTR_DATA_UINT32_SET) {
        IMAGE_LOGE("InsertSet: AttrData type is not uint32Set or null, type: %{public}d.", type_);
        return ERR_UNSUPPORTED;
    }

    auto result = value_.uint32Set->insert(value);
    if (!result.second) {
        IMAGE_LOGE("InsertSet: set insert error!");
        return ERR_GENERAL;
    }

    return SUCCESS;
}

uint32_t AttrData::InsertSet(const string &value)
{
    if (type_ == AttrDataType::ATTR_DATA_NULL) {
        value_.stringSet = new (std::nothrow) set<string>({ value });
        if (value_.stringSet == nullptr) {
            IMAGE_LOGE("InsertSet: alloc stringSet result null!");
            return ERR_INTERNAL;
        }

        type_ = AttrDataType::ATTR_DATA_STRING_SET;
        return SUCCESS;
    }

    if (type_ != AttrDataType::ATTR_DATA_STRING_SET) {
        IMAGE_LOGE("InsertSet: AttrData type is not stringSet or null, type: %{public}d.", type_);
        return ERR_UNSUPPORTED;
    }

    auto result = value_.stringSet->insert(value);
    if (!result.second) {
        IMAGE_LOGE("InsertSet: set insert error!");
        return ERR_INTERNAL;
    }

    return SUCCESS;
}

uint32_t AttrData::InsertSet(string &&value)
{
    if (type_ == AttrDataType::ATTR_DATA_NULL) {
        value_.stringSet = new (std::nothrow) set<string>;
        if (value_.stringSet == nullptr) {
            IMAGE_LOGE("InsertSet: alloc stringSet result null!");
            return ERR_INTERNAL;
        }

        auto result = value_.stringSet->insert(std::move(value));
        if (!result.second) {
            delete value_.stringSet;
            value_.stringSet = nullptr;
            IMAGE_LOGE("InsertSet: set insert error!");
            return ERR_INTERNAL;
        }

        type_ = AttrDataType::ATTR_DATA_STRING_SET;
        return SUCCESS;
    }

    if (type_ != AttrDataType::ATTR_DATA_STRING_SET) {
        IMAGE_LOGE("InsertSet: AttrData type is not stringSet or null, type: %{public}d.", type_);
        return ERR_UNSUPPORTED;
    }

    auto result = value_.stringSet->insert(std::move(value));
    if (!result.second) {
        IMAGE_LOGE("InsertSet: set insert error!");
        return ERR_INTERNAL;
    }

    return SUCCESS;
}

bool AttrData::InRange(bool value) const
{
    if (type_ != AttrDataType::ATTR_DATA_BOOL) {
        IMAGE_LOGE("InRange: comparison of bool type with non-bool type: %{public}d.", type_);
        return false;
    }

    return value == value_.boolValue;
}

bool AttrData::InRange(uint32_t value) const
{
    switch (type_) {
        case AttrDataType::ATTR_DATA_UINT32: {
            return value == value_.uint32Value;
        }
        case AttrDataType::ATTR_DATA_UINT32_SET: {
            return value_.uint32Set->find(value) != value_.uint32Set->end();
        }
        case AttrDataType::ATTR_DATA_UINT32_RANGE: {
            return InRangeUint32Range(value);
        }
        default: {
            IMAGE_LOGE("InRange: comparison of uint32 type with non-uint32 type: %{public}d.", type_);
            return false;
        }
    }
}

bool AttrData::InRange(const string &value) const
{
    switch (type_) {
        case AttrDataType::ATTR_DATA_STRING: {
            return value == *(value_.stringValue);
        }
        case AttrDataType::ATTR_DATA_STRING_SET: {
            return value_.stringSet->find(value) != value_.stringSet->end();
        }
        default: {
            IMAGE_LOGE("InRange: comparison of string type with non-string type: %{public}d.", type_);
            return false;
        }
    }
}

bool AttrData::InRange(const AttrData &data) const
{
    switch (data.type_) {
        case AttrDataType::ATTR_DATA_NULL: {
            return type_ == AttrDataType::ATTR_DATA_NULL;
        }
        case AttrDataType::ATTR_DATA_BOOL: {
            return InRange(data.value_.boolValue);
        }
        case AttrDataType::ATTR_DATA_UINT32: {
            return InRange(data.value_.uint32Value);
        }
        case AttrDataType::ATTR_DATA_STRING: {
            return InRange(*(data.value_.stringValue));
        }
        case AttrDataType::ATTR_DATA_UINT32_SET: {
            return InRange(*(data.value_.uint32Set));
        }
        case AttrDataType::ATTR_DATA_STRING_SET: {
            return InRange(*(data.value_.stringSet));
        }
        case AttrDataType::ATTR_DATA_UINT32_RANGE: {
            return InRange(data.value_.uint32Rang);
        }
        default: {
            IMAGE_LOGE("InRange: unexpected AttrData type: %{public}d.", data.type_);
            return false;
        }
    }
}

AttrDataType AttrData::GetType() const
{
    return type_;
}

uint32_t AttrData::GetMinValue(uint32_t &value) const
{
    switch (type_) {
        case AttrDataType::ATTR_DATA_UINT32: {
            value = value_.uint32Value;
            return SUCCESS;
        }
        case AttrDataType::ATTR_DATA_UINT32_SET: {
            auto iter = value_.uint32Set->begin();
            if (iter == value_.uint32Set->end()) {
                IMAGE_LOGE("GetMinValue: uint32Set is empty.");
                return ERR_GENERAL;
            }
            value = *iter;
            return SUCCESS;
        }
        case AttrDataType::ATTR_DATA_UINT32_RANGE: {
            value = value_.uint32Rang[LOWER_BOUND_INDEX];
            return SUCCESS;
        }
        default: {
            IMAGE_LOGE("GetMinValue: invalid data type for uint32: %{public}d.", type_);
            return ERR_INVALID_PARAMETER;
        }
    }
}

uint32_t AttrData::GetMaxValue(uint32_t &value) const
{
    switch (type_) {
        case AttrDataType::ATTR_DATA_UINT32: {
            value = value_.uint32Value;
            return SUCCESS;
        }
        case AttrDataType::ATTR_DATA_UINT32_SET: {
            auto iter = value_.uint32Set->rbegin();
            if (iter == value_.uint32Set->rend()) {
                IMAGE_LOGE("GetMaxValue: GetMaxValue: uint32Set is empty.");
                return ERR_GENERAL;
            }

            value = *iter;
            return SUCCESS;
        }
        case AttrDataType::ATTR_DATA_UINT32_RANGE: {
            value = value_.uint32Rang[UPPER_BOUND_INDEX];
            return SUCCESS;
        }
        default: {
            IMAGE_LOGE("GetMaxValue: invalid data type for uint32: %{public}d.", type_);
            return ERR_INVALID_PARAMETER;
        }
    }
}

uint32_t AttrData::GetMinValue(const string *&value) const
{
    switch (type_) {
        case AttrDataType::ATTR_DATA_STRING: {
            value = value_.stringValue;
            return SUCCESS;
        }
        case AttrDataType::ATTR_DATA_STRING_SET: {
            auto iter = value_.stringSet->begin();
            if (iter == value_.stringSet->end()) {
                IMAGE_LOGE("GetMinValue: stringSet is empty.");
                return ERR_GENERAL;
            }

            value = (&(*iter));
            return SUCCESS;
        }
        default: {
            IMAGE_LOGE("GetMinValue: invalid data type for string: %{public}d.", type_);
            return ERR_INVALID_PARAMETER;
        }
    }
}

uint32_t AttrData::GetMaxValue(const string *&value) const
{
    switch (type_) {
        case AttrDataType::ATTR_DATA_STRING: {
            value = value_.stringValue;
            return SUCCESS;
        }
        case AttrDataType::ATTR_DATA_STRING_SET: {
            auto iter = value_.stringSet->rbegin();
            if (iter == value_.stringSet->rend()) {
                IMAGE_LOGE("GetMaxValue: stringSet is empty.");
                return ERR_GENERAL;
            }

            value = (&(*iter));
            return SUCCESS;
        }
        default: {
            IMAGE_LOGE("GetMaxValue: invalid data type for string: %{public}d.", type_);
            return ERR_INVALID_PARAMETER;
        }
    }
}

uint32_t AttrData::GetValue(bool &value) const
{
    if (type_ != AttrDataType::ATTR_DATA_BOOL) {
        IMAGE_LOGE("Get uint32 value: not a bool AttrData type: %{public}d.", type_);
        return ERR_INVALID_PARAMETER;
    }

    value = value_.boolValue;
    return SUCCESS;
}

uint32_t AttrData::GetValue(uint32_t &value) const
{
    if (type_ != AttrDataType::ATTR_DATA_UINT32) {
        IMAGE_LOGE("Get uint32 value: not a uint32 AttrData type: %{public}d.", type_);
        return ERR_INVALID_PARAMETER;
    }

    value = value_.uint32Value;
    return SUCCESS;
}

uint32_t AttrData::GetValue(string &value) const
{
    if (type_ != AttrDataType::ATTR_DATA_STRING) {
        IMAGE_LOGE("Get string value by reference: not a string AttrData type: %{public}d.", type_);
        return ERR_INVALID_PARAMETER;
    }

    value = *(value_.stringValue);
    return SUCCESS;
}

uint32_t AttrData::GetValue(const string *&value) const
{
    if (type_ != AttrDataType::ATTR_DATA_STRING) {
        IMAGE_LOGE("Get string value: not a string AttrData type: %{public}d.", type_);
        return ERR_INVALID_PARAMETER;
    }

    value = value_.stringValue;
    return SUCCESS;
}

// ------------------------------- private method -------------------------------
uint32_t AttrData::InitStringAttrData(const AttrData &data)
{
    value_.stringValue = new (std::nothrow) string(*(data.value_.stringValue));
    if (value_.stringValue == nullptr) {
        IMAGE_LOGE("InitStringAttrData: alloc stringValue result null!");
        type_ = AttrDataType::ATTR_DATA_NULL;
        return ERR_INTERNAL;
    }
    type_ = AttrDataType::ATTR_DATA_STRING;
    return SUCCESS;
}

uint32_t AttrData::InitUint32SetAttrData(const AttrData &data)
{
    value_.uint32Set = new (std::nothrow) set<uint32_t>(*(data.value_.uint32Set));
    if (value_.uint32Set == nullptr) {
        IMAGE_LOGE("InitUint32SetAttrData: alloc uint32Set result null!");
        type_ = AttrDataType::ATTR_DATA_NULL;
        return ERR_INTERNAL;
    }
    type_ = AttrDataType::ATTR_DATA_UINT32_SET;
    return SUCCESS;
}

uint32_t AttrData::InitStringSetAttrData(const AttrData &data)
{
    value_.stringSet = new (std::nothrow) set<string>(*(data.value_.stringSet));
    if (value_.stringSet == nullptr) {
        IMAGE_LOGE("InitStringSetAttrData: alloc stringSet result null!");
        type_ = AttrDataType::ATTR_DATA_NULL;
        return ERR_INTERNAL;
    }
    type_ = AttrDataType::ATTR_DATA_STRING_SET;
    return SUCCESS;
}

bool AttrData::InRangeUint32Range(uint32_t value) const
{
    return value >= value_.uint32Rang[LOWER_BOUND_INDEX] && value <= value_.uint32Rang[UPPER_BOUND_INDEX];
}

bool AttrData::InRange(const set<uint32_t> &uint32Set) const
{
    if (uint32Set.empty()) {
        return false;
    }

    for (uint32_t value : uint32Set) {
        if (!InRange(value)) {
            return false;
        }
    }

    return true;
}

bool AttrData::InRange(const set<string> &stringSet) const
{
    if (stringSet.empty()) {
        IMAGE_LOGD("InRange: empty set of parameter.");
        return false;
    }

    for (const string &value : stringSet) {
        if (!InRange(value)) {
            return false;
        }
    }

    return true;
}

bool AttrData::InRange(const uint32_t (&uint32Rang)[RANGE_ARRAY_SIZE]) const
{
    if (uint32Rang[LOWER_BOUND_INDEX] > uint32Rang[UPPER_BOUND_INDEX]) {
        return false;
    }

    switch (type_) {
        case AttrDataType::ATTR_DATA_UINT32: {
            return uint32Rang[LOWER_BOUND_INDEX] == uint32Rang[UPPER_BOUND_INDEX] &&
                   uint32Rang[UPPER_BOUND_INDEX] == value_.uint32Value;
        }
        case AttrDataType::ATTR_DATA_UINT32_SET: {
            auto lowerIter = value_.uint32Set->find(uint32Rang[LOWER_BOUND_INDEX]);
            if (lowerIter == value_.uint32Set->end()) {
                return false;
            }

            auto upperIter = value_.uint32Set->find(uint32Rang[UPPER_BOUND_INDEX]);
            if (upperIter == value_.uint32Set->end()) {
                return false;
            }

            uint32_t count = 0;
            for (auto tmpIter = lowerIter; tmpIter != upperIter; ++tmpIter) {
                count++;
            }

            if (count != (uint32Rang[UPPER_BOUND_INDEX] - uint32Rang[LOWER_BOUND_INDEX])) {
                return false;
            }

            return true;
        }
        case AttrDataType::ATTR_DATA_UINT32_RANGE: {
            return (uint32Rang[LOWER_BOUND_INDEX] >= value_.uint32Rang[LOWER_BOUND_INDEX]) &&
                   (uint32Rang[UPPER_BOUND_INDEX] <= value_.uint32Rang[UPPER_BOUND_INDEX]);
        }
        default: {
            return false;
        }
    }
}
} // namespace MultimediaPlugin
} // namespace OHOS
