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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_ERROR_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_ERROR_H

namespace OHOS {
namespace ImagePlugin {
enum heif_error {
    heif_error_ok = 0,
    heif_error_eof = 1,
    heif_error_no_ftyp = 2,
    heif_error_no_idat = 3,
    heif_error_no_meta = 4,
    heif_error_no_hvcc = 5,
    heif_error_no_pitm = 6,
    heif_error_no_ipco = 7,
    heif_error_no_ipma = 8,
    heif_error_no_iloc = 9,
    heif_error_no_iinf = 10,
    heif_error_no_iprp = 11,
    heif_error_invalid_box_size = 12,
    heif_error_invalid_handler = 13,
    heif_error_item_not_found = 14,
    heif_error_item_data_not_found = 15,
    heif_error_primary_item_not_found = 16,
    heif_error_property_not_found = 17,
    heif_error_invalid_property_index = 18,
    heif_error_invalid_color_profile = 19,
    heif_invalid_exif_data = 20,
    heif_invalid_mirror_direction = 21,
    heif_error_grid_too_large = 22,
    heif_error_too_many_item = 23,
    heif_error_too_many_recursion = 24,
    heif_error_no_data = 25,
    heif_error_extent_num_too_large = 26,
    heif_error_no_trak = 27,
    heif_error_no_tkhd = 28,
    heif_error_no_mdia = 29,
    heif_error_no_mdhd = 30,
    heif_error_no_hdlr = 31,
    heif_error_no_minf = 32,
    heif_error_no_vmhd = 33,
    heif_error_no_dinf = 34,
    heif_error_no_stbl = 35,
    heif_error_no_dref = 36,
    heif_error_no_stsd = 37,
    heif_error_no_stts = 38,
    heif_error_no_stsc = 39,
    heif_error_no_stco = 40,
    heif_error_no_stsz = 41,
    heif_error_no_mvhd = 42,
    heif_error_invalid_index = 43,
    heif_error_invalid_major_brand = 44,
    heif_error_not_heifs = 45,
    heif_error_invalid_stsz = 46,
    heif_error_invalid_stts = 47,
    heif_error_no_stss = 48,
    heif_error_invalid_stss = 49,
    heif_error_invalid_dref = 50,
    heif_error_invalid_stsd = 51,
    heif_error_invalid_stsc = 52,
    heif_error_invalid_stco = 53,
    heif_error_sample_size_too_large = 54,
    heif_error_add_overflow = 55,
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_ERROR_H
