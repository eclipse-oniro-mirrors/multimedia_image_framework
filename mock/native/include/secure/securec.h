/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef MOCK_NATIVE_INCLUDE_SECURE_SECUREC_H_
#define MOCK_NATIVE_INCLUDE_SECURE_SECUREC_H_

/* success */
#ifndef EOK
#define EOK (0)
#endif

#ifndef errno_t
typedef int errno_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif
    /**
    * @Description:The memset_s function copies the value of c (converted to an unsigned char) into each of the first count characters of the object pointed to by dest.
    * @param dest - destination  address
    * @param destMax -The maximum length of destination buffer
    * @param c - the value to be copied
    * @param count -copies first count characters of  dest
    * @return  EOK if there was no runtime-constraint violation
    */
    errno_t memset_s(void *dest, size_t destMax, int c, size_t count);

    /**
    * @Description:The memcpy_s function copies n characters from the object pointed to by src into the object pointed to by dest.
    * @param dest - destination  address
    * @param destMax -The maximum length of destination buffer
    * @param src -source  address
    * @param count -copies count  characters from the  src
    * @return  EOK if there was no runtime-constraint violation
    */
    errno_t memcpy_s(void *dest, size_t destMax, const void *src, size_t count);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#define F_DUPFD_CLOEXEC 1030

#endif // MOCK_NATIVE_INCLUDE_SECURE_SECUREC_H_
