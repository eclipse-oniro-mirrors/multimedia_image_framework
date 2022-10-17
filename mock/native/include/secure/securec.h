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

#if SECUREC_SUPPORT_FORMAT_WARNING && !defined(SECUREC_PCLINT)
#define SECUREC_ATTRIBUTE(x, y)  __attribute__((format(printf, (x), (y))))
#else
#define SECUREC_ATTRIBUTE(x, y)
#endif

/* if you need export the function of this library in Win32 dll, use __declspec(dllexport) */
#ifdef SECUREC_IS_DLL_LIBRARY
#ifdef SECUREC_DLL_EXPORT
#define SECUREC_API __declspec(dllexport)
#else
#define SECUREC_API __declspec(dllimport)
#endif
#else
/* Standardized function declaration . If a security function is declared in the your code,
 * it may cause a compilation alarm,Please delete the security function you declared
 */
#define SECUREC_API extern
#endif

#ifndef errno_t
typedef int errno_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif
    /**
    * @param dest - destination  address
    * @param destMax -The maximum length of destination buffer
    * @param c - the value to be copied
    * @param count -copies first count characters of  dest
    * @return  EOK if there was no runtime-constraint violation
    */
    errno_t memset_s(void *dest, size_t destMax, int c, size_t count);

    /**
    * @param dest - destination  address
    * @param destMax -The maximum length of destination buffer
    * @param src -source  address
    * @param count -copies count  characters from the  src
    * @return  EOK if there was no runtime-constraint violation
    */
    errno_t memcpy_s(void *dest, size_t destMax, const void *src, size_t count);

    /**
    * @param strDest -  produce output according to a format ,write to the character string strDest
    * @param destMax - The maximum length of destination buffer(including the terminating null byte ('\0'))
    * @param format - format string
    */
    SECUREC_API int sprintf_s(char *strDest, size_t destMax, const char *format, ...) SECUREC_ATTRIBUTE(3, 4);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // MOCK_NATIVE_INCLUDE_SECURE_SECUREC_H_
