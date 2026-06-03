# PixelMap 内存模型与接口行为

## 适用范围

改动涉及以下场景时，先读本文，再回到代码确认当前实现：

- `PixelMap` 创建、复制、裁剪、缩放、旋转、翻转、序列化和跨进程传输。
- `HEAP_ALLOC`、`SHARE_MEM_ALLOC`、`CUSTOM_ALLOC`、`DMA_ALLOC` 或 NDK `IMAGE_ALLOCATOR_MODE_*` 的选择和行为。
- RGB、YUV、P010、ASTC 像素格式转换，以及 ASTC 编码。
- surface/native buffer、GL 后处理、HDR metadata、色彩空间或真实设备显示效果。
- JS/NAPI、NDK/C、CJ、ANI、Taihe、Native inner API 的外部可见行为。

本文是背景知识和排查路线，不替代代码。修改前仍需读取对应头文件、实现文件和测试。

## 快速代码地图

| 方向 | 主要文件 |
| --- | --- |
| inner API 和基础类型 | `interfaces/innerkits/include/pixel_map.h`, `interfaces/innerkits/include/pixel_astc.h`, `interfaces/innerkits/include/pixel_map_parcel.h`, `interfaces/innerkits/include/image_type.h` |
| 错误码 | `interfaces/innerkits/include/media_errors.h`, `interfaces/kits/native/include/image/image_common.h` |
| PixelMap 主实现 | `frameworks/innerkitsimpl/common/src/pixel_map.cpp`, `frameworks/innerkitsimpl/common/src/pixel_map_parcel.cpp`, `frameworks/innerkitsimpl/common/src/pixel_astc.cpp` |
| YUV/P010 扩展 | `interfaces/innerkits/include/pixel_yuv.h`, `interfaces/innerkits/include/pixel_yuv_ext.h`, `frameworks/innerkitsimpl/common/src/pixel_yuv.cpp`, `frameworks/innerkitsimpl/common/src/pixel_yuv_ext.cpp` |
| 内存创建 | `frameworks/innerkitsimpl/common/include/memory_manager.h`, `frameworks/innerkitsimpl/common/src/memory_manager.cpp` |
| 像素格式转换 | `interfaces/innerkits/include/image_format_convert.h`, `frameworks/innerkitsimpl/converter/src/image_format_convert.cpp`, `frameworks/innerkitsimpl/converter/src/image_format_convert_utils.cpp`, `frameworks/innerkitsimpl/converter/src/image_format_convert_ext_utils.cpp`, `frameworks/innerkitsimpl/converter/src/pixel_convert.cpp` |
| GL/surface/native buffer | `frameworks/innerkitsimpl/egl_image/`, `frameworks/innerkitsimpl/common/src/native_image.cpp`, `interfaces/innerkits/include/native_image.h` |
| ASTC 编码 | `plugins/common/libs/image/libextplugin/src/texture_encode/astc_codec.cpp`, `plugins/common/libs/image/libextplugin/src/texture_encode/image_compressor.cpp` |
| JS/NAPI | `frameworks/kits/js/common/pixel_map_napi.cpp`, `frameworks/kits/js/common/image_error_convert.cpp` |
| NDK/C API | `interfaces/kits/native/include/image/pixelmap_native.h`, `interfaces/kits/native/include/image/image_common.h`, `frameworks/kits/js/common/pixelmap_ndk/` |
| 单测和 fuzz | `frameworks/innerkitsimpl/test/BUILD.gn`, `frameworks/innerkitsimpl/test/fuzztest/BUILD.gn` |

## 核心模型

`PixelMap` 同时承载三类信息：

- 图片元信息：宽高、像素格式、alpha 类型、色彩空间、base density（参数无效，可忽略）、rowStride（行跨距，单位为字节）等。
- 像素内存：`data_` 指向可访问地址，`context_` 保存 allocator 相关上下文，`pixelsSize_` 记录可用大小。
- 运行标志：是否可编辑、是否 dirty、是否 ASTC、是否 display-only、变换信息、唯一 ID 等。

创建入口主要在 `PixelMap::Create`、`PixelMap::CreateFromPixels`、`PixelMap::ConvertFromAstc` 和各语言绑定层。创建时通常会先解析 `InitializationOptions`，生成目标 `ImageInfo`，计算 buffer 大小，创建内存，再做像素转换或拷贝，最后通过 `SetPixelsAddr` 绑定内存和释放方式。

YUV/P010 和 ASTC 不是普通 RGBA 的小变体：

- YUV/P010 可能走 `PixelYuv` 或 `PixelYuvExt`，需要关注 plane、stride、色彩转换细节和 buffer size 计算。
- ASTC 可能走 `PixelAstc`，很多直接读写像素的 API 不支持，变换更多表现为记录变换参数和更新尺寸。

## 设计背景与决策理由

下面的“代码体现”来自当前实现；“设计意图”包含代码路径、注释、依赖形态和模块责任人补充的背景。

| 决策 | 代码体现 | 设计意图 |
| --- | --- | --- |
| `DEFAULT` allocator 不是实际存储类型 | `ImageUtils::GetPixelMapAllocatorType` 会把 `DEFAULT` 推导为 `DMA_ALLOC`、`SHARE_MEM_ALLOC` 或平台上的 `HEAP_ALLOC` | 调用方不硬编码内存类型，让框架按尺寸、格式、平台能力和系统属性选择更合适的路径 |
| 默认 DMA 分支当前有宽度对齐判断 | `ImageUtils::IsWidthAligned` 当前硬编码判断 `(width * 4) & 255 == 0` | 这是当前代码里的临时硬编码，不应作为稳定规格理解；真实 gralloc 对齐约束和芯片平台有关，后续改相关逻辑需要人工确认 |
| No-Padding/noIPC DMA 优化 | `IsSupportDefaultDmaNopadding` 命中后设置 `BUFFER_USAGE_PREFER_NO_PADDING | BUFFER_USAGE_ALLOC_NO_IPC` | 针对 gralloc 对齐和跨进程申请成本做优化：no-padding 表示 DMA 内存可按无 padding 方式申请；noIPC 表示不通过跨进程 binder 申请，直接在应用进程内申请，申请速度更快 |
| 非 DMA 默认走 share memory | 非跨平台分支兜底返回 `SHARE_MEM_ALLOC` | share memory 支持跨进程传 fd，避免 heap 在 IPC 中完整复制大 buffer |
| Windows、Apple、iOS、Android 平台走 heap | `GetPixelMapAllocatorType` 在这些平台直接返回 `HEAP_ALLOC` | 这些平台不走当前 OpenHarmony Ashmem/SurfaceBuffer 能力，只能用 malloc 类路径 |
| `CUSTOM_ALLOC` 不能由框架主动创建 | `MemoryManager::CreateMemory` 对 `CUSTOM_ALLOC` 返回不支持 | custom 的语义是调用方传入外部内存和释放回调，框架无法替调用方分配或决定所有权 |
| `displayOnly` 用于 RS 显示侧区分 | `PixelMap` 将 `OHOS::Rosen::RSMarshallingHelper` 声明为 friend，`SetPixelsAddr(..., bool displayOnly)` 在 `displayOnly == true` 时不调用 `FlushSurfaceBuffer` | 当前该语义由 RS 侧 `RSMarshallingHelper` 调用，用于区分只面向显示消费的 PixelMap；其他模块不要直接扩展或复用该语义 |

## 创建和内存分配

`InitializationOptions` 中容易影响行为的字段：

- `pixelFormat`：目标格式。未指定或为 `UNKNOWN` 时，部分路径会根据源格式和默认值推导。
- `srcPixelFormat`：从裸数据创建时的源格式，默认 `BGRA_8888`。
- `allocatorType`：内部 allocator，默认 `AllocatorType::DEFAULT`。
- `useDMA`：仅在 `allocatorType == DEFAULT` 时影响推导；设为 `true` 会让第一条 DMA 分支按 `preferDma` 处理。
- `editable`：决定是否允许写像素和部分修改操作。
- `srcRowStride`：从外部 buffer 创建时影响逐行读取和转换。
- `useSourceIfMatch`：源和目标匹配时可能复用源对象，改动时要防止共享内存生命周期被误判。

默认值来自 `interfaces/innerkits/include/pixel_map.h`：

| 字段 | 默认值 |
| --- | --- |
| `size` | `{0, 0}` |
| `srcPixelFormat` | `PixelFormat::BGRA_8888` |
| `pixelFormat` | `PixelFormat::UNKNOWN` |
| `alphaType` | `AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN` |
| `scaleMode` | `ScaleMode::FIT_TARGET_SIZE` |
| `srcRowStride` | `0`，表示无 padding，行 stride 等于行字节数 |
| `allocatorType` | `AllocatorType::DEFAULT` |
| `editable` | `false` |
| `useSourceIfMatch` | `false` |
| `useDMA` | `false` |

内部 allocator 枚举在 `interfaces/innerkits/include/image_type.h`：

- `DEFAULT = 0`
- `HEAP_ALLOC = 1`
- `SHARE_MEM_ALLOC = 2`
- `CUSTOM_ALLOC = 3`
- `DMA_ALLOC = 4`

`DEFAULT` 不是一种真实存储方式。创建时会通过 `ImageUtils::GetPixelMapAllocatorType` 结合尺寸、格式、`useDMA`、系统属性和 usage 推导成具体 allocator。后续新增对外接口应优先走 No-Padding/noIPC DMA；旧的 `useDMA/preferDma` 分支属于当前实现细节，不作为新增接口的规格限制。显式指定 allocator 时，会直接交给 `MemoryManager::CreateMemory`；当前 `MemoryManager` 对 `CUSTOM_ALLOC` 的主动创建返回不支持，`CUSTOM_ALLOC` 更多用于外部内存传入和自定义释放回调。

buffer 大小不能简单按 `width * height * bytesPerPixel` 理解：

- 普通 RGB 路径通常依赖 `ImageInfo::GetRowDataSize` 和像素格式字节数。
- YUV/P010 需要用对应的 YUV byte count 和 plane/stride 信息。
- DMA/native buffer 的实际 stride 可能来自 `SurfaceBuffer::GetStride`，不一定等于图片宽度乘像素字节数。
- ASTC 需要区分压缩数据大小和原图真实宽高，`PixelMap` 里有 ASTC real size 相关字段。
- heap 路径有内存上限保护；代码注释说明 heap IPC 场景可能出现额外拷贝，所以对大图更敏感。

## Allocator 选择决策树

当 `InitializationOptions::allocatorType == AllocatorType::DEFAULT` 时，当前实现会走 `ImageUtils::GetPixelMapAllocatorType`。后续新增对外接口按 No-Padding/noIPC DMA 优选；当前代码里仍可见旧 DMA 分支，但不要把旧分支的尺寸判断作为新接口限制。

```text
DEFAULT allocator
  |
  |-- IsSupportDefaultDmaNopadding(format)
  |     |-- system properties:
  |     |   persist.multimedia.defaultDmaNopadding.enabled == true
  |     |   persist.gralloc.nopadding.enabled == true
  |     |-- format in {BGRA_8888, RGBA_8888}
  |           -> DMA_ALLOC
  |           -> usage adds BUFFER_USAGE_PREFER_NO_PADDING | BUFFER_USAGE_ALLOC_NO_IPC
  |
  |-- legacy DMA branch in current code
  |     |-- includes current hard-coded size/alignment checks
  |     |-- do not treat these checks as new public API limits
  |
  |-- fallback
        -> SHARE_MEM_ALLOC
```

平台分支：

- Windows、Apple、iOS、Android：直接返回 `HEAP_ALLOC`。
- No-Padding/noIPC DMA 是新增对外接口的优选路径，受系统属性和格式白名单控制。
- `BUFFER_USAGE_ALLOC_NO_IPC` 会影响跨进程能力，改 No-Padding 路径时必须确认调用方是否需要 IPC。

## 规格限制

### 尺寸和内存上限

| 限制项 | 当前值 | 代码锚点 | 说明 |
| --- | --- | --- | --- |
| 普通 PixelMap 最大宽高 | `INT32_MAX >> 2`，即 `536870911` | `frameworks/innerkitsimpl/common/src/pixel_map.cpp`, `frameworks/innerkitsimpl/utils/src/image_utils.cpp` | `IsValidImageInfo`、创建和变换路径都会复用该限制 |
| heap malloc 上限 | `1500 * 1024 * 1024` bytes | `frameworks/innerkitsimpl/common/src/memory_manager.cpp` | `HeapMemory::Create` 使用的分配上限 |
| PixelMap heap/IPC/转换校验上限 | `600 * 1024 * 1024` bytes | `interfaces/innerkits/include/pixel_map.h`, `frameworks/innerkitsimpl/converter/src/*` | `pixel_map.h` 注释说明 heap IPC 会发生两次拷贝，因此需要限制 |
| parcel 数据上限 | `128 * 1024 * 1024` bytes | `interfaces/innerkits/include/pixel_map.h` | `MAX_IMAGEDATA_SIZE` |
| parcel 数据下限 | `32 * 1024` bytes | `interfaces/innerkits/include/pixel_map.h` | `MIN_IMAGEDATA_SIZE` |
| DMA SurfaceBuffer stride 对齐请求 | `0x8` | `frameworks/innerkitsimpl/common/src/memory_manager.cpp` | `BufferRequestConfig::strideAlignment` |

注意：当前代码里存在两个名字相同但作用域不同的 `PIXEL_MAP_MAX_RAM_SIZE`。`memory_manager.cpp` 的 1500MB 用于 heap malloc；`pixel_map.h` 和多处转换/校验路径的 600MB 用于 PixelMap heap/IPC/中间 buffer 保护。排查大图问题时要先确认命中的是分配上限还是 PixelMap 业务校验上限。

## Allocator 语义

### HEAP_ALLOC

`HEAP_ALLOC` 是普通堆内存。释放时走 `free(data_)`。它适合普通本地读写和测试，但大图、跨进程传输、真实设备硬件链路并不一定适合 heap。

注意点：

- heap 序列化通常会复制 buffer，性能和内存峰值都要关注。
- 对外接口如果新增大尺寸路径，不要只用小图单测验证。
- 大图失败时先看 buffer size、row stride 和内存上限，而不是只看像素格式。

### SHARE_MEM_ALLOC

`SHARE_MEM_ALLOC` 使用共享内存。`context_` 通常保存 fd 相关上下文，释放时需要 `munmap`、`close(fd)` 并清理 fd 指针。`SetPixelsAddr` 对共享内存的 `context` 有非空要求。

注意点：

- parcel 传输时会传 fd，不是单纯复制字节。
- fd 生命周期、重复 close、mmap 权限和只读降级都可能造成问题。
- 反序列化失败时要确认 fd 是否有效、mmap 是否成功、buffer size 是否和元信息一致。

### CUSTOM_ALLOC

`CUSTOM_ALLOC` 表示外部传入内存，释放依赖 `CustomFreePixelMap` 回调。它不是一个可以随便重新分配的通用 allocator。

注意点：

- 外部内存所有权必须明确，不能把 heap/share/DMA 的释放方式套到 custom 上。
- 当前主动创建内存时 `MemoryManager::CreateMemory` 对 `CUSTOM_ALLOC` 返回不支持。
- parcel 读取时 `DEFAULT` 和 `CUSTOM_ALLOC` 会被归一到 `HEAP_ALLOC` 路径，改 custom 行为要特别检查跨进程结果。

### DMA_ALLOC

`DMA_ALLOC` 对应 `SurfaceBuffer`/native buffer 场景。释放时会通过 `ImageUtils::SurfaceBuffer_Unreference` 处理引用。像素地址通常来自 `SurfaceBuffer::GetVirAddr`，stride 可能来自 `SurfaceBuffer::GetStride`。

注意点：

- DMA 是 surface、native buffer、GL、HDR metadata 和部分硬件链路的关键路径。
- native buffer 创建 PixelMap 时要确认 CPU 访问权限和格式支持。
- 写入或转换后要关注 `FlushSurfaceBuffer`，否则真实设备显示或跨进程消费者可能读到旧数据。
- No-Padding DMA 路径会设置 `BUFFER_USAGE_PREFER_NO_PADDING | BUFFER_USAGE_ALLOC_NO_IPC`，后续转换、后处理和编码路径可能通过 `GetNoPaddingUsage` 继续沿用该 usage。
- No-Padding/noIPC DMA 内存有限制：不支持 GPU 回写数据，只支持 GPU 读。涉及 GPU 写回、读写纹理或跨进程传输时，不要直接套用该路径。
- DMA 问题不能只靠本地单测闭环，涉及真实设备能力、驱动和显示效果时需要补充真实设备验证结果。

### display-only

parcel 里有 `displayOnly` 语义，但它不是通用公开能力。当前通过 friend 类做区分，实际调用方是 RS 侧的 `OHOS::Rosen::RSMarshallingHelper`，用于只面向显示消费的 PixelMap 路径。改 DMA、surface 或反序列化逻辑时，要确认 display-only 对 `data_`、`context_`、可编辑性和错误返回的影响，并避免让非 RS 路径直接依赖该语义。

特别注意：

- `PixelMap::FreePixelMap` 中，如果 `data_ == nullptr` 且 `displayOnly_ == true`，不会因为空 `data_` 直接返回，释放逻辑仍会继续看 allocator。
- `SetPixelsAddr(..., bool displayOnly)` 中，`displayOnly == true` 时会跳过 `FlushSurfaceBuffer`。
- 新增或调整 display-only 行为时，需要和 RS 侧调用方一起确认；当前不要把它扩展成普通 PixelMap 调用约定。

## 新增接口内存选择原则

新增对外接口时，包括 NAPI、C API、Taihe 等，优先选择 No-Padding/noIPC DMA 内存，以减少 gralloc padding 和跨进程 binder 申请成本。若 DMA 内存申请失败，应 fallback 到 ashmem/share memory；在 OpenHarmony 平台上不要把 heap 作为新能力的优先路径。

新增 inner 接口时，内存类型选择要考虑对外接口的兼容性。如果 inner 接口后续可能被 NAPI、C API、Taihe 或其他公开接口复用，应提前确认 allocator、IPC、GPU 读写能力和错误码映射，避免内部接口先选了对外不可承诺的内存语义。

在 OpenHarmony 平台上，heap 内存当前仅保留历史通路，不作为后续 PixelMap 内存能力演进方向。只有跨平台限制、历史兼容或明确无法使用 share memory/DMA 的场景，才考虑 heap。

## SetPixelsAddr 绑定边界

`SetPixelsAddr` 是 PixelMap 绑定裸地址、上下文、allocator 和释放策略的关键入口。当前有两个主要重载：

- `SetPixelsAddr(void *addr, void *context, uint32_t size, AllocatorType type, CustomFreePixelMap func)`
- `SetPixelsAddr(void *addr, void *context, uint32_t size, AllocatorType type, bool displayOnly)`

关键边界：

- allocator 超出 `DEFAULT` 到 `DMA_ALLOC` 范围时会直接返回。
- 绑定新地址前，如果 `data_ != nullptr`，会先 `FreePixelMap` 释放旧数据。
- `SHARE_MEM_ALLOC + context == nullptr` 只打错误日志，不会 return；后续共享内存释放、mmap/munmap 或 fd close 路径会留下风险，调用方不应依赖这个路径继续工作。
- callback 版会保留 `custFreePixelMap_ = func`；`displayOnly` 版会把 `custFreePixelMap_` 置空。
- DMA 且 `rowDataSize_ != 0` 时会调用 `UpdateImageInfo`，因此 row stride 变化可能反向影响 `ImageInfo`。
- callback 版会无条件调用 `FlushSurfaceBuffer`；`displayOnly` 版仅在 `displayOnly == false` 时 flush。
- callback 版在非反序列化路径会调用 `MarkPropertiesDirty`；反序列化路径通过 `isUnmarshalling_` 避免标脏。

## Parcel 和跨进程传输

PixelMap 的传输和序列化不是单一路径：

- `PixelMapParcel` 偏基础序列化，写入图片元信息和数据。共享内存场景会写 fd，其他路径可能写 buffer。
- `PixelMapRecordParcel` 仅用于 RS 侧图片录制回放逻辑处理，属于测试框架相关功能；做普通业务分析和代码适配时，可以忽略该文件下的函数，不要把它当 PixelMap 主传输链路。
- DMA 反序列化会从 parcel 读取 `SurfaceBuffer` 并增加引用。
- share memory 反序列化会读 fd 并 mmap。
- heap 路径会读入字节 buffer。
- TLV 是另一套 `std::vector<uint8_t>` 序列化路径，入口是 `PixelMap::EncodeTlv` 和 `PixelMap::DecodeTlv`，属性读取集中在 `PixelMap::ReadTlvAttr`，tag 和 varint 工具在 `frameworks/innerkitsimpl/utils/include/image_utils.h` 与 `frameworks/innerkitsimpl/utils/src/image_utils.cpp`。

TLV 传输当前要点：

- TLV tag 覆盖宽高、像素格式、色彩空间、alpha、base density、allocator、像素数据、HDR 标志、SurfaceBuffer 色彩/HDR metadata 和 color space manager 信息，结束 tag 为 `TLV_END`。
- `EncodeTlv` 先通过 `ImageUtils::CheckTlvSupportedFormat` 校验格式，再写基础 ImageInfo、HDR/SurfaceBuffer 信息、allocator 和 `TLV_IMAGE_DATA`。当前写出的 allocator tag 使用 `HEAP_ALLOC`，解码时会根据 HDR 和 No-Padding 条件重新选择实际内存。
- `DecodeTlv` 通过 `ReadTlvAttr` 逐 tag 读取：未知 tag 会按长度跳过，已支持 tag 会做重复 tag 检查，重复出现直接失败。
- `ReadVarint` 有游标越界和 shift 溢出检查；`ReadTlvAttr` 会校验 `len <= 0`、`cursor + len` 溢出和越界。
- `TLV_IMAGE_DATA` 读取时走 `ImageUtils::ReadData`，会限制 `MAX_TLV_HEAP_SIZE`，校验 cursor 范围、期望数据大小、DMA stride、SurfaceBuffer size 和 heap row stride，再执行拷贝。
- TLV HDR metadata 会从 SurfaceBuffer 写入/读出，包括 color type、metadata type、static metadata、dynamic metadata。新增 metadata tag 或改长度语义时要同步检查 metadata vector 的长度、拷贝范围和目标 SurfaceBuffer 能力。
- TLV 相关 fuzz 目标包括 `imagepixelmapTlv_fuzzer`、`imagepixelmaptlv2_fuzzer`、`imagepixelmapHdrTLV_fuzzer`，公开 API 变化还要结合对应单测和 XTS。

改 parcel/TLV/跨进程传输相关逻辑时重点检查：

- allocator 枚举是否仍然在有效范围内。
- 新字段是否影响旧数据兼容读取，未知字段是否能安全跳过。
- ASTC real size、YUV plane 信息、row stride 和 buffer size 是否一起传递；普通业务链路优先看 `PixelMapParcel`、`PixelMap::Marshalling` 和 TLV 路径，不优先看 `PixelMapRecordParcel`。
- 失败路径是否释放已经 mmap、malloc 或 reference 的资源。
- JS/NDK/Native 跨进程接口是否把内部错误码转换成调用方能理解的错误。
- 传输入口要按不可信输入处理，重点考虑安全攻击问题：长度伪造、整数溢出、重复 tag、未知 tag、越界 cursor、超大内存申请、fd 伪造、mmap 权限、DMA stride/SurfaceBuffer size 不匹配、metadata 长度异常和失败路径资源释放。
- 修改传输解析函数后，至少补充畸形数据、边界长度、重复字段、未知字段和异常 allocator 的 fuzz/单测覆盖。

## RGB、YUV 和 P010 转换

格式转换核心在 `ImageFormatConvert`：

- RGB 到 YUV/P010 的映射在 `g_cvtFuncMap`。
- YUV/P010 到 RGB 或 YUV/P010 互转的映射在 `g_yuvCvtFuncMap`。
- P010 在代码中主要表现为 `YCBCR_P010` 和 `YCRCB_P010`。
- 部分路径有 EXT_PIXEL 变体，可能影响转换函数选择、stride 处理和性能。

改转换能力时不要只改 `image_format_convert.cpp`。还要同步检查：

- JS/NAPI 的 `IsMatchFormatType`、`TypeFormat` 和 `convertPixelFormat` 入参校验。
- NDK `OH_PixelMapNative_ConvertPixelFormat` 里也有一套允许转换的格式白名单 `IsMatchType`。它和 JS 的 `IsMatchFormatType` 不完全一样，例如 JS 把 `YCBCR_P010`、`YCRCB_P010` 和 `ASTC_4x4` 放进转换分组，NDK 这段主要只覆盖常见 RGB 与 `NV12`、`NV21`。新增或修改转换能力时，两边都要同步检查。
- `interfaces/kits/native/include/image/pixelmap_native.h` 中公开说明和支持格式。
- `interfaces/kits/native/include/image/image_common.h` 中公开错误码。
- CJ/ANI/Taihe 等绑定层是否也暴露了同一行为。

涉及对外接口或 API 行为时，还需要验证对应 XTS 用例。

## ASTC PixelMap

ASTC PixelMap 的主要锚点是 `interfaces/innerkits/include/pixel_astc.h` 和 `frameworks/innerkitsimpl/common/src/pixel_astc.cpp`。

`PixelAstc` 和普通 `PixelMap` 的关键差异：

- `GetPixel*`、`ReadPixel`、`ReadPixels`、`WritePixel`、`WritePixels`、`SetAlpha`、`ResetConfig` 等直接像素访问或修改接口在 `PixelAstc` 中大多返回不支持。
- scale、translate、rotate、flip、crop 等变换会维护 `TransformData` 并更新尺寸，不能按普通 RGB 内存重排理解。
- ASTC 需要记录压缩数据大小和原图真实大小。parcel、clone、转换和显示路径都可能依赖这个信息。
- JS `convertPixelFormat` 中 ASTC 主要作为单独格式组处理，当前锚点是 `ASTC_4x4`。

排查 ASTC 问题时先判断是“ASTC PixelMap 解码/显示/转换”还是“ASTC 编码生成”。两条链路入口不同，测试目标也不同。

## ASTC 编码

ASTC 编码在插件侧，主要锚点：

- `plugins/common/libs/image/libextplugin/src/texture_encode/astc_codec.cpp`
- `plugins/common/libs/image/libextplugin/src/texture_encode/image_compressor.cpp`

这里处理的是把输入 `PixelMap` 编成 ASTC/SUT 相关输出，不是普通 `PixelAstc` 的变换接口。

重点关注：

- 编码格式名、quality/profile、block 维度和 ASTC header。
- SDR/HDR ASTC、SUT super compress、软件 astcenc、OpenCL 编码路径的选择条件。
- ASTC 编码能力门控统一按 graphic 扩展部件判断：`defined(global_parts_info) && defined(global_parts_info.graphic_graphic_2d_ext)` 命中时，才认为目标产品具备 ASTC 编码相关能力；相关 BUILD 宏包括 `SUT_ENCODE_ENABLE`，测试侧还会添加 `ASTC_CUSTOMIZED_ENABLE`。后续改 BUILD 条件时，也应保持 ASTC 编码能力判断口径一致。
- 最大宽高、stride、输入 buffer 非空、输出 buffer 大小等边界。
- OpenCL 动态库、kernel、bin 缓存、SUT 动态库是否在目标设备可用。
- 编码结果如果会被 JS/NDK/Native 使用，还要检查 MIME/格式能力、插件元数据和调用方错误码。

ASTC 编码涉及设备能力或 OpenCL/SUT 时，需要真实设备验证。没有设备时，应记录已完成的本地验证和缺失的真实设备验证项，等待人工确认后再继续 push。

## GL、surface 和 native buffer

GL/surface/native buffer 场景通常与 DMA 绑定，排查时不要只看 `PixelMap` 本身。

需要一起看：

- `frameworks/innerkitsimpl/egl_image/` 下的 PixelMap GL 创建、resize、后处理逻辑。
- `frameworks/innerkitsimpl/common/src/native_image.cpp` 和 native image 相关头文件。
- NDK `OH_PixelmapNative_CreatePixelmapFromNativeBuffer`、`CreatePixelmapFromSurface`、`CreatePixelmapFromSurfaceWithTransformation`。
- `graphic_surface`、`graphic_2d`、`drivers_interface_display` 提供的 buffer、stride、usage、CPU 访问权限和 release 语义。

常见风险：

- native buffer 的实际格式和 PixelMap 元信息不一致。
- stride、rowDataSize、bufferSize 三者只改了一个。
- 写入 DMA 后没有 flush，导致显示侧或消费者读到旧数据。
- SurfaceBuffer 引用计数不匹配，导致泄漏或提前释放。
- 只在模拟/本地环境验证，真实设备上因为驱动、显示或硬件 codec 能力不同而失败。

## 对外 API 兼容性

以下行为属于外部可见行为，不应只按内部实现重构处理：

- 新增、删除或改变像素格式、图片格式、ASTC/SUT 格式名。
- allocator 选择策略、公开 allocator mode、DMA/share memory 行为。
- `ReadPixel`、`WritePixels`、`convertPixelFormat` 等 API 对某格式是否支持。
- 错误码、异常对象、错误文案和错误码映射。
- HDR metadata key/type、色彩空间、alpha type、base density。
- parcel 后对象是否可编辑、是否保留颜色空间和 transform 信息；若涉及 RS 侧 display-only 路径，还要单独确认 `RSMarshallingHelper` 调用语义。

改上述行为时至少检查：

- `interfaces/innerkits/include/media_errors.h`
- `interfaces/kits/native/include/image/image_common.h`
- `frameworks/kits/js/common/image_error_convert.cpp`
- `frameworks/kits/js/common/pixel_map_napi.cpp`
- `frameworks/kits/js/common/pixelmap_ndk/`
- CJ/ANI/Taihe 相关适配代码
- 对应 XTS 用例

如果改动触达 `graphic_2d`、`drivers_peripheral`、`ability_runtime`、`napi`、`ipc` 等跨仓接口或调用方假设，需要在提交说明或 PR 说明里写明跨仓影响和验证方式。

## 常见故障排查

### 创建 PixelMap 失败

优先检查：

- `InitializationOptions` 的宽高、目标格式、源格式、row stride 是否有效。
- buffer size 是否溢出或超过限制；大图要区分 1500MB heap malloc 上限和 600MB PixelMap heap/IPC/中间 buffer 校验上限。
- allocator 是否被正确解析，`DEFAULT` 是否走到了预期 allocator。
- No-Padding DMA 是否受系统属性控制，且是否允许 `BUFFER_USAGE_ALLOC_NO_IPC`。
- YUV/P010 是否用了正确的 plane/stride/byte count。
- `MemoryManager::CreateMemory` 是否支持当前 allocator。

### 大图上限不一致导致的混淆

如果同一张大图在不同路径表现不同，先确认命中的上限：

- `HeapMemory::Create` 可以允许到 1500MB。
- `PixelMap` 创建、读写、转换和部分中间 buffer 校验常用 600MB。
- parcel 写入还有 128MB 的 `MAX_IMAGEDATA_SIZE` 限制。

因此“大图 heap 能 malloc”不等于“PixelMap 所有操作都允许该大小”，也不等于“可以通过 parcel 传输”。

### 共享内存反序列化失败

优先检查：

- fd 是否有效，是否被提前 close。
- mmap 权限是否符合当前读写要求。
- parcel 中的 allocator、buffer size、rowDataSize、image info 是否一致。
- 失败路径是否重复释放 fd 或泄漏 mmap。

### DMA/native buffer 路径崩溃或显示异常

优先检查：

- `SurfaceBuffer` 是否成功创建、读取或引用。
- `GetVirAddr` 是否可用，CPU 访问权限是否满足要求。
- stride 是否按 SurfaceBuffer 实际 stride 处理。
- 写完后是否调用 flush。
- 是否走了 No-Padding DMA；如果 usage 带 `BUFFER_USAGE_ALLOC_NO_IPC`，不要假设它可以跨进程传输。
- 是否需要 GPU 回写；No-Padding/noIPC DMA 只支持 GPU 读，不支持 GPU 回写数据。
- 是否进入 RS 侧 `RSMarshallingHelper` 的 display-only 路径，导致 `data_` 为空或跳过 flush。
- 真实设备上的 graphic/display/codec 能力是否支持该格式和 usage。

### ASTC 读写或转换不符合预期

优先判断当前对象是不是 `PixelAstc`：

- 如果是 `PixelAstc`，直接读写像素接口大多不支持，这是设计行为。
- 如果目标是转成 RGB，再看 `PixelMap::ConvertFromAstc` 和 JS `convertPixelFormat` 的 ASTC 支持范围。
- 如果目标是编码生成 ASTC，看 `texture_encode` 插件链路、格式名、quality/profile、OpenCL/SUT 条件和 `textureencodetest`。

### JS 和 NDK 行为不一致

优先检查两边允许转换的格式白名单：

- JS 在 `pixel_map_napi.cpp` 中按 RGB/YUV/ASTC 分组，P010 和 ASTC 也有对应判断。
- NDK 在 `pixelmap_ndk/pixelmap_native.cpp` 中有自己的 `IsMatchType` 白名单，支持范围可能比 JS 窄，例如不一定覆盖 P010/ASTC。
- 错误码可能在 NDK、JS 和 inner API 之间转换，不能只看 inner 返回值。

## 验证建议

构建命令从 OpenHarmony 源码根目录执行：

```sh
./build.sh --product-name <product-name> --build-target image_framework --ccache
prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> image_framework plugins image_test_list
```

就近单测目标优先看：

- `pixelmaptest`
- `imagepixelmaptest`
- `imageformatconverttest`
- `textureencodetest`

就近 fuzz 目标按改动范围选择，不需要全量列跑。常用锚点：

- PixelMap 基础和序列化：`imagepixelmapBase_fuzzer`, `imagepixelmapMarshalling_fuzzer`, `imagepixelmapTlv_fuzzer`
- DMA/HDR/YUV/P010：按 `frameworks/innerkitsimpl/test/fuzztest/BUILD.gn` 中对应 `imagepixelmap*`, `imagepixelYuv*`, `imagefwkconvertp010*` 目标选择
- ASTC：`imagefwkcreateastcpixelmap_fuzzer`, `imagefwkconvertastc2rgb_fuzzer`, `imagetextureencode_fuzzer`
- 像素格式转换：`imagefwkconvertpixelmapformat*`, `imagefwkconvertrgb2yuv_fuzzer`

涉及对外接口或公开 API 行为时，需要补充对应 XTS 用例。涉及硬解、surface、DMA、HDR 显示、设备 codec 能力、GL 后处理或 ASTC OpenCL/SUT 编码时，需要补充真实设备验证结果。当前没有真实设备时，不要声称完整验证已完成；记录缺失原因、已完成本地验证和仍需人工补充的真实设备验证项。

## 改动检查清单

- 是否读过公开头文件，再读实现文件，而不是只改内部实现？
- 是否确认 allocator 选择、释放函数和所有权？
- 是否检查 row stride、buffer size、YUV plane、ASTC real size 是否同步变化？
- 是否确认 parcel 版本、跨进程传输和失败释放路径？
- 是否同步 JS/NAPI、NDK/C、CJ、ANI、Taihe 等绑定层？
- 是否同步错误码和错误码映射？
- 是否需要 XTS？
- 是否需要真实设备验证？
- 是否避免在转换、序列化、metadata 或插件枚举热点路径增加全量扫描、大内存拷贝或高频日志？

## 待补充背景

这些内容需要模块责任人后续补充，不能仅靠静态扫描完全确定：

- PixelMap 相关 XTS 目标名、真实设备验证用例和团队常用验证命令。
- 历史线上问题，例如 DMA 生命周期、display-only、ASTC 转换、P010 stride、共享内存 fd 泄漏等典型案例。
