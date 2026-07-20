# 图片框架指引

## 项目定位

本仓库对应 OpenHarmony `foundation/multimedia/image_framework`。优先按这些目录定位问题：

- `frameworks/innerkitsimpl/codec/`、`frameworks/innerkitsimpl/stream/`：`ImageSource`、`ImagePacker`、输入输出流、解码和编码主链路。
- `frameworks/innerkitsimpl/common/`、`frameworks/innerkitsimpl/converter/`、`frameworks/innerkitsimpl/egl_image/`：`PixelMap`、YUV/RGB/ASTC/P010 转换、GL 后处理和内存承载。
- `frameworks/innerkitsimpl/accessor/`、`frameworks/innerkitsimpl/picture/`、`frameworks/innerkitsimpl/utils/`：EXIF/XMP/metadata、`Picture`/辅助图、HDR、色彩空间和通用工具。
- `frameworks/innerkitsimpl/creator/`、`frameworks/innerkitsimpl/receiver/`：`ImageCreator`、`ImageReceiver`、surface/native buffer 生命周期。
- `interfaces/innerkits/`、`interfaces/kits/`、`frameworks/kits/`：Native inner API、JS/NAPI、NDK/C API、CJ、ANI、Taihe 绑定。
- `plugins/manager/`、`plugins/common/libs/image/`：插件框架、格式识别、扩展编解码插件和插件元数据。
- `frameworks/innerkitsimpl/test/`、`plugins/manager/test/`、`test/resource/`、`mock/`：单元测试、fuzz 目标、测试图片资源和本地 mock。

## 典型工作流

1. 先判断改动场景，读取下文知识路由和对应 `docs/knowledge/` 文档；一个任务跨多个场景时，按影响面同时读取多个入口。
2. 定位公开接口和内部实现边界：先看 `interfaces/innerkits/include/`、`interfaces/kits/`，再看 `frameworks/innerkitsimpl/` 和 `frameworks/kits/`。
3. 改动涉及公开 API、错误码、插件能力、内存/Surface、HDR、metadata、Parcel/TLV 或跨进程传输时，先确认生命周期、安全边界、错误码映射和 API 兼容性。
4. 小步修改，就近复用项目已有宏、错误码、日志和测试资源。
5. 按下文验证矩阵和知识文档中的验证重点跑最近目标；涉及真实硬件、surface、DMA 或显示效果时，补充真实设备上的验证结果。
6. 最终回复要写明读取过的知识文档、完成的验证、未覆盖的 XTS/真实设备缺口，以及是否已提交或 push。
7. 提交和 push 前按下文“提交和推送”要求完成检查。

## 依赖和接口边界

本仓对外依赖在 `bundle.json` 中声明，常见跨子系统边界包括：

- 图形和显示：`graphic_2d`、`graphic_surface`、`egl`、`opengles`、`drivers_interface_display`。
- 硬件编解码和内存：`drivers_interface_codec`、`hdf_core`、`memory_utils`、`memmgr`、`openmax`。
- 运行时和 API：`ability_runtime`、`napi`、`ipc`、`ffrt`、`eventhandler`、`ets_runtime`。
- 第三方编解码和元数据：`skia`、`ffmpeg`、`libjpeg-turbo`、`libpng`、`libtiff`、`dav1d`、`libexif`、`xmp_toolkit_sdk`。

改动触达上述依赖的接口、枚举、buffer 语义、错误码或能力查询时，不要只在本仓内闭环；需要检查依赖方公开头文件、运行时能力和调用方假设，并在提交说明中写明跨仓影响和验证方式。

## 验证

按改动范围选择最近的测试目标，具体目标优先参考知识文档。涉及对外接口或 API 行为时，还需要验证对应 XTS 用例。涉及硬解、surface、DMA、HDR 显示、设备 codec 能力或公开 API 行为时，需要补充真实设备上的验证结果。当前没有真实设备时，不要声称已完成完整验证；应记录缺失原因、已完成的本地验证和仍需补充的真实设备验证项，并等待人工确认是否继续 push。

任务级验证参考：

| 改动类型 | 近端验证 | 额外要求 |
| --- | --- | --- |
| 文档、知识路由、注释 | 检查链接、路径、术语和代码锚点是否存在 | 不改行为时通常不需要额外验证 |
| C++ 内部实现 | 对应模块最近单测 | 关注错误码、日志、资源释放和异常路径 |
| 公开 API 或多语言绑定 | 对应 JS/NDK/CJ/ANI/Taihe 单测 | 必须验证或说明对应 XTS；检查错误码和默认值兼容 |
| 编解码、插件、metadata 解析 | 对应 codec/plugin/accessor 单测 | 补跑相关 fuzz，覆盖截断、畸形、超大尺寸和异常 metadata |
| `PixelMap`、Surface、DMA、HDR、硬件 codec | 最近单测 + 相关 fuzz | 需要真实设备验证；没有设备时记录缺口并等待人工确认 |
| Parcel/TLV、跨进程传输、安全修复 | 最近单测 + 相关 fuzz | 重点检查越界、溢出、fd 泄漏、重复释放和旧数据兼容 |

XTS 用例不在本仓完整维护。涉及公开 API、错误码、默认值、权限、异常类型、跨语言行为或兼容性时，必须查 OpenHarmony XTS 仓、CI 配置或团队用例映射；查不到时，在最终回复中明确写“XTS 目标未确认”，并列出已跑的本仓单测/fuzz 和需要人工补充确认的 API 场景。

真实设备验证记录至少包含：产品名、设备形态、系统版本或镜像标识、输入样例、触发 API/命令、关键 buffer 参数或格式参数、期望结果、实际结果。没有真实设备时，不要继续自行 push 涉及设备行为的改动，除非用户或模块责任人明确确认可以先合入。

## 提交和推送

所有提交在 push 之前，必须完成 `stability-code-review` 检视，并确认没有遗留问题。`stability-code-review` 是团队外部检查工具/skill，不是 Agent 内置能力；当前环境不可用时，先执行：

```sh
npm i @ohos-graphics/stability-code-review
```

安装后按工具说明执行检视。如果安装或执行失败，不要继续 push；需要在回复或 PR 说明中记录失败原因，并等待人工确认。以下为 Agent 提交约定，可能与历史人工提交风格不同；人工提交按团队现有规范执行。提交建议使用 `git commit -s` 自动生成 `Signed-off-by`，其姓名和邮箱来自 `git config user.name` 与 `git config user.email`，格式类似 `Signed-off-by: yaozhupeng <yaozhupeng@huawei.com>`。同时在 commit message 末尾额外空一行写入 `Co-Authored-By: Agent`：

```text
<type>(<scope>): <summary>

<body，可选>

Signed-off-by: <name> <email>

Co-Authored-By: Agent
```

没有明确项目要求时，`type` 优先使用 `fix`、`feat`、`refactor`、`test`、`docs`、`build`，`scope` 使用模块名或目录名。若关联 issue、缺陷单或需求单，在 body 中写清编号和影响范围。

## 知识路由

稳定背景知识放在 `docs/knowledge/`。改动前按场景读取对应文件：

| 场景 | 先读 | 代码锚点 | 验证重点 |
| --- | --- | --- | --- |
| `ImageSource`、`ImagePacker`、输入输出流、解码、编码、硬件 codec | `docs/knowledge/codec-pipeline.md` | `interfaces/innerkits/include/image_source.h`, `interfaces/innerkits/include/image_packer.h`, `frameworks/innerkitsimpl/codec/`, `frameworks/innerkitsimpl/stream/` | `imagesourcetest`、`streamtest`、对应 codec/ImagePacker 单测和 ImageSource/decode/encode fuzz |
| `PixelMap` 创建、内存类型、YUV/P010/ASTC、ASTC 编码、transform、parcel、GL 后处理 | `docs/knowledge/pixelmap-memory-model.md` | `interfaces/innerkits/include/pixel_map.h`, `interfaces/innerkits/include/pixel_astc.h`, `frameworks/innerkitsimpl/common/`, `frameworks/innerkitsimpl/converter/`, `frameworks/innerkitsimpl/egl_image/`, `plugins/common/libs/image/libextplugin/src/texture_encode/` | `pixelmaptest`、`imageformatconverttest`、`textureencodetest`、PixelMap/ASTC fuzz |
| 插件加载、格式识别、`.pluginmeta`、扩展格式能力 | `docs/knowledge/plugin-format-pipeline.md` | `plugins/manager/`, `plugins/common/libs/image/`, `AbsImageFormatAgent`, `AbsImageDecoder`, `AbsImageEncoder` | `PluginManagerTest`、`formatagentplugintest`、`pluginsmanagersrcframeworktest`、对应插件 fuzz |
| EXIF、XMP、metadata key、`Picture`、辅助图、HDR/gainmap | `docs/knowledge/metadata-picture-model.md` | `frameworks/innerkitsimpl/accessor/`, `frameworks/innerkitsimpl/picture/`, `frameworks/innerkitsimpl/utils/`, `interfaces/innerkits/include/` | `imageaccessortest`、`exifmetadatatest`、`xmpmetadatatest`、`picturetest`、metadata/Picture fuzz |
| `ImageCreator`、`ImageReceiver`、surface/native buffer、监听回调 | `docs/knowledge/creator-receiver-surface.md` | `frameworks/innerkitsimpl/creator/`, `frameworks/innerkitsimpl/receiver/`, `frameworks/kits/js/`, `frameworks/kits/native/` | `creatortest`、`creatormocktest`、`receivertest`、`image_receiver_native_test`、`imagereceiver_fuzzer` |
| JS/NAPI、NDK/C API、CJ、ANI、Taihe、错误码映射、API 兼容 | `docs/knowledge/api-binding-surface.md` | `interfaces/kits/`, `frameworks/kits/js/`, `frameworks/kits/native/`, `frameworks/kits/cj/`, `frameworks/kits/ani/`, `frameworks/kits/taihe/` | `napitest`、`ndktest`、`ndktest2`、`image_cj_test`、对应 XTS |
| Fuzz、安全解析、Parcel/TLV、跨进程传输、异常输入 | `docs/knowledge/fuzz-security-parsing.md` | `frameworks/innerkitsimpl/test/fuzztest/`, `frameworks/innerkitsimpl/codec/`, `frameworks/innerkitsimpl/accessor/`, `plugins/common/libs/image/`, Parcel/TLV 相关实现 | 对应 fuzz 目标、截断/畸形/超大输入样例、相关单测和 XTS |

术语路由：

| 触发词 | 优先读取 | 重点 |
| --- | --- | --- |
| `ImageSource`、`ImagePacker`、region decode、incremental、硬解、`SkCodec`、`Heif`、`Avif` | `docs/knowledge/codec-pipeline.md` | 输入流、格式探测、解码/编码主链路和插件选择 |
| `PixelMap`、allocator、`DMA_ALLOC`、`SHARE_MEM_ALLOC`、`HEAP_ALLOC`、`CUSTOM_ALLOC`、No-Padding、ASTC、P010、YUV、GL 后处理 | `docs/knowledge/pixelmap-memory-model.md` | 内存类型、生命周期、转换、ASTC 编码、Parcel/TLV |
| `.pluginmeta`、format agent、`AbsImageDecoder`、`AbsImageEncoder`、插件加载、格式能力 | `docs/knowledge/plugin-format-pipeline.md` | 元数据、格式识别、插件注册和能力查询一致性 |
| EXIF、XMP、metadata key、`Picture`、`AuxiliaryPicture`、gainmap、HDR metadata | `docs/knowledge/metadata-picture-model.md` | metadata 解析、公开 key、辅助图、HDR/gainmap 传输 |
| `ImageCreator`、`ImageReceiver`、SurfaceBuffer、native buffer、fence、listener、release/acquire | `docs/knowledge/creator-receiver-surface.md` | Surface 生命周期、回调线程、fd/buffer 释放 |
| NAPI、NDK、CJ、ANI、Taihe、错误码、ABI、XTS、公开枚举 | `docs/knowledge/api-binding-surface.md` | 多语言接口一致性、错误码映射、XTS 兼容 |
| TLV、Parcel、unmarshal、fuzz、越界、溢出、截断流、恶意图片、`PixelMapRecordParcel` | `docs/knowledge/fuzz-security-parsing.md` | 不可信输入、安全攻击面、fuzz 和跨进程传输 |

## 项目约束

不要做：

- 不要在解码、像素转换、metadata 解析、序列化或插件枚举的热点路径中增加全量扫描、重复大内存拷贝、字符串格式化或高频 INFO 日志。
- 不要只改某一层语言绑定来改变公开行为；图片格式、像素格式、内存分配方式、色彩空间、HDR 类型、metadata key 和错误码会影响 JS、NDK、Native、CJ、ANI、Taihe 等外部接口。
- 不要只改 `.pluginmeta`、format agent、decoder 或 encoder 中的一个入口来声明格式能力。
- 不要把缺失真实设备验证的 surface、DMA、HDR、硬件 codec 或显示效果改动描述为完整验证。
- 不要把 `PixelMapRecordParcel` 当作普通业务路径分析；它仅用于 RS 侧图片录制回放测试框架逻辑，除非任务明确涉及 RS 录制回放。
- 不要执行破坏性 git/文件操作或大范围机械重构，除非用户明确要求。

Ask before / 必须人工确认：

以下场景不是普通“建议确认”，而是 Agent 继续修改、提交或 push 前的门禁。触发后要向用户或模块责任人说明影响面、已读文档、计划改动和拟验证项，得到明确答复后再继续。

- 改公开 API/ABI、枚举值、结构体字段、错误码、默认值或 XTS 预期前，先确认兼容策略。
- 改 JS/NDK/CJ/ANI/Taihe 绑定、生成代码或接口命名时，先确认所有语言入口是否需要同步。
- 改插件格式能力、第三方库、license 或产品裁剪时，先确认插件矩阵和依赖边界。
- 改 `graphic_2d`、`drivers_peripheral`、`ability_runtime`、`napi`、`ipc` 等跨仓接口或 buffer 语义时，先确认依赖方公开头文件、调用方假设和跨仓验证方式。
- 改 `PixelMap` allocator、surface/native buffer、DMA、HDR 或硬件 codec 行为时，先确认生命周期、释放函数、真实设备验证条件和 fallback 策略。
- 改安全解析、Parcel/TLV 格式、fuzz 触发样例或历史漏洞修复时，先确认攻击面、兼容策略和回归用例。
- 需要真实设备验证但当前没有设备时，先确认是否允许只带本地验证结果继续。
- 改上述行为时，要同步检查错误码和各语言接口映射，包括 `interfaces/innerkits/include/media_errors.h`、`interfaces/kits/native/include/image/image_common.h`、`frameworks/kits/js/common/image_error_convert.cpp` 以及对应 NDK/CJ/NAPI 适配代码。

C++ 改动优先复用附近的 `CHECK_*`、`IMAGE_LOG*`、`SUCCESS`、`ERR_IMAGE_*` 等项目宏、错误码和日志习惯。

## 完成定义

Agent 最终回复必须包含：

- 读取过的知识文档和对应场景。
- 修改的文件、行为影响面和明确未修改的关键文件。
- 已执行的单测、fuzz、XTS 或真实设备验证命令；未执行时说明原因。
- XTS 目标或真实设备验证无法确认时，列出缺口和需要人工确认的问题。
- 若涉及提交或 push，说明 `stability-code-review` 结果、commit message 是否包含 `Signed-off-by` 和 `Co-Authored-By: Agent`。
