

# Image组件

- [简介](#introduction)
- [目录](#index)
- [使用说明](#usage-guidelines)
  - [读像素到数组](#readPixelsToBuffer)
  - [从区域读像素](readpixels)
  - [写像素到区域](#writePixels)
  - [写buffer到像素](#writeBufferToPixels)
  - [获取图片基本信息](#getImageInfo1)
  - [获取字节](#getBytesNumberPerRow)
  - [获取位图buffer](#getPixelBytesNumber)
  - [获取像素密度](#getDensity)
  - [设置透明比率](#opacity)
  - [生成Alpha通道](#createAlphaPixelmap)
  - [图片缩放](#scale)
  - [位置变换](#translate)
  - [图片旋转](#rotate)
  - [图片翻转](#flip)
  - [图片裁剪](#crop)
  - [释放位图](#release1)
  - [从图片源获取信息](#getImageInfo)
  - [获取整型值](#getImagePropertyInt)
  - [修改图片属性](#modifyImageProperty)
  - [创建位图](#createPixelMap)
  - [更新数据](#updateData)
  - [释放图片源实例](#release2)
  - [打包图片](#packing)
  - [释放packer实例](#release3)
  - [获取surface id](#getReceivingSurfaceId)
  - [读取最新图片](#readLatestImage)
  - [读取下一张图片](#readNextImage)
  - [注册回调](#on)
  - [释放receiver实例](#release4)
  - [获取组件缓存](#getComponent)
  - [释放image实例](#release5)
  - [CreateIncrementalSource](#CreateIncrementalSource)
  - [创建ImageSource实例](#createImageSource2)
  - [创建PixelMap实例](#createPixelMap2)
  - [创建imagepacker实例](#createImagePacker2)
  - [创建imagereceiver实例](#createImageReceiver2)

## 简介<a name="introduction"></a>

**image_framework仓库**提供了一系列易用的接口用于存放image的源码信息，提供创建图片源和位图管理能力，支持运行标准系统的设备使用。

**图1** Image组件架构图

![](https://gitee.com/openharmony/multimedia_image_framework/raw/master/figures/Image%E7%BB%84%E4%BB%B6%E6%9E%B6%E6%9E%84%E5%9B%BE.png)



支持能力列举如下：

- 创建、释放位图。
- 读写像素。
- 获取位图信息。
- 创建、释放图片源。
- 获取图片源信息。
- 创建、释放packer实例。

## 目录<a name="index"></a>

仓目录结构如下：

```
/foundation/multimedia/image_framework  
├── frameworks                                  # 框架代码
│   ├── innerkitsimpl                           # 内部接口实现
│   │   └──image                                # Native 实现
│   └── kitsimpl                                # 外部接口实现
│       └──image                                # 外部  NAPI 实现
├── interfaces                                  # 接口代码
│   ├── innerkits                               # 内部 Native 接口
│   └── kits                                    # 外部 JS 接口
├── LICENSE                                     # 证书文件
├── ohos.build                                  # 编译文件
├── sa_profile                                  # 服务配置文件
└── services                                    # 服务实现
```

## 使用说明<a name="usage-guidelines"></a>

### 1.读像素到数组<a name="readPixelsToBuffer"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何将像素读到缓冲区。

通过调用readPixelsToBuffer读pixels到buffer。

```
readPixelsToBuffer(dst: ArrayBuffer): Promise<void>;
readPixelsToBuffer(dst: ArrayBuffer, callback: AsyncCallback<void>): void;
```

示例：

```
pixelmap.readPixelsToBuffer(readBuffer).then(() => {})
```

### 2.读pixels<a name="readPixels"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何按照区域读像素。

通过调用readPixels读pixels。

```
readPixels(area: PositionArea): Promise<void>;
readPixels(area: PositionArea, callback: AsyncCallback<void>): void;
```

示例：

```
pixelmap.readPixels(area).then(() => {})
```

### 3.写pixels<a name="writePixels"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何写像素。

通过调用writepixels写到指定区域。

```
writePixels(area: PositionArea): Promise<void>;
writePixels(area: PositionArea, callback: AsyncCallback<void>): void;
```

示例：

```
pixelmap.writePixels(area, () => {})
```

### 4.writeBufferToPixels<a name="writeBufferToPixels"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何将数据写进pixels。

通过调用writeBufferToPixels写到pixel。

```
writeBufferToPixels(src: ArrayBuffer): Promise<void>;
writeBufferToPixels(src: ArrayBuffer, callback: AsyncCallback<void>): void;
```

示例：

```
pixelmap.writeBufferToPixels(writeColor, () => {})
```

### 5.getImageInfo<a name="getImageInfo1"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何获取图片信息。

通过调用getImageInfo获取图片基本信息。

1.使用create通过属性创建pixelmap。

```
image.createPixelMap(color, opts, pixelmap =>{})
```

2.使用getImageInfo获取图片基本信息。

```
pixelmap.getImageInfo( imageInfo => {})
```

### 6.getBytesNumberPerRow<a name="getBytesNumberPerRow"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何获取每行字节数。

通过调用getBytesNumberPerRow获取字节数。

```
getBytesNumberPerRow(): Promise<number>;
getBytesNumberPerRow(callback: AsyncCallback<number>): void;
```

示例：

```
pixelmap.getBytesNumberPerRow((num) => {})
```

### 7.getPixelBytesNumber<a name="getPixelBytesNumber"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何获取buffer。

通过调用getPixelBytesNumber获取buffer数。

```
getPixelBytesNumber(): Promise<number>;
getPixelBytesNumber(callback: AsyncCallback<number>): void;
```

示例：

```
pixelmap.getPixelBytesNumber().then((num) => {
          console.info('TC_026 num is ' + num)
          expect(num == expectNum).assertTrue()
          done()
        })
```

### 8.getDensity<a name="getDensity"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何获取图片像素密度。

通过调用getDensity获取图片像素密度。

```
getDensity():number;
```

示例：

```
let getDensity = pixelmap.getDensity();
```

### 9.opacity<a name="opacity"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何设置图片透明比率。

通过调用opacity设置图片透明比率。

```
opacity(rate: number, callback: AsyncCallback<void>): void;
opacity(rate: number): Promise<void>;
```

示例：

```
async function () {
	await pixelMap.opacity(0.5);
}
```

### 10.createAlphaPixelmap<a name="createAlphaPixelmap"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何生成一个仅包含Alpha通道信息的pixelmap。

通过调用createAlphaPixelmap生成一个仅包含Alpha通道信息的pixelmap，可用于阴影效果。

```
createAlphaPixelmap(): Promise<PixelMap>;
createAlphaPixelmap(callback: AsyncCallback<PixelMap>): void;
```

示例：

```
pixelMap.createAlphaPixelmap(async (err, alphaPixelMap) => {})
```

### 11.scale<a name="scale"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何根据输入的宽高对图片进行缩放。

通过调用scale对图片进行缩放。

```
scale(x: number, y: number, callback: AsyncCallback<void>): void;
scale(x: number, y: number): Promise<void>;
```

示例：

```
await pixelMap.scale(2.0, 1.0);
```

### 12.translate<a name="translate"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何根据输入的坐标对图片进行位置变换。

通过调用translate对图片进行位置变换。

```
translate(x: number, y: number, callback: AsyncCallback<void>): void;
translate(x: number, y: number): Promise<void>;
```

示例：

```
await pixelMap.translate(3.0, 1.0);
```

### 13.rotate<a name="rotate"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何根据输入的角度对图片进行旋转。

通过调用rotate对图片进行旋转。

```
rotate(angle: number, callback: AsyncCallback<void>): void;
rotate(angle: number): Promise<void>;
```

示例：

```
await pixelMap.rotate(90.0);
```

### 14.flip<a name="flip"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何根据输入的条件对图片进行翻转。

通过调用flip对图片进行翻转。

```
flip(horizontal: boolean, vertical: boolean, callback: AsyncCallback<void>): void;
flip(horizontal: boolean, vertical: boolean): Promise<void>;
```

示例：

```
await pixelMap.flip(false, true);
```

### 15.crop<a name="crop"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何根据输入的尺寸对图片进行裁剪。

通过调用crop对图片进行裁剪。

```
crop(region: Region, callback: AsyncCallback<void>): void;
crop(region: Region): Promise<void>;
```

示例：

```
await pixelMap.crop({ x: 0, y: 0, size: { height: 100, width: 100 } });
```

### 16.release<a name="release1"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何释放pixelmap实例。

通过调用release释放pixelmap。

1.使用create通过属性创建pixelmap。

```
image.createPixelMap(color, opts, pixelmap =>{}
```

2.使用release释放pixelmap实例

```
pixelmap.release(()=>{
            expect(true).assertTrue();
            console.log('TC_027-1 suc');
            done();
        })  
```

### 17.getImageInfo<a name="getImageInfo"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何根据特定数字获取图片信息。

```
getImageInfo(index: number, callback: AsyncCallback<ImageInfo>): void;
getImageInfo(callback: AsyncCallback<ImageInfo>): void;
getImageInfo(index?: number): Promise<ImageInfo>;
```

1.创建imagesource。

```
const imageSourceApi = image.createImageSource('/sdcard/test.jpg')
```

2.获取图片信息。

```
imageSourceApi.getImageInfo((imageInfo) => {
        console.info('TC_045 imageInfo')
        expect(imageInfo !== null).assertTrue()
        done()
      })
```

### 18.getImageProperty<a name="getImageProperty"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何根据索引获取图像的指定属性键的值。

```
getImageProperty(key:string, options?: GetImagePropertyOptions): Promise<string>;
getImageProperty(key:string, callback: AsyncCallback<string>): void;
```

### 19.modifyImageProperty<a name="modifyImageProperty"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何通过指定的键修改图片属性的值。

```
modifyImageProperty(key: string, value: string): Promise<void>;
modifyImageProperty(key: string, value: string, callback: AsyncCallback<void>): void;
```

### 20.createPixelMap<a name="createPixelMap"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何创建pixelmap实例。

1.使用createImageSource创建图片源。

```
const imageSourceApi = image.createImageSource('/sdcard/test.jpg')
```

2.使用createPixelMap创建pixelmap

```
imageSourceApi.createPixelMap(decodingOptions, (pixelmap) => {})
```

### 21.updateData<a name="updateData"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何更新图片数据源。

```
updateData(buf: ArrayBuffer, isFinished: boolean, value: number, length: number): Promise<void>;
updateData(buf: ArrayBuffer, isFinished: boolean, value: number, length: number, callback: AsyncCallback<void>): void;
```

1.使用CreateIncrementalSource创建imagesource。

```
const dataBuffer = new ArrayBuffer(96)
const imageSourceIncrementalSApi = image.CreateIncrementalSource(dataBuffer)
```

2.使用updateData更新图片源。

```
imageSourceIncrementalSApi.updateData(array, false, (error, data) => {})
```

### 22.release<a name="release2"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何释放图片源实例。

```
release(callback: AsyncCallback<void>): void;
release(): Promise<void>;
```

### 23.packing<a name="packing"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何压缩图片。

```
packing(source: ImageSource, option: PackingOption, callback: AsyncCallback<ArrayBuffer>): void;
packing(source: ImageSource, option: PackingOption): Promise<ArrayBuffer>;
packing(source: PixelMap, option: PackingOption, callback: AsyncCallback<ArrayBuffer>): void;
packing(source: PixelMap, option: PackingOption): Promise<ArrayBuffer>;
```

1.使用createImageSource创建图片源。

```
const imageSourceApi = image.createImageSource('/sdcard/test.png')
```

2.创建packer实例。

```
imagePackerApi.packing(imageSourceApi, packOpts).then((data) => {})
```

### 24.release<a name="release3"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何释放packer实例。

```
release(callback: AsyncCallback<void>): void;
release(): Promise<void>;
```

1.使用createImagePacker创建packer实例。

```
const imagePackerApi = image.createImagePacker()
```

2.使用release释放packer实例。

```
imagePackerApi.release()
```

### 25.getReceivingSurfaceId<a name="getReceivingSurfaceId"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何获取surface id供Camera或其他组件使用。

```
getReceivingSurfaceId(): Promise<string>;
getReceivingSurfaceId(callback: AsyncCallback<string>): void;
```

示例：
```
receiver.getReceivingSurfaceId().then( id => { } )
```

### 26.readLatestImage<a name="readLatestImage"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何读取最新的图片。

```
readLatestImage(callback: AsyncCallback<Image>): void;
readLatestImage(): Promise<Image>;
```

示例：
```
receiver.readLatestImage().then(img => { })
```

### 27.readNextImage<a name="readNextImage"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何读取下一张图片。

```
readNextImage(callback: AsyncCallback<Image>): void;
readNextImage(): Promise<Image>;
```

示例：
```
receiver.readNextImage().then(img => {})
```

### 28.on<a name="on"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何接收图片时注册回调。

```
on(type: 'imageArrival', callback: AsyncCallback<void>): void;
```

示例：
```
receiver.on('imageArrival', () => {})
```

### 29.release<a name="release4"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何释放receiver实例。

```
release(callback: AsyncCallback<void>): void;
release(): Promise<void>;
```

1.使用createImageReceiver创建receiver实例。

```
const imageReceiverApi = image.createImageReceiver()
```

2.使用release释放packer实例。

```
imageReceiverApi.release()
```

### 30.getComponent<a name="getComponent"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何根据图像的组件类型从图像中获取组件缓存。

```
getComponent(componentType: ComponentType, callback: AsyncCallback<Component>): void;
getComponent(componentType: ComponentType): Promise<Component>;
```

示例：
```
img.getComponent(4).then(component => { })
```

### 31.release<a name="release5"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何释放image实例。

```
release(callback: AsyncCallback<void>): void;
release(): Promise<void>;
```

### 32.CreateIncrementalSource<a name="CreateIncrementalSource"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何创建增量imagesource。

```
CreateIncrementalSource(buf: ArrayBuffer): ImageSource;
CreateIncrementalSource(buf: ArrayBuffer, options?: SourceOptions): ImageSource;
```

1.创建buffer。

```
const data = new ArrayBuffer(96)
```

2.使用CreateIncrementalSource创建imagesource。

```
const imageSourceApi = image.CreateIncrementalSource(data)
```

### 33.创建ImageSource实例<a name="createImageSource2"></a>

image提供了操作imagesource的接口，如创建、读取和删除，以下展示了如何通过不同方式创建imagesource。

1.通过文件路径创建imagesource。

```
createImageSource(uri: string): ImageSource;
createImageSource(uri: string, options: SourceOptions): ImageSource;
```

示例：
```
const imageSourceApi = image.createImageSource('/sdcard/test.jpg');
```

2.通过fd创建imagesource。

```
createImageSource(fd: number): ImageSource;
createImageSource(fd: number, options: SourceOptions): ImageSource;
```

示例：
```
const imageSourceApi = image.createImageSource(fd);
```

3.通过buffer创建imagesource。

```
createImageSource(buf: ArrayBuffer): ImageSource;
createImageSource(buf: ArrayBuffer, options: SourceOptions): ImageSource;
```

示例：
```
const data = new ArrayBuffer(112);
const imageSourceApi = image.createImageSource(data);
```

### 34.创建PixelMap实例<a name="createPixelMap2"></a>

image提供了操作pixelmap的接口，如创建、读取和删除，以下展示了如何通过属性创建pixelmap。

```
createPixelMap(colors: ArrayBuffer, options: InitializationOptions): Promise<PixelMap>;
createPixelMap(colors: ArrayBuffer, options: InitializationOptions, callback: AsyncCallback<PixelMap>): void;
```

1.设置属性。

```
const Color = new ArrayBuffer(96)
let opts = {
  alphaType: 0,
  editable: true,
  pixelFormat: 4,
  scaleMode: 1,
  size: { height: 2, width: 3 },
}
```

2.调用createpixelmap通过属性创建pixelmap实例。

```
image.createPixelMap(Color, opts)
      .then((pixelmap) => {
        expect(pixelmap !== null).assertTrue()
        console.info('Succeeded in creating pixelmap.')
        done()
      })
```

### 35.创建imagepacker实例<a name="createImagePacker2"></a>

image提供了操作imagepacker的接口，以下展示了如何通过属性创建imagepacker。

```
createImagePacker(): ImagePacker;
```

1.创建imagesource。

```
const imageSourceApi = image.createImageSource('/sdcard/test.png')
```

2.创建imagepacker。

```
const imagePackerApi = image.createImagePacker()
```

### 36.创建imagereceiver实例<a name="createImageReceiver2"></a>

image提供了操作imagereceiver的接口，以下展示了如何通过属性创建imagereceiver。

```
createImageReceiver(width: number, height: number, format: number, capacity: number): ImageReceiver;
```

## 相关仓<a name="relevant"></a>

[multimedia\_image\_framework](https://gitee.com/openharmony/multimedia_image_framework/blob/master/README_zh.md)