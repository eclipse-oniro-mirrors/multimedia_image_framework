/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

export namespace image {

  loadLibrary("image_ani");

  enum DecodingDynamicRange {
    AUTO = 0,
    SDR = 1,
    HDR = 2
  }

  enum PropertyKeyAni {
    BITS_PER_SAMPLE = 'BitsPerSample',
    ORIENTATION = 'Orientation',
    IMAGE_LENGTH = 'ImageLength',
    IMAGE_WIDTH = 'ImageWidth',
    GPS_LATITUDE = 'GPSLatitude',
    GPS_LONGITUDE = 'GPSLongitude',
    GPS_LATITUDE_REF = 'GPSLatitudeRef',
    GPS_LONGITUDE_REF = 'GPSLongitudeRef',
    DATE_TIME_ORIGINAL = 'DateTimeOriginal',
    EXPOSURE_TIME = 'ExposureTime',
    SCENE_TYPE = 'SceneType',
    ISO_SPEED_RATINGS = 'ISOSpeedRatings',
    F_NUMBER = 'FNumber',
    DATE_TIME = 'DateTime',
    GPS_TIME_STAMP = 'GPSTimeStamp',
    GPS_DATE_STAMP = 'GPSDateStamp',
    IMAGE_DESCRIPTION = 'ImageDescription',
    MAKE = 'Make',
    MODEL = 'Model',
    PHOTO_MODE = 'PhotoMode',
    SENSITIVITY_TYPE = 'SensitivityType',
    STANDARD_OUTPUT_SENSITIVITY = 'StandardOutputSensitivity',
    RECOMMENDED_EXPOSURE_INDEX = 'RecommendedExposureIndex',
    ISO_SPEED = 'ISOSpeedRatings',
    APERTURE_VALUE = 'ApertureValue',
    EXPOSURE_BIAS_VALUE = 'ExposureBiasValue',
    METERING_MODE = 'MeteringMode',
    LIGHT_SOURCE = 'LightSource',
    FLASH = 'Flash',
    FOCAL_LENGTH = 'FocalLength',
    USER_COMMENT = 'UserComment',
    PIXEL_X_DIMENSION = 'PixelXDimension',
    PIXEL_Y_DIMENSION = 'PixelYDimension',
    WHITE_BALANCE = 'WhiteBalance',
    FOCAL_LENGTH_IN_35_MM_FILM = 'FocalLengthIn35mmFilm',
    CAPTURE_MODE = 'HwMnoteCaptureMode',
    PHYSICAL_APERTURE = 'HwMnotePhysicalAperture',
    ROLL_ANGLE = 'HwMnoteRollAngle',
    PITCH_ANGLE = 'HwMnotePitchAngle',
    SCENE_FOOD_CONF = 'HwMnoteSceneFoodConf',
    SCENE_STAGE_CONF = 'HwMnoteSceneStageConf',
    SCENE_BLUE_SKY_CONF = 'HwMnoteSceneBlueSkyConf',
    SCENE_GREEN_PLANT_CONF = 'HwMnoteSceneGreenPlantConf',
    SCENE_BEACH_CONF = 'HwMnoteSceneBeachConf',
    SCENE_SNOW_CONF = 'HwMnoteSceneSnowConf',
    SCENE_SUNSET_CONF = 'HwMnoteSceneSunsetConf',
    SCENE_FLOWERS_CONF = 'HwMnoteSceneFlowersConf',
    SCENE_NIGHT_CONF = 'HwMnoteSceneNightConf',
    SCENE_TEXT_CONF = 'HwMnoteSceneTextConf',
    FACE_COUNT = 'HwMnoteFaceCount',
    FOCUS_MODE = 'HwMnoteFocusMode',
    COMPRESSION = 'Compression',
    PHOTOMETRIC_INTERPRETATION = 'PhotometricInterpretation',
    STRIP_OFFSETS = 'StripOffsets',
    SAMPLES_PER_PIXEL = 'SamplesPerPixel',
    ROWS_PER_STRIP = 'RowsPerStrip',
    STRIP_BYTE_COUNTS = 'StripByteCounts',
    X_RESOLUTION = 'XResolution',
    Y_RESOLUTION = 'YResolution',
    PLANAR_CONFIGURATION = 'PlanarConfiguration',
    RESOLUTION_UNIT = 'ResolutionUnit',
    TRANSFER_FUNCTION = 'TransferFunction',
    SOFTWARE = 'Software',
    ARTIST = 'Artist',
    WHITE_POINT = 'WhitePoint',
    PRIMARY_CHROMATICITIES = 'PrimaryChromaticities',
    YCBCR_COEFFICIENTS = 'YCbCrCoefficients',
    YCBCR_SUB_SAMPLING = 'YCbCrSubSampling',
    YCBCR_POSITIONING = 'YCbCrPositioning',
    REFERENCE_BLACK_WHITE = 'ReferenceBlackWhite',
    COPYRIGHT = 'Copyright',
    JPEG_INTERCHANGE_FORMAT = 'JPEGInterchangeFormat',
    JPEG_INTERCHANGE_FORMAT_LENGTH = 'JPEGInterchangeFormatLength',
    EXPOSURE_PROGRAM = 'ExposureProgram',
    SPECTRAL_SENSITIVITY = 'SpectralSensitivity',
    OECF = 'OECF',
    EXIF_VERSION = 'ExifVersion',
    DATE_TIME_DIGITIZED = 'DateTimeDigitized',
    COMPONENTS_CONFIGURATION = 'ComponentsConfiguration',
    SHUTTER_SPEED = 'ShutterSpeedValue',
    BRIGHTNESS_VALUE = 'BrightnessValue',
    MAX_APERTURE_VALUE = 'MaxApertureValue',
    SUBJECT_DISTANCE = 'SubjectDistance',
    SUBJECT_AREA = 'SubjectArea',
    MAKER_NOTE = 'MakerNote',
    SUBSEC_TIME = 'SubsecTime',
    SUBSEC_TIME_ORIGINAL = 'SubsecTimeOriginal',
    SUBSEC_TIME_DIGITIZED = 'SubsecTimeDigitized',
    FLASHPIX_VERSION = 'FlashpixVersion',
    COLOR_SPACE = 'ColorSpace',
    RELATED_SOUND_FILE = 'RelatedSoundFile',
    FLASH_ENERGY = 'FlashEnergy',
    SPATIAL_FREQUENCY_RESPONSE = 'SpatialFrequencyResponse',
    FOCAL_PLANE_X_RESOLUTION = 'FocalPlaneXResolution',
    FOCAL_PLANE_Y_RESOLUTION = 'FocalPlaneYResolution',
    FOCAL_PLANE_RESOLUTION_UNIT = 'FocalPlaneResolutionUnit',
    SUBJECT_LOCATION = 'SubjectLocation',
    EXPOSURE_INDEX = 'ExposureIndex',
    SENSING_METHOD = 'SensingMethod',
    FILE_SOURCE = 'FileSource',
    CFA_PATTERN = 'CFAPattern',
    CUSTOM_RENDERED = 'CustomRendered',
    EXPOSURE_MODE = 'ExposureMode',
    DIGITAL_ZOOM_RATIO = 'DigitalZoomRatio',
    SCENE_CAPTURE_TYPE = 'SceneCaptureType',
    GAIN_CONTROL = 'GainControl',
    CONTRAST = 'Contrast',
    SATURATION = 'Saturation',
    SHARPNESS = 'Sharpness',
    DEVICE_SETTING_DESCRIPTION = 'DeviceSettingDescription',
    SUBJECT_DISTANCE_RANGE = 'SubjectDistanceRange',
    IMAGE_UNIQUE_ID = 'ImageUniqueID',
    GPS_VERSION_ID = 'GPSVersionID',
    GPS_ALTITUDE_REF = 'GPSAltitudeRef',
    GPS_ALTITUDE = 'GPSAltitude',
    GPS_SATELLITES = 'GPSSatellites',
    GPS_STATUS = 'GPSStatus',
    GPS_MEASURE_MODE = 'GPSMeasureMode',
    GPS_DOP = 'GPSDOP',
    GPS_SPEED_REF = 'GPSSpeedRef',
    GPS_SPEED = 'GPSSpeed',
    GPS_TRACK_REF = 'GPSTrackRef',
    GPS_TRACK = 'GPSTrack',
    GPS_IMG_DIRECTION_REF = 'GPSImgDirectionRef',
    GPS_IMG_DIRECTION = 'GPSImgDirection',
    GPS_MAP_DATUM = 'GPSMapDatum',
    GPS_DEST_LATITUDE_REF = 'GPSDestLatitudeRef',
    GPS_DEST_LATITUDE = 'GPSDestLatitude',
    GPS_DEST_LONGITUDE_REF = 'GPSDestLongitudeRef',
    GPS_DEST_LONGITUDE = 'GPSDestLongitude',
    GPS_DEST_BEARING_REF = 'GPSDestBearingRef',
    GPS_DEST_BEARING = 'GPSDestBearing',
    GPS_DEST_DISTANCE_REF = 'GPSDestDistanceRef',
    GPS_DEST_DISTANCE = 'GPSDestDistance',
    GPS_PROCESSING_METHOD = 'GPSProcessingMethod',
    GPS_AREA_INFORMATION = 'GPSAreaInformation',
    GPS_DIFFERENTIAL = 'GPSDifferential',
    BODY_SERIAL_NUMBER = 'BodySerialNumber',
    CAMERA_OWNER_NAME = 'CameraOwnerName',
    COMPOSITE_IMAGE = 'CompositeImage',
    COMPRESSED_BITS_PER_PIXEL = 'CompressedBitsPerPixel',
    DNG_VERSION = 'DNGVersion',
    DEFAULT_CROP_SIZE = 'DefaultCropSize',
    GAMMA = 'Gamma',
    ISO_SPEED_LATITUDE_YYY = 'ISOSpeedLatitudeyyy',
    ISO_SPEED_LATITUDE_ZZZ = 'ISOSpeedLatitudezzz',
    LENS_MAKE = 'LensMake',
    LENS_MODEL = 'LensModel',
    LENS_SERIAL_NUMBER = 'LensSerialNumber',
    LENS_SPECIFICATION = 'LensSpecification',
    NEW_SUBFILE_TYPE = 'NewSubfileType',
    OFFSET_TIME = 'OffsetTime',
    OFFSET_TIME_DIGITIZED = 'OffsetTimeDigitized',
    OFFSET_TIME_ORIGINAL = 'OffsetTimeOriginal',
    SOURCE_EXPOSURE_TIMES_OF_COMPOSITE_IMAGE = 'SourceExposureTimesOfCompositeImage',
    SOURCE_IMAGE_NUMBER_OF_COMPOSITE_IMAGE = 'SourceImageNumberOfCompositeImage',
    SUBFILE_TYPE = 'SubfileType',
    GPS_H_POSITIONING_ERROR = 'GPSHPositioningError',
    PHOTOGRAPHIC_SENSITIVITY = 'PhotographicSensitivity',
    BURST_NUMBER = 'HwMnoteBurstNumber',
    FACE_CONF = 'HwMnoteFaceConf',
    FACE_LEYE_CENTER = 'HwMnoteFaceLeyeCenter',
    FACE_MOUTH_CENTER = 'HwMnoteFaceMouthCenter',
    FACE_POINTER = 'HwMnoteFacePointer',
    FACE_RECT = 'HwMnoteFaceRect',
    FACE_REYE_CENTER = 'HwMnoteFaceReyeCenter',
    FACE_SMILE_SCORE = 'HwMnoteFaceSmileScore',
    FACE_VERSION = 'HwMnoteFaceVersion',
    FRONT_CAMERA = 'HwMnoteFrontCamera',
    SCENE_POINTER = 'HwMnoteScenePointer',
    SCENE_VERSION = 'HwMnoteSceneVersion',
    IS_XMAGE_SUPPORTED = 'HwMnoteIsXmageSupported',
    XMAGE_MODE = 'HwMnoteXmageMode',
    XMAGE_LEFT = 'HwMnoteXmageLeft',
    XMAGE_TOP = 'HwMnoteXmageTop',
    XMAGE_RIGHT = 'HwMnoteXmageRight',
    XMAGE_BOTTOM = 'HwMnoteXmageBottom',
    CLOUD_ENHANCEMENT_MODE = 'HwMnoteCloudEnhancementMode',
    WIND_SNAPSHOT_MODE = 'HwMnoteWindSnapshotMode',
    GIF_LOOP_COUNT = 'GIFLoopCount'
  }

  enum AntiAliasingLevel {
    NONE = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
  }

  enum HdrMetadataKey {
    HDR_METADATA_TYPE = 0,
    HDR_STATIC_METADATA = 1,
    HDR_DYNAMIC_METADATA = 2,
    HDR_GAINMAP_METADATA = 3,
  }

  enum HdrMetadataType {
    NONE = 0,
    BASE = 1,
    GAINMAP = 2,
    ALTERNATE = 3,
  }

  enum PackingDynamicRange {
    AUTO = 0,
    SDR = 1,
  }

  enum ScaleMode {
    FIT_TARGET_SIZE = 0,
    CENTER_CROP = 1
  }

  enum AuxiliaryPictureType {
    GAINMAP = 1,
    DEPTH_MAP = 2,
    UNREFOCUS_MAP = 3,
    LINEAR_MAP = 4,
    FRAGMENT_MAP = 5,
  }

  enum MetadataType {
    EXIF_METADATA = 1,
    FRAGMENT_METADATA = 2,
  }

  enum PixelMapFormat {
    UNKNOWN = 0,
    RGB_565 = 2,
    RGBA_8888 = 3,
    BGRA_8888 = 4,
    RGB_888 = 5,
    ALPHA_8 = 6,
    RGBA_F16 = 7,
    NV21 = 8,
    NV12 = 9,
    RGBA_1010102 = 10,
    YCBCR_P010 = 11,
    YCRCB_P010 = 12
  }

  enum AlphaType {
    UNKNOWN = 0,
    OPAQUE = 1,
    PREMUL = 2,
    UNPREMUL = 3
  }

  // common
  export interface Size {
    width: int,
    height: int,
  }

  class SizeInner implements Size {
    constructor(w: int, h: int) {
      this.width = w;
      this.height = h;
    }
    width: int;
    height: int;
  }

  export interface Region {
    size: Size;
    x: int;
    y: int;
  }

  interface PositionArea {
    pixels: ArrayBuffer;
    offset: int;
    stride: int;
    region: Region;
  }

  export interface ImageInfo {
    size: Size;
    density: int;
    stride: int;
    pixelFormat: int;
    alphaType: int;
    mimeType: string;
    isHdr: boolean;
  }

  class ImageInfoInner implements ImageInfo {
    size: Size = { width: 0, height: 0 };
    density: int = 0;
    stride: int = 0;
    pixelFormat: int = 0;
    alphaType: int = 0;
    mimeType: string = " ";
    isHdr: boolean = false;
  }
  // end common

  // pixelmap
  export interface InitializationOptions {
    size: Size;
    srcPixelFormat?: Int;
    pixelFormat?: Int;
    editable?: boolean;
    alphaType?: Int;
    scaleMode?: Int;
  }

  export class InitializationOptionsInner implements InitializationOptions {
    size: Size = { width: 0, height: 0 };
    pixelFormat?: Int | undefined = 0;
    srcPixelFormat?: Int | undefined = 0;
    editable?: boolean | undefined = false;
    alphaType?: Int | undefined = 0;
    scaleMode?: Int | undefined = 0;
  }

  export interface PixelMap {
    createAlphaPixelmapSync(): PixelMap;
    createAlphaPixelmap(): Promise<PixelMap>;
    getImageInfoSync(): ImageInfo;
    getImageInfo(): Promise<ImageInfo>;
    getPixelBytesNumber(): int;
    readPixelsToBufferSync(buff: ArrayBuffer);
    readPixelsToBuffer(buff: ArrayBuffer): Promise<void>;
    release(): Promise<void>;
  }

  class PixelMapInner implements PixelMap {
    private nativeObj: long = 0;

    constructor(context: long) {
      if (this.nativeObj == 0) {
        this.nativeObj = context;
      }
    }

    native nativeCreateAlphaPixelmap(): PixelMap;

    public createAlphaPixelmapSync(): PixelMap {
      return this.nativeCreateAlphaPixelmap();
    }

    public createAlphaPixelmap(): Promise<PixelMap> {
      return new Promise<PixelMap>((resolve: (v: PixelMap) => void, reject: (error: Object) => void) => {
        const cb = (): PixelMap => {
          return this.nativeCreateAlphaPixelmap();
        };
        taskpool.execute(cb)
          .then((e: NullishType) => resolve(e as PixelMap));
      });
    }

    native nativeGetImageInfo(): ImageInfo;

    public getImageInfoSync(): ImageInfo {
      return this.nativeGetImageInfo();
    }

    public getImageInfo(): Promise<ImageInfo> {
      return new Promise<ImageInfo>((resolve: (v: ImageInfo) => void, reject: (error: Object) => void) => {
        const cb = (): ImageInfo => {
          return this.nativeGetImageInfo();
        };
        taskpool.execute(cb)
          .then((e: NullishType) => resolve(e as ImageInfo));
      });
    }

    native getPixelBytesNumber(): int;

    native nativeReadPixelsToBuffer(buff: ArrayBuffer): void;

    public readPixelsToBufferSync(buff: ArrayBuffer): void {
      return this.nativeReadPixelsToBuffer(buff);
    }

    public readPixelsToBuffer(buff: ArrayBuffer): Promise<void> {
      return new Promise<void>((resolve: (v: Promise<void>) => void, reject: (error: Object) => void) => {
        const cb = (): boolean => {
          this.nativeReadPixelsToBuffer(buff);
          return true;
        };
        taskpool.execute(cb)
          .then((): void => resolve(Promise.resolve()));
      });
    }

    native nativeRelease(): void;

    public release(): Promise<void> {
      return new Promise<void>((resolve: (v: Promise<void>) => void, reject: (error: Object) => void) => {
        const cb = (): boolean => {
          this.nativeRelease();
          return true;
        };
        taskpool.execute(cb)
          .then((): void => resolve(Promise.resolve()));
      });
    }
  }

  export native function createPixelMapSync(options: InitializationOptions): PixelMap;

  // end pixelmap

  // imageSource
  export interface SourceOptions {
    sourceDensity: int;
    sourcePixelFormat?: int;
    sourceSize?: Size;
  }

  interface ImagePropertyOptions {
    index?: int;
    defaultValue?: string;
  }

  interface GetImagePropertyOptions {
    index?: int;
    defaultValue?: string;
  }

  export interface DecodingOptions {
    index?: Int;
    sampleSize?: Int;
    rotate?: Int;
    editable?: Int;
    desiredSize?: Size;
    desiredRegion?: Region;
    desiredPixelFormat?: Int;
    fitDensity?: Int;
    desiredColorSpace?: Int;
    desiredDynamicRange?: Int;
    resolutionQuality?: Int;
  }

  export class DecodingOptionsInner implements DecodingOptions {
    index?: Int | undefined = 0;
    sampleSize?: Int | undefined = 1;
    rotate?: Int | undefined = 0;
    editable?: Int | undefined = 0;
    desiredSize?: Size | undefined = { width: 100, height: 200 }
    desiredRegion?: Region | undefined = { size: { width: 10, height: 20 }, x: 30, y: 40 };
    desiredPixelFormat?: Int | undefined = 3;
    fitDensity?: Int | undefined = 1;
    desiredColorSpace?: Int | undefined = 1;
    desiredDynamicRange?: Int | undefined = 1;
    resolutionQuality?: Int | undefined = 1;
  }


  export interface ImageSource {
    getImageInfoSync(index: int): ImageInfo;
    getImageInfo(index: int): Promise<ImageInfo>;
    createPixelMapSync(options?: DecodingOptions): PixelMap;
    createPixelMap(options?: DecodingOptions): Promise<PixelMap>;
    modifyImageProperty(key: string, value: string): void;
    modifyImageProperties(records: Record<string, string>): void;
    getImageProperties(key: Array<string>): Record<string, string>;
    release(): void;
  }


  export class ImageSourceInner implements ImageSource {
    private nativeObj: long = 0;

    constructor(context: long) {
      if (this.nativeObj == 0) {
        this.nativeObj = context;
      }
    }
    native nativeGetImageInfo(index: int): ImageInfo;
    native nativeCreatePixelMap(options?: DecodingOptions): PixelMap;
    private native modifyImageProperty(nativeObj: long, key: string, value: string): void;
    native modifyImageProperties(records: Record<string, string>): void;
    native getImageProperties(key: Array<string>): Record<string, string>;
    native release(): void;

    public createPixelMapSync(options?: DecodingOptions): PixelMap {
      return this.nativeCreatePixelMap(options);
    }

    public createPixelMap(options?: DecodingOptions): Promise<PixelMap> {
      return new Promise<PixelMap>((resolve: (v: PixelMap) => void, reject: (error: Object) => void) => {
        const cb = (): PixelMap => {
          return this.nativeCreatePixelMap(options);
        };
        taskpool.execute(cb)
          .then((e: NullishType) => resolve(e as PixelMap));
      });
    }

    public modifyImageProperty(key: string, value: string): void {
      this.modifyImageProperty(this.nativeObj, key, value);
      return;
    }

    public getImageInfoSync(index: int): ImageInfo {
      return this.nativeGetImageInfo(index);
    }

    public getImageInfo(index: int): Promise<ImageInfo> {
      return new Promise<ImageInfo>((resolve: (v: ImageInfo) => void, reject: (error: Object) => void) => {
        const cb = (): ImageInfo => {
          return this.nativeGetImageInfo(index);
        };
        taskpool.execute(cb)
          .then((e: NullishType) => resolve(e as ImageInfo));
      });
    }
  }

  native function nativeCreateImageSourceByUri(uri: string): ImageSource;
  native function nativeCreateImageSourceByFd(fd: Int): ImageSource;

  export function createImageSource(uri: string): ImageSource {
    return nativeCreateImageSourceByUri(uri);
  }
  export function createImageSource(fd: Int): ImageSource {
    return nativeCreateImageSourceByFd(fd);
  }
  // end imagesource

  //imagepacker
  interface PackingOptionsForSequence {
    frameCount: int;
    delayTimeList: Array<int>;
    disposalTypes?: Array<int>;
    loopCount?: int;
  }

  interface PackingOptionInterface {
    format: string;
    quality: Int;
    bufferSize?: Int;
    desiredDynamicRange?: Int;
    needsPackProperties?: Int;
  }

  export class PackingOption implements PackingOptionInterface {
    format: string = "";
    quality: Int = 0;
    bufferSize?: Int | undefined = 20971520;
    desiredDynamicRange?: Int | undefined = 0;
    needsPackProperties?: Int | undefined = 0;
  }

  export interface ImagePacker {
    packing(source: PixelMap, option: PackingOption): ArrayBuffer;
    release(): void;
  }

  class ImagePackerInner implements ImagePacker {
    private nativeObj: long = 0;

    constructor(context: long) {
      if (this.nativeObj == 0) {
        this.nativeObj = context;
      }
    }

    native nativePackingWithPixelMap(source: PixelMap, option: PackingOption): ArrayBuffer;

    native nativeRelease(): void;

    public release(): void {
      this.nativeRelease();
    }

    public packing(source: PixelMap, option: PackingOption): ArrayBuffer {
      return this.nativePackingWithPixelMap(source, option);
    }
    supportedFormats: Array<string> = new Array<string>("");
  }

  export native function createImagePacker(): ImagePacker;
  // end imagepcker

  // metadata
  type HdrMetadataValue = HdrMetadataType | HdrStaticMetadata | ArrayBuffer | HdrGainmapMetadata;

  interface HdrStaticMetadata {
    displayPrimariesX: Array<double>;
    displayPrimariesY: Array<double>;
    whitePointX: double;
    whitePointY: double;
    maxLuminance: double;
    minLuminance: double;
    maxContentLightLevel: double;
    maxFrameAverageLightLevel: double;
  }

  interface GainmapChannel {
    gainmapMax: double;
    gainmapMin: double;
    gamma: double;
    baseOffset: double;
    alternateOffset: double;
  }

  interface Metadata {
    getProperties(key: Array<string>): Promise<Record<string, string | null>>
    setProperties(records: Record<string, string | null>): Promise<void>
    getAllProperties(): Promise<Record<string, string | null>>
    clone(): Promise<Metadata>
  }
  // END Meta

  interface HdrGainmapMetadata {
    writerVersion: int;
    miniVersion: int;
    gainmapChannelCount: int;
    useBaseColorFlag: boolean;
    baseHeadroom: double;
    alternateHeadroom: double;
    channels: Array<GainmapChannel>;
  }

  // picture
  interface AuxiliaryPicture {
    writePixelsFromBuffer(data: ArrayBuffer): Promise<void>;
    readPixelsToBuffer(): Promise<ArrayBuffer>;
    getType(): AuxiliaryPictureType;
    setMetadata(metadataType: MetadataType, metadata: Metadata): Promise<void>
    getMetadata(metadataType: MetadataType): Promise<Metadata>
    getAuxiliaryPictureInfo(): AuxiliaryPictureInfo;
    setAuxiliaryPictureInfo(info: AuxiliaryPictureInfo): void
    release(): void
  }

  interface AuxiliaryPictureInfo {
    auxiliaryPictureType: AuxiliaryPictureType;
    size: Size;
    rowStride: number;
    pixelFormat: PixelMapFormat;
    colorSpace: int;
  }

  interface DecodingOptionsForPicture {
    desiredAuxiliaryPictures: Array<int>; // Array<AuxiliaryPictureType>
  }
} // namespace