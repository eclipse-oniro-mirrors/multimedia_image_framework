/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

export class BusinessError<T = void> {
   code: number;
   data: T;
}

type AsyncCallback<T, E = void> = (err: BusinessError<E>, data: T) => void;


class Result<T, E>{
    result:T;
    error:E;
    constructor(result: T , error: E) {
        this.result = result;
        this.error = error;
    }
}

export namespace image {

enum DecodingDynamicRange {
  /**
    * Decoding according to the content of the image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  AUTO = 0,

  /**
    * Decoding to standard dynamic range.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  SDR = 1,

  /**
    * Decoding to high dynamic range.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  HDR = 2
}

enum PropertyKeyAni {
  /**
    * Number of bits in each pixel of an image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 7
    */
  /**
    * Number of bits in each pixel of an image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  BITS_PER_SAMPLE = 'BitsPerSample',

  /**
    * Image rotation mode.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 7
    */
  /**
    * Image rotation mode.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  ORIENTATION = 'Orientation',

  /**
    * Image length.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 7
    */
  /**
    * Image length.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  IMAGE_LENGTH = 'ImageLength',

  /**
    * Image width.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 7
    */
  /**
    * Image width.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  IMAGE_WIDTH = 'ImageWidth',

  /**
    * GPS latitude.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 7
    */
  /**
    * GPS latitude.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  GPS_LATITUDE = 'GPSLatitude',

  /**
    * GPS longitude.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 7
    */
  /**
    * GPS longitude.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  GPS_LONGITUDE = 'GPSLongitude',

  /**
    * GPS latitude reference. For example, N indicates north latitude and S indicates south latitude.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 7
    */
  /**
    * GPS latitude reference. For example, N indicates north latitude and S indicates south latitude.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  GPS_LATITUDE_REF = 'GPSLatitudeRef',

  /**
    * GPS longitude reference. For example, E indicates east longitude and W indicates west longitude.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 7
    */
  /**
    * GPS longitude reference. For example, E indicates east longitude and W indicates west longitude.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  GPS_LONGITUDE_REF = 'GPSLongitudeRef',

  /**
    * Shooting time
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 9
    */
  /**
    * Shooting time
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  DATE_TIME_ORIGINAL = 'DateTimeOriginal',

  /**
    * Exposure time
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 9
    */
  /**
    * Exposure time
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  EXPOSURE_TIME = 'ExposureTime',

  /**
    * Scene type
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 9
    */
  /**
    * Scene type
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  SCENE_TYPE = 'SceneType',

  /**
    * ISO speedratings
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 9
    */
  /**
    * ISO speedratings
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  ISO_SPEED_RATINGS = 'ISOSpeedRatings',

  /**
    * Aperture value
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 9
    */
  /**
    * Aperture value
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  F_NUMBER = 'FNumber',

  /**
    * Date time
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  DATE_TIME = 'DateTime',

  /**
    * GPS time stamp
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  GPS_TIME_STAMP = 'GPSTimeStamp',

  /**
    * GPS date stamp
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  GPS_DATE_STAMP = 'GPSDateStamp',

  /**
    * Image description
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  IMAGE_DESCRIPTION = 'ImageDescription',

  /**
    * Make
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  MAKE = 'Make',

  /**
    * Model
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  MODEL = 'Model',

  /**
    * Photo mode
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  PHOTO_MODE = 'PhotoMode',

  /**
    * Sensitivity type
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  SENSITIVITY_TYPE = 'SensitivityType',

  /**
    * Standard output sensitivity
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  STANDARD_OUTPUT_SENSITIVITY = 'StandardOutputSensitivity',

  /**
    * Recommended exposure index
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  RECOMMENDED_EXPOSURE_INDEX = 'RecommendedExposureIndex',

  /**
    * ISO speed
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  ISO_SPEED = 'ISOSpeedRatings',

  /**
    * Aperture value
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  APERTURE_VALUE = 'ApertureValue',

  /**
    * Exposure bias value
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  EXPOSURE_BIAS_VALUE = 'ExposureBiasValue',

  /**
    * Metering mode
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  METERING_MODE = 'MeteringMode',

  /**
    * Light source
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  LIGHT_SOURCE = 'LightSource',

  /**
    * Flash
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  FLASH = 'Flash',

  /**
    * Focal length
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  FOCAL_LENGTH = 'FocalLength',

  /**
    * User comment
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  USER_COMMENT = 'UserComment',

  /**
    * Pixel x dimension
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  PIXEL_X_DIMENSION = 'PixelXDimension',

  /**
    * Pixel y dimension
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  PIXEL_Y_DIMENSION = 'PixelYDimension',

  /**
    * White balance
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  WHITE_BALANCE = 'WhiteBalance',

  /**
    * Focal length in 35mm film
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  FOCAL_LENGTH_IN_35_MM_FILM = 'FocalLengthIn35mmFilm',

  /**
    * Capture mode
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  CAPTURE_MODE = 'HwMnoteCaptureMode',

  /**
    * Physical aperture
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 10
    */
  PHYSICAL_APERTURE = 'HwMnotePhysicalAperture',

  /**
    * Roll Angle
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  ROLL_ANGLE = 'HwMnoteRollAngle',

  /**
    * Pitch Angle
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  PITCH_ANGLE = 'HwMnotePitchAngle',

  /**
    * Capture Scene: Food
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  SCENE_FOOD_CONF = 'HwMnoteSceneFoodConf',

  /**
    * Capture Scene: Stage
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  SCENE_STAGE_CONF = 'HwMnoteSceneStageConf',

  /**
    * Capture Scene: Blue Sky
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  SCENE_BLUE_SKY_CONF = 'HwMnoteSceneBlueSkyConf',

  /**
    * Capture Scene: Green Plant
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  SCENE_GREEN_PLANT_CONF = 'HwMnoteSceneGreenPlantConf',

  /**
    * Capture Scene: Beach
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  SCENE_BEACH_CONF = 'HwMnoteSceneBeachConf',

  /**
    * Capture Scene: Snow
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  SCENE_SNOW_CONF = 'HwMnoteSceneSnowConf',

  /**
    * Capture Scene: Sunset
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  SCENE_SUNSET_CONF = 'HwMnoteSceneSunsetConf',

  /**
    * Capture Scene: Flowers
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  SCENE_FLOWERS_CONF = 'HwMnoteSceneFlowersConf',

  /**
    * Capture Scene: Night
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  SCENE_NIGHT_CONF = 'HwMnoteSceneNightConf',

  /**
    * Capture Scene: Text
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  SCENE_TEXT_CONF = 'HwMnoteSceneTextConf',

  /**
    * Face Count
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  FACE_COUNT = 'HwMnoteFaceCount',

  /**
    * Focus Mode
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 11
    */
  FOCUS_MODE = 'HwMnoteFocusMode',

  /**
    * The scheme used for image compression.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  COMPRESSION = 'Compression',

  /**
    * Pixel composition, such as RGB or YCbCr.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  PHOTOMETRIC_INTERPRETATION = 'PhotometricInterpretation',

  /**
    * For each strip, the byte offset of that strip.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  STRIP_OFFSETS = 'StripOffsets',

  /**
    * The number of components per pixel.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SAMPLES_PER_PIXEL = 'SamplesPerPixel',

  /**
    * The number of rows per strip of image data.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  ROWS_PER_STRIP = 'RowsPerStrip',

  /**
    * The total number of bytes in each strip of image data.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  STRIP_BYTE_COUNTS = 'StripByteCounts',

  /**
    * The image resolution in the width direction.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  X_RESOLUTION = 'XResolution',

  /**
    * The image resolution in the height direction.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  Y_RESOLUTION = 'YResolution',

  /**
    * Indicates whether pixel components are recorded in a chunky or planar format.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  PLANAR_CONFIGURATION = 'PlanarConfiguration',

  /**
    * The unit used to measure XResolution and YResolution.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  RESOLUTION_UNIT = 'ResolutionUnit',

  /**
    * The transfer function for the image, typically used for color correction.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  TRANSFER_FUNCTION = 'TransferFunction',

  /**
    * The name and version of the software used to generate the image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SOFTWARE = 'Software',

  /**
    * The name of the person who created the image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  ARTIST = 'Artist',

  /**
    * The chromaticity of the white point of the image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  WHITE_POINT = 'WhitePoint',

  /**
    * The chromaticity of the primary colors of the image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  PRIMARY_CHROMATICITIES = 'PrimaryChromaticities',

  /**
    * The matrix coefficients for transformation from RGB to YCbCr image data.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  YCBCR_COEFFICIENTS = 'YCbCrCoefficients',

  /**
    * The sampling ratio of chrominance components to the luminance component.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  YCBCR_SUB_SAMPLING = 'YCbCrSubSampling',

  /**
    * The position of chrominance components in relation to the luminance component.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  YCBCR_POSITIONING = 'YCbCrPositioning',

  /**
    * The reference black point value and reference white point value.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  REFERENCE_BLACK_WHITE = 'ReferenceBlackWhite',

  /**
    * Copyright information for the image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  COPYRIGHT = 'Copyright',

  /**
    * The offset to the start byte (SOI) of JPEG compressed thumbnail data.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  JPEG_INTERCHANGE_FORMAT = 'JPEGInterchangeFormat',

  /**
    * The number of bytes of JPEG compressed thumbnail data.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  JPEG_INTERCHANGE_FORMAT_LENGTH = 'JPEGInterchangeFormatLength',

  /**
    * The class of the program used by the camera to set exposure when the picture is taken.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  EXPOSURE_PROGRAM = 'ExposureProgram',

  /**
    * Indicates the spectral sensitivity of each channel of the camera used.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SPECTRAL_SENSITIVITY = 'SpectralSensitivity',

  /**
    * Indicates the Opto-Electric Conversion Function (OECF) specified in ISO 14524.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  OECF = 'OECF',

  /**
    * The version of the Exif standard supported.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  EXIF_VERSION = 'ExifVersion',

  /**
    * The date and time when the image was stored as digital data.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  DATE_TIME_DIGITIZED = 'DateTimeDigitized',

  /**
    * Information specific to compressed data.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  COMPONENTS_CONFIGURATION = 'ComponentsConfiguration',

  /**
    * The shutter speed, expressed as an APEX (Additive System of Photographic Exposure) value.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SHUTTER_SPEED = 'ShutterSpeedValue',

  /**
    * The brightness value of the image, in APEX units.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  BRIGHTNESS_VALUE = 'BrightnessValue',

  /**
    * The smallest F number of lens.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  MAX_APERTURE_VALUE = 'MaxApertureValue',

  /**
    * The distance to the subject, measured in meters.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SUBJECT_DISTANCE = 'SubjectDistance',

  /**
    * This tag indicate the location and area of the main subject in the overall scene.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SUBJECT_AREA = 'SubjectArea',

  /**
    * A tag for manufacturers of Exif/DCF writers to record any desired information.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  MAKER_NOTE = 'MakerNote',

  /**
    * A tag for record fractions of seconds for the DateTime tag.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SUBSEC_TIME = 'SubsecTime',

  /**
    * A tag used to record fractions of seconds for the DateTimeOriginal tag.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SUBSEC_TIME_ORIGINAL = 'SubsecTimeOriginal',

  /**
    * A tag used to record fractions of seconds for the DateTimeDigitized tag.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SUBSEC_TIME_DIGITIZED = 'SubsecTimeDigitized',

  /**
    * This tag denotes the Flashpix format version supported by an FPXR file, enhancing device compatibility.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FLASHPIX_VERSION = 'FlashpixVersion',

  /**
    * The color space information tag, often recorded as the color space specifier.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  COLOR_SPACE = 'ColorSpace',

  /**
    * The name of an audio file related to the image data.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  RELATED_SOUND_FILE = 'RelatedSoundFile',

  /**
    * Strobe energy at image capture, in BCPS.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FLASH_ENERGY = 'FlashEnergy',

  /**
    * Camera or input device spatial frequency table.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SPATIAL_FREQUENCY_RESPONSE = 'SpatialFrequencyResponse',

  /**
    * Pixels per FocalPlaneResolutionUnit in the image width.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FOCAL_PLANE_X_RESOLUTION = 'FocalPlaneXResolution',

  /**
    * Pixels per FocalPlaneResolutionUnit in the image height.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FOCAL_PLANE_Y_RESOLUTION = 'FocalPlaneYResolution',

  /**
    * Unit for measuring FocalPlaneXResolution and FocalPlaneYResolution.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FOCAL_PLANE_RESOLUTION_UNIT = 'FocalPlaneResolutionUnit',

  /**
    * Location of the main subject, relative to the left edge.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SUBJECT_LOCATION = 'SubjectLocation',

  /**
    * Selected exposure index at capture.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  EXPOSURE_INDEX = 'ExposureIndex',

  /**
    * Image sensor type on the camera.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SENSING_METHOD = 'SensingMethod',

  /**
    * Indicates the image source.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FILE_SOURCE = 'FileSource',

  /**
    * Color filter array (CFA) geometric pattern of the image sensor.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  CFA_PATTERN = 'CFAPattern',

  /**
    * Indicates special processing on image data.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  CUSTOM_RENDERED = 'CustomRendered',

  /**
    * Exposure mode set when the image was shot.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  EXPOSURE_MODE = 'ExposureMode',

  /**
    * Digital zoom ratio at the time of capture.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  DIGITAL_ZOOM_RATIO = 'DigitalZoomRatio',

  /**
    * Type of scene captured.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SCENE_CAPTURE_TYPE = 'SceneCaptureType',

  /**
    * Degree of overall image gain adjustment.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GAIN_CONTROL = 'GainControl',

  /**
    * Direction of contrast processing applied by the camera.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  CONTRAST = 'Contrast',

  /**
    * Direction of saturation processing applied by the camera.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SATURATION = 'Saturation',

  /**
    * The direction of sharpness processing applied by the camera.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SHARPNESS = 'Sharpness',

  /**
    * Information on picture-taking conditions for a specific camera model.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  DEVICE_SETTING_DESCRIPTION = 'DeviceSettingDescription',

  /**
    * Indicates the distance range to the subject.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SUBJECT_DISTANCE_RANGE = 'SubjectDistanceRange',

  /**
    * An identifier uniquely assigned to each image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  IMAGE_UNIQUE_ID = 'ImageUniqueID',

  /**
    * The version of the GPSInfoIFD.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_VERSION_ID = 'GPSVersionID',

  /**
    * Reference altitude used for GPS altitude.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_ALTITUDE_REF = 'GPSAltitudeRef',

  /**
    * The altitude based on the reference in GPSAltitudeRef.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_ALTITUDE = 'GPSAltitude',

  /**
    * The GPS satellites used for measurements.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_SATELLITES = 'GPSSatellites',

  /**
    * The status of the GPS receiver when the image is recorded.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_STATUS = 'GPSStatus',

  /**
    * The GPS measurement mode.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_MEASURE_MODE = 'GPSMeasureMode',

  /**
    * The GPS DOP (data degree of precision).
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_DOP = 'GPSDOP',

  /**
    * The unit used to express the GPS receiver speed of movement.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_SPEED_REF = 'GPSSpeedRef',

  /**
    * The speed of GPS receiver movement.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_SPEED = 'GPSSpeed',

  /**
    * The reference for giving the direction of GPS receiver movement.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_TRACK_REF = 'GPSTrackRef',

  /**
    * The direction of GPS receiver movement.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_TRACK = 'GPSTrack',

  /**
    * The reference for the image's direction.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_IMG_DIRECTION_REF = 'GPSImgDirectionRef',

  /**
    * The direction of the image when captured.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_IMG_DIRECTION = 'GPSImgDirection',

  /**
    * Geodetic survey data used by the GPS receiver.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_MAP_DATUM = 'GPSMapDatum',

  /**
    * Indicates the latitude reference of the destination point.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_DEST_LATITUDE_REF = 'GPSDestLatitudeRef',

  /**
    * The latitude of the destination point.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_DEST_LATITUDE = 'GPSDestLatitude',

  /**
    * Indicates the longitude reference of the destination point.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_DEST_LONGITUDE_REF = 'GPSDestLongitudeRef',

  /**
    * The longitude of the destination point.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_DEST_LONGITUDE = 'GPSDestLongitude',

  /**
    * The reference for the bearing to the destination point.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_DEST_BEARING_REF = 'GPSDestBearingRef',

  /**
    * The bearing to the destination point.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_DEST_BEARING = 'GPSDestBearing',

  /**
    * The measurement unit for the distance to the target point.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_DEST_DISTANCE_REF = 'GPSDestDistanceRef',

  /**
    * The distance to the destination point.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_DEST_DISTANCE = 'GPSDestDistance',

  /**
    * A character string recording the name of the method used for location finding.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_PROCESSING_METHOD = 'GPSProcessingMethod',

  /**
    * A character string recording the name of the GPS area.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_AREA_INFORMATION = 'GPSAreaInformation',

  /**
    * This field denotes if differential correction was applied to GPS data, crucial for precise location accuracy.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_DIFFERENTIAL = 'GPSDifferential',

  /**
    * The serial number of the camera body.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  BODY_SERIAL_NUMBER = 'BodySerialNumber',

  /**
    * The name of the camera owner.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  CAMERA_OWNER_NAME = 'CameraOwnerName',

  /**
    * Indicates whether the image is a composite image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  COMPOSITE_IMAGE = 'CompositeImage',

  /**
    * The compression mode used for a compressed image, in unit bits per pixel.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  COMPRESSED_BITS_PER_PIXEL = 'CompressedBitsPerPixel',

  /**
    * The DNGVersion tag encodes the four-tier version number for DNG specification compliance.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  DNG_VERSION = 'DNGVersion',

  /**
    * DefaultCropSize specifies the final image size in raw coordinates, accounting for extra edge pixels.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  DEFAULT_CROP_SIZE = 'DefaultCropSize',

  /**
    * Indicates the value of coefficient gamma.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GAMMA = 'Gamma',

  /**
    * The tag indicate the ISO speed latitude yyy value of the camera or input device that is defined in ISO 12232.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  ISO_SPEED_LATITUDE_YYY = 'ISOSpeedLatitudeyyy',

  /**
    * The tag indicate the ISO speed latitude zzz value of the camera or input device that is defined in ISO 12232.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  ISO_SPEED_LATITUDE_ZZZ = 'ISOSpeedLatitudezzz',

  /**
    * The manufacturer of the lens.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  LENS_MAKE = 'LensMake',

  /**
    * The model name of the lens.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  LENS_MODEL = 'LensModel',

  /**
    * The serial number of the lens.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  LENS_SERIAL_NUMBER = 'LensSerialNumber',

  /**
    * Specifications of the lens used.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  LENS_SPECIFICATION = 'LensSpecification',

  /**
    * This tag provides a broad description of the data type in this subfile.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  NEW_SUBFILE_TYPE = 'NewSubfileType',

  /**
    * This tag records the UTC offset for the DateTime tag, ensuring accurate timestamps regardless of location.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  OFFSET_TIME = 'OffsetTime',

  /**
    * This tag records the UTC offset when the image was digitized, aiding in accurate timestamp adjustment.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  OFFSET_TIME_DIGITIZED = 'OffsetTimeDigitized',

  /**
    * This tag records the UTC offset when the original image was created, crucial for time-sensitive applications.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  OFFSET_TIME_ORIGINAL = 'OffsetTimeOriginal',

  /**
    * Exposure times of source images for a composite image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SOURCE_EXPOSURE_TIMES_OF_COMPOSITE_IMAGE = 'SourceExposureTimesOfCompositeImage',

  /**
    * The number of source images used for a composite image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SOURCE_IMAGE_NUMBER_OF_COMPOSITE_IMAGE = 'SourceImageNumberOfCompositeImage',

  /**
    * This deprecated tag indicates the data type in this subfile. Use NewSubfileType instead.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SUBFILE_TYPE = 'SubfileType',

  /**
    * This tag indicates horizontal positioning errors in meters.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GPS_H_POSITIONING_ERROR = 'GPSHPositioningError',

  /**
    * This tag indicates the sensitivity of the camera or input device when the image was shot.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  PHOTOGRAPHIC_SENSITIVITY = 'PhotographicSensitivity',

  /**
    * Burst Number
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  BURST_NUMBER = 'HwMnoteBurstNumber',

  /**
    * Face Conf
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FACE_CONF = 'HwMnoteFaceConf',

  /**
    * Face Leye Center
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FACE_LEYE_CENTER = 'HwMnoteFaceLeyeCenter',

  /**
    * Face Mouth Center
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FACE_MOUTH_CENTER = 'HwMnoteFaceMouthCenter',

  /**
    * Face Pointer
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FACE_POINTER = 'HwMnoteFacePointer',

  /**
    * Face Rect
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FACE_RECT = 'HwMnoteFaceRect',

  /**
    * Face Reye Center
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FACE_REYE_CENTER = 'HwMnoteFaceReyeCenter',

  /**
    * Face Smile Score
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FACE_SMILE_SCORE = 'HwMnoteFaceSmileScore',

  /**
    * Face Version
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FACE_VERSION = 'HwMnoteFaceVersion',

  /**
    * Front Camera
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  FRONT_CAMERA = 'HwMnoteFrontCamera',

  /**
    * Scene Pointer
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SCENE_POINTER = 'HwMnoteScenePointer',

  /**
    * Scene Version
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  SCENE_VERSION = 'HwMnoteSceneVersion',

  /**
    * Is Xmage Supported
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  IS_XMAGE_SUPPORTED = 'HwMnoteIsXmageSupported',

  /**
    * Xmage Mode
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  XMAGE_MODE = 'HwMnoteXmageMode',

  /**
    * Xmage X1 Coordinate
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  XMAGE_LEFT = 'HwMnoteXmageLeft',

  /**
    * Xmage Y1 Coordinate
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  XMAGE_TOP = 'HwMnoteXmageTop',

  /**
    * Xmage X2 Coordinate
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  XMAGE_RIGHT = 'HwMnoteXmageRight',

  /**
    * Xmage Y2 Coordinate
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  XMAGE_BOTTOM = 'HwMnoteXmageBottom',

  /**
    * Cloud Enhancement Mode
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  CLOUD_ENHANCEMENT_MODE = 'HwMnoteCloudEnhancementMode',

  /**
    * Wind Snapshot Mode
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  WIND_SNAPSHOT_MODE = 'HwMnoteWindSnapshotMode',

  /**
    * GIF LOOP COUNT
    * If infinite loop returns 0, other values represent the number of loops
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 12
    */
  GIF_LOOP_COUNT = 'GIFLoopCount'
}

enum AntiAliasingLevel {
  /**
    * Nearest-neighbor interpolation algorithm.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  NONE = 0,

  /**
    * Bilinear interpolation algorithm.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  LOW = 1,

  /**
    * Bilinear interpolation algorithm with mipmap linear filtering.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  MEDIUM = 2,

  /**
    * Cubic interpolation algorithm.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  HIGH = 3,
}

enum HdrMetadataKey {
  /**
    * Indicate the types of metadata that image needs to use.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  HDR_METADATA_TYPE = 0,

  /**
    * Static metadata key.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  HDR_STATIC_METADATA = 1,

  /**
    * Dynamic metadata key.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  HDR_DYNAMIC_METADATA = 2,

  /**
    * Gainmap metadata key.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  HDR_GAINMAP_METADATA = 3,
}

enum HdrMetadataType {
  /**
    * No metadata.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  NONE = 0,

  /**
    * Indicates that metadata will be used for the base image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  BASE = 1,

  /**
    * Indicates that metadata will be used for the gainmap image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  GAINMAP = 2,

  /**
    * Indicates that metadata will be used for the alternate image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  ALTERNATE = 3,
}

enum PackingDynamicRange {
  /**
    * Packing according to the content of the image.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  AUTO = 0,

  /**
    * Packing to standard dynamic range.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  SDR = 1,
}

enum ScaleMode {
  /**
    * Indicates the effect that fits the image into the target size.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 9
    */
  /**
    * Indicates the effect that fits the image into the target size.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  /**
    * Indicates the effect that fits the image into the target size.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @atomicservice
    * @since 11
    */
  /**
    * Indicates the effect that fits the image into the target size.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @form
    * @atomicservice
    * @since 12
    */
  FIT_TARGET_SIZE = 0,

  /**
    * Indicates the effect that scales an image to fill the target image area and center-crops the part outside the area.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 9
    */
  /**
    * Indicates the effect that scales an image to fill the target image area and center-crops the part outside the area.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @since 10
    */
  /**
    * Indicates the effect that scales an image to fill the target image area and center-crops the part outside the area.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @atomicservice
    * @since 11
    */
  /**
    * Indicates the effect that scales an image to fill the target image area and center-crops the part outside the area.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @crossplatform
    * @form
    * @atomicservice
    * @since 12
    */
  CENTER_CROP = 1
}

enum AuxiliaryPictureType {
  /**
    * Gain map.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
  GAINMAP = 1,

  /**
    * Depth map.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
  DEPTH_MAP = 2,

  /**
    * Unrefocus map.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
  UNREFOCUS_MAP = 3,

  /**
    * Linear map.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
  LINEAR_MAP = 4,

  /**
    * Fragment map.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
  FRAGMENT_MAP = 5,
}

enum MetadataType {
  /**
    * EXIF metadata.
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
  EXIF_METADATA = 1,

  /**
    * Fragment metadata. 
    *
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
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

class SizeInner implements Size{
  constructor(w:int, h:int) {
    this.width = w;
    this.height = h;
  }
  width: int;
  height: int;
}

interface Region {
  size: Size;
  x: Int;
  y: Int;
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

class ImageInfoInner implements ImageInfo{
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

export class InitializationOptionsInner implements InitializationOptions{
  size: Size = { width: 0, height:0 };
  pixelFormat?: Int | undefined = 0;
  srcPixelFormat?: Int | undefined = 0;
  editable?: boolean | undefined = false;
  alphaType?: Int | undefined = 0;
  scaleMode?: Int | undefined = 0;
}

class PixelMapInner implements PixelMap{
  private nativeObj: long = 0;

  constructor(context: long) {
    if (this.nativeObj == 0) {
      this.nativeObj = context;
    }
  }

  native nativeGetImageInfo(): ImageInfo;

  public GetImageInfoSync(): ImageInfo {
    console.log("Test PixelMap sync GetImageInfo");
    return this.nativeGetImageInfo();
  }

  public GetImageInfo(): Promise<ImageInfo> {
    let p = new Promise<ImageInfo>((resolve: (v: ImageInfo) => void, reject: (error: Object) => void) => {
        // 选项2： 推荐用法
        let cb = (): undefined => {
            this.nativeGetImageInfo()
            return undefined
        }
        let p1 = taskpool.execute(cb);
        p1.then((e: NullishType)=>{
            let r : ImageInfo =  e as ImageInfo;
            resolve(r);
        });
    });
    return p;
  }


  native nativeReadPixelsToBuffer(buff:ArrayBuffer): void;

  public readPixelsToBuffer(buff:ArrayBuffer): void {
    console.log("Test PixelMap sync GetImageInfo");
    return this.nativeReadPixelsToBuffer(buff);
  }

  native nativeRelase(): void;

  public release(): void {
    console.log("Test PixelMap sync GetImageInfo");
    return this.nativeRelase();
  }
}

export interface PixelMap {
  GetImageInfoSync(): ImageInfo;
  GetImageInfo():Promise<ImageInfo>;
  readPixelsToBuffer(buff:ArrayBuffer);
  release();
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
  /**
    * Index of an image.
    *
    * @type { ?number }
    * @syscap SystemCapability.Multimedia.Image.ImageSource
    * @crossplatform
    * @since 11
    */
  index?: int;

  /**
    * Default property value.
    *
    * @type { ?string }
    * @syscap SystemCapability.Multimedia.Image.ImageSource
    * @crossplatform
    * @since 11
    */
  defaultValue?: string;
}

interface GetImagePropertyOptions {
  index?: int;
  defaultValue?: string;
}

export class RegionInner implements Region{
  size: Size = {width:100, height:100}
  x: Int = 0;
  y: Int = 0;
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

export class DecodingOptionsInner implements DecodingOptions{
  index?: Int | undefined = 0;
  sampleSize?: Int | undefined = 1;
  rotate?: Int | undefined = 0;
  editable?: Int | undefined = 0;
  desiredSize?: Size| undefined = {width:100, height:200}
  desiredRegion?: Region | undefined = {size:{width:10, height:20}, x:30, y:40};
  desiredPixelFormat?: Int | undefined = 3;
  fitDensity?: Int | undefined = 1;
  desiredColorSpace?: Int | undefined = 1;
  desiredDynamicRange?: Int | undefined = 1;
  resolutionQuality?: Int | undefined = 1;
}


export interface ImageSource {
  getImageInfo(index: int): ImageInfo;
  createPixelMapSync(options?: DecodingOptions): PixelMap;
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
  native getImageInfo(index: int): ImageInfo;
  native createPixelMapSync(options?: DecodingOptions): PixelMap;
  private native modifyImageProperty(nativeObj: long, key: string, value: string): void;
  native modifyImageProperties(records: Record<string, string>): void;
  native getImageProperties(key: Array<string>): Record<string, string>;
  native release(): void;

  public modifyImageProperty(key: string, value: string): void {
    this.modifyImageProperty(this.nativeObj, key, value);
    return;
  }

}

type ImageSourceDatyType = string | int;
export native function createImageSource(data: ImageSourceDatyType): ImageSource;
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

export class PackingOption  implements PackingOptionInterface{
  format: string = "";
  quality: Int = 0;
  bufferSize?: Int | undefined = 20971520;
  desiredDynamicRange?: Int | undefined = 0;
  needsPackProperties?: Int | undefined = 0;
}

class ImagePacker{
  private nativeObj: long = 0;

  constructor(context: long) {
    if (this.nativeObj == 0) {
      this.nativeObj = context;
    }
  }

  native nativePackingWithPixelMap(source: PixelMap, option: PackingOption): ArrayBuffer;

  native nativeRelease(): void;

  public release(): void {
    
  }
  public packing(source: PixelMap, option: PackingOption): ArrayBuffer {
    console.log("Test PixelMap sync GetImageInfo");
    return this.nativePackingWithPixelMap(source, option);
  }
  supportedFormats:Array<string> =  new Array<string>("");
}

export native function createImagePacker(): ImagePacker;
// end imagepcker

// metadata
type HdrMetadataValue = HdrMetadataType | HdrStaticMetadata | ArrayBuffer | HdrGainmapMetadata;

interface HdrStaticMetadata {
  /**
    * The X-coordinate of the primary colors. The length of the array is three. Store in the order of r, g, b.
    *
    * @type { Array<number> }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  displayPrimariesX: Array<double>;

  /**
    * The Y-coordinate of the primary colors. The length of the array is three. Store in the order of r, g, b.
    *
    * @type { Array<number> }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  displayPrimariesY: Array<double>;

  /**
    * The X-coordinate of the white point value.
    *
    * @type { number }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  whitePointX: double;

  /**
    * The Y-coordinate of the white point value.
    *
    * @type { number }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  whitePointY: double;

  /**
    * Max luminance.
    *
    * @type { number }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  maxLuminance: double;

  /**
    * Min luminance.
    *
    * @type { number }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  minLuminance: double;

  /**
    * Maximum brightness of displayed content.
    *
    * @type { number }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  maxContentLightLevel: double;

  /**
    * Maximum average brightness of displayed content.
    *
    * @type { number }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
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
  /**
    * Obtains the value of properties in an image. This method uses a promise to return the property values in array
    * of records.
    *
    * @param { Array<string> } key Name of the properties whose value is to be obtained.
    * @returns { Promise<Record<string, string | null>> } Array of Records instance used to return the property values.
    * @throws { BusinessError } 401 - Parameter error. Possible causes: 1.Mandatory parameters are left unspecified.
    * 2.Incorrect parameter types. 3.Parameter verification failed.
    * @throws { BusinessError } 7600202 - Unsupported metadata. Possible causes: 1. Unsupported metadata type. 2. The
    * metadata type does not match the auxiliary picture type.
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
  getProperties(key: Array<string>): Promise<Record<string, string | null>>

  /**
    * Modify the value of properties in an image with the specified keys.
    *
    * @param { Record<string, string | null> } records Array of the property Records whose values are to
    * be modified.
    * @returns { Promise<void> } A Promise instance used to return the operation result.
    * @throws { BusinessError } 401 - Parameter error. Possible causes: 1.Mandatory parameters are left unspecified.
    * 2.Incorrect parameter types. 3.Parameter verification failed.
    * @throws { BusinessError } 7600202 - Unsupported metadata. Possible causes: 1. Unsupported metadata type. 2. The
    * metadata type does not match the auxiliary picture type.
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
  setProperties(records: Record<string, string | null>): Promise<void>

  /**
    * Obtains the value of all properties in an image. This method uses a promise to return the property values
    * in array of records.
    *
    * @returns { Promise<Record<string, string | null>> } Array of Records instance used to return the property values.
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
  getAllProperties(): Promise<Record<string, string | null>>

  /**
    * Obtains a clone of metadata. This method uses a promise to return the metadata.
    *
    * @returns { Promise<Metadata> } A Promise instance used to return the metadata.
    * @throws { BusinessError } 7600301 - Memory alloc failed.
    * @throws { BusinessError } 7600302 - Memory copy failed.
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
  clone(): Promise<Metadata>
}
// END Meta

interface HdrGainmapMetadata {
  /**
    * The version used by the writer.
    *
    * @type { number }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  writerVersion: int;

  /**
    * The minimum version a parser needs to understand.
    *
    * @type { number }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  miniVersion: int;

  /**
    * The number of gain map channels, with a value of 1 or 3.
    *
    * @type { number }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  gainmapChannelCount: int;

  /**
    * Indicate whether to use the color space of the base image.
    *
    * @type { boolean }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  useBaseColorFlag: boolean;

  /**
    * The baseline hdr headroom.
    *
    * @type { number }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */    
  baseHeadroom: double;

  /**
    * The alternate hdr headroom.
    *
    * @type { number }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
  alternateHeadroom: double;

  /**
    * The per-channel metadata.
    *
    * @type { Array<GainmapChannel> }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 12
    */
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

  release():void
}

interface AuxiliaryPictureInfo {
  /**
    * Indicates auxiliary picture type.
    *
    * @type { AuxiliaryPictureType }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
  auxiliaryPictureType: AuxiliaryPictureType;

  /**
    * Indicates image dimensions specified by a {@link Size} interface.
    *
    * @type { Size }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
  size: Size;

  /**
    * The number of byte per row.
    *
    * @type { number }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
  rowStride: number;

  /**
    * Indicates image format.
    *
    * @type { PixelMapFormat }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
    pixelFormat: PixelMapFormat;

  /**
    * Indicates color space for pixel map.
    *
    * @type { colorSpaceManager.ColorSpaceManager }
    * @syscap SystemCapability.Multimedia.Image.Core
    * @since 13
    */
    colorSpace: int;
}

interface DecodingOptionsForPicture {
  desiredAuxiliaryPictures: Array<int>; // Array<AuxiliaryPictureType>
}
}// namespace