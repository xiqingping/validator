package validator

import "regexp"

// Basic regular expressions for validating strings
const (
	RegexpEmail          string = "^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$"
	RegexpCreditCard     string = "^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})$"
	RegexpISBN10         string = "^(?:[0-9]{9}X|[0-9]{10})$"
	RegexpISBN13         string = "^(?:[0-9]{13})$"
	RegexpUUID3          string = "^[0-9a-f]{8}-[0-9a-f]{4}-3[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$"
	RegexpUUID4          string = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
	RegexpUUID5          string = "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
	RegexpUUID           string = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	RegexpAlpha          string = "^[a-zA-Z]+$"
	RegexpAlphanumeric   string = "^[a-zA-Z0-9]+$"
	RegexpNumeric        string = "^[-+]?[0-9]+$"
	RegexpInt            string = "^(?:[-+]?(?:0|[1-9][0-9]*))$"
	RegexpFloat          string = "^(?:[-+]?(?:[0-9]+))?(?:\\.[0-9]*)?(?:[eE][\\+\\-]?(?:[0-9]+))?$"
	RegexpHexadecimal    string = "^[0-9a-fA-F]+$"
	RegexpHexcolor       string = "^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$"
	RegexpRGBcolor       string = "^rgb\\(\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*\\)$"
	RegexpASCII          string = "^[\x00-\x7F]+$"
	RegexpMultibyte      string = "[^\x00-\x7F]"
	RegexpFullWidth      string = "[^\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]"
	RegexpHalfWidth      string = "[\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]"
	RegexpBase64         string = "^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$"
	RegexpPrintableASCII string = "^[\x20-\x7E]+$"
	RegexpDataURI        string = "^data:.+\\/(.+);base64$"
	RegexpLatitude       string = "^[-+]?([1-8]?\\d(\\.\\d+)?|90(\\.0+)?)$"
	RegexpLongitude      string = "^[-+]?(180(\\.0+)?|((1[0-7]\\d)|([1-9]?\\d))(\\.\\d+)?)$"
	RegexpURL            string = `^((ftp|https?):\/\/)?(\S+(:\S*)?@)?((([1-9]\d?|1\d\d|2[01]\d|22[0-3])(\.(1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.([0-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(([a-zA-Z0-9]+([-\.][a-zA-Z0-9]+)*)|((www\.)?))?(([a-z\x{00a1}-\x{ffff}0-9]+-?-?)*[a-z\x{00a1}-\x{ffff}0-9]+)(?:\.([a-z\x{00a1}-\x{ffff}]{2,}))?))(:(\d{1,5}))?((\/|\?|#)[^\s]*)?$`
	RegexpSSN            string = `^\d{3}[- ]?\d{2}[- ]?\d{4}$`
	RegexpWinPath        string = `^[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*$`
	RegexpUnixPath       string = `^((?:\/[a-zA-Z0-9\.\:]+(?:_[a-zA-Z0-9\:\.]+)*(?:\-[\:a-zA-Z0-9\.]+)*)+\/?)$`
	RegexpDomain         string = `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$`
	RegexpIPV4           string = `^(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])$`
	RegexpIPV4Mask       string = `^(254|252|248|240|224|192|128|0)\.0\.0\.0$|^(255\.(254|252|248|240|224|192|128|0)\.0\.0)$|^(255\.255\.(254|252|248|240|224|192|128|0)\.0)$|^(255\.255\.255\.(254|252|248|240|224|192|128|0))$`
)

// Used by IsFilePath func
const (
	// Unknown is unresolved OS type
	Unknown = iota
	// Win is Windows type
	Win
	// Unix is *nix OS types
	Unix
)

var (
	rxEmail          = regexp.MustCompile(RegexpEmail)
	rxCreditCard     = regexp.MustCompile(RegexpCreditCard)
	rxISBN10         = regexp.MustCompile(RegexpISBN10)
	rxISBN13         = regexp.MustCompile(RegexpISBN13)
	rxUUID3          = regexp.MustCompile(RegexpUUID3)
	rxUUID4          = regexp.MustCompile(RegexpUUID4)
	rxUUID5          = regexp.MustCompile(RegexpUUID5)
	rxUUID           = regexp.MustCompile(RegexpUUID)
	rxAlpha          = regexp.MustCompile(RegexpAlpha)
	rxAlphanumeric   = regexp.MustCompile(RegexpAlphanumeric)
	rxNumeric        = regexp.MustCompile(RegexpNumeric)
	rxInt            = regexp.MustCompile(RegexpInt)
	rxFloat          = regexp.MustCompile(RegexpFloat)
	rxHexadecimal    = regexp.MustCompile(RegexpHexadecimal)
	rxHexcolor       = regexp.MustCompile(RegexpHexcolor)
	rxRGBcolor       = regexp.MustCompile(RegexpRGBcolor)
	rxASCII          = regexp.MustCompile(RegexpASCII)
	rxPrintableASCII = regexp.MustCompile(RegexpPrintableASCII)
	rxMultibyte      = regexp.MustCompile(RegexpMultibyte)
	rxFullWidth      = regexp.MustCompile(RegexpFullWidth)
	rxHalfWidth      = regexp.MustCompile(RegexpHalfWidth)
	rxBase64         = regexp.MustCompile(RegexpBase64)
	rxDataURI        = regexp.MustCompile(RegexpDataURI)
	rxLatitude       = regexp.MustCompile(RegexpLatitude)
	rxLongitude      = regexp.MustCompile(RegexpLongitude)
	rxURL            = regexp.MustCompile(RegexpURL)
	rxSSN            = regexp.MustCompile(RegexpSSN)
	rxWinPath        = regexp.MustCompile(RegexpWinPath)
	rxUnixPath       = regexp.MustCompile(RegexpUnixPath)
	rxDomain         = regexp.MustCompile(RegexpDomain)
	rxIPV4           = regexp.MustCompile(RegexpIPV4)
	rxIPV4Mask       = regexp.MustCompile(RegexpIPV4Mask)
)
