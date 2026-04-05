package core

import (
    "strings"
)

// DeviceInfo contains parsed device information
type DeviceInfo struct {
    DeviceName string
    DeviceType string
    Browser    string
    OS         string
}

// ParseUserAgent parses a User-Agent string and returns device info
func ParseUserAgent(userAgent string) *DeviceInfo {
    if userAgent == "" {
        return &DeviceInfo{
            DeviceName: "Unknown",
            DeviceType: "unknown",
            Browser:    "Unknown",
            OS:         "Unknown",
        }
    }

    ua := strings.ToLower(userAgent)
    info := &DeviceInfo{
        DeviceName: "Unknown",
        DeviceType: "desktop",
        Browser:    "Unknown",
        OS:         "Unknown",
    }

    // Detect Device Type
    switch {
    case strings.Contains(ua, "mobile"):
        info.DeviceType = "mobile"
    case strings.Contains(ua, "tablet") || strings.Contains(ua, "ipad"):
        info.DeviceType = "tablet"
    case strings.Contains(ua, "bot") || strings.Contains(ua, "crawler"):
        info.DeviceType = "bot"
    }

    // Detect OS
    switch {
    case strings.Contains(ua, "windows"):
        info.OS = "Windows"
        if strings.Contains(ua, "windows nt 10.0") {
            info.OS = "Windows 10"
        } else if strings.Contains(ua, "windows nt 6.1") {
            info.OS = "Windows 7"
        }
    case strings.Contains(ua, "mac os x") || strings.Contains(ua, "macintosh"):
        info.OS = "macOS"
    case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
        info.OS = "iOS"
    case strings.Contains(ua, "android"):
        info.OS = "Android"
    case strings.Contains(ua, "linux"):
        info.OS = "Linux"
    }

    // Detect Browser
    switch {
    case strings.Contains(ua, "chrome") && !strings.Contains(ua, "edg"):
        info.Browser = "Chrome"
    case strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome"):
        info.Browser = "Safari"
    case strings.Contains(ua, "firefox"):
        info.Browser = "Firefox"
    case strings.Contains(ua, "edg"):
        info.Browser = "Edge"
    case strings.Contains(ua, "opera") || strings.Contains(ua, "opr"):
        info.Browser = "Opera"
    }

    // Build device name
    deviceParts := []string{}
    if info.Browser != "Unknown" {
        deviceParts = append(deviceParts, info.Browser)
    }
    if info.OS != "Unknown" {
        deviceParts = append(deviceParts, info.OS)
    }
    if len(deviceParts) > 0 {
        info.DeviceName = strings.Join(deviceParts, " on ")
    } else {
        info.DeviceName = "Unknown Device"
    }

    return info
}
