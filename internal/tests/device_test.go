package tests

import (
    "context"
    "testing"
    
    "github.com/crydensync/cryden/internal/core"
    "github.com/crydensync/cryden/internal/stores/memory"
)

func TestParseUserAgent(t *testing.T) {
    tests := []struct {
        name      string
        userAgent string
        expected  core.DeviceInfo
    }{
        {
            name:      "Chrome on Windows",
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
            expected: core.DeviceInfo{
                DeviceName: "Chrome on Windows 10",
                DeviceType: "desktop",
                Browser:    "Chrome",
                OS:         "Windows 10",
            },
        },
        {
            name:      "Safari on iPhone",
            userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
            expected: core.DeviceInfo{
                DeviceName: "Safari on iOS",
                DeviceType: "mobile",
                Browser:    "Safari",
                OS:         "iOS",
            },
        },
        {
            name:      "Firefox on Mac",
            userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
            expected: core.DeviceInfo{
                DeviceName: "Firefox on macOS",
                DeviceType: "desktop",
                Browser:    "Firefox",
                OS:         "macOS",
            },
        },
        {
            name:      "Empty user agent",
            userAgent: "",
            expected: core.DeviceInfo{
                DeviceName: "Unknown",
                DeviceType: "unknown",
                Browser:    "Unknown",
                OS:         "Unknown",
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := core.ParseUserAgent(tt.userAgent)
            
            if result.DeviceName != tt.expected.DeviceName {
                t.Errorf("DeviceName: expected %s, got %s", tt.expected.DeviceName, result.DeviceName)
            }
            if result.DeviceType != tt.expected.DeviceType {
                t.Errorf("DeviceType: expected %s, got %s", tt.expected.DeviceType, result.DeviceType)
            }
            if result.Browser != tt.expected.Browser {
                t.Errorf("Browser: expected %s, got %s", tt.expected.Browser, result.Browser)
            }
            if result.OS != tt.expected.OS {
                t.Errorf("OS: expected %s, got %s", tt.expected.OS, result.OS)
            }
        })
    }
}

func TestDeviceTrackingInSession(t *testing.T) {
    userStore := memory.NewUserStore()
    sessionStore := memory.NewSessionStore()
    engine := core.New(userStore, sessionStore)
    
    ctx := context.Background()
    
    // Sign up
    _, err := engine.SignUp(ctx, "device@example.com", "Password123")
    if err != nil {
        t.Fatalf("SignUp failed: %v", err)
    }
    
    // Login with device info
    userAgent := "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1"
    deviceInfo := core.ParseUserAgent(userAgent)
    ipAddress := "192.168.1.100"
    
    tokens, _, err := engine.Login(ctx, "device@example.com", "Password123", deviceInfo, ipAddress)
    if err != nil {
        t.Fatalf("Login failed: %v", err)
    }
    
    // List sessions
    sessions, err := engine.ListSessions(ctx, "device@example.com")
    if err != nil {
        t.Fatalf("ListSessions failed: %v", err)
    }
    
    if len(sessions) == 0 {
        t.Fatal("No sessions found")
    }
    
    session := sessions[0]
    if session.DeviceName != "Safari on iOS" {
        t.Errorf("Expected device name 'Safari on iOS', got '%s'", session.DeviceName)
    }
    if session.DeviceType != "mobile" {
        t.Errorf("Expected device type 'mobile', got '%s'", session.DeviceType)
    }
    if session.IPAddress != ipAddress {
        t.Errorf("Expected IP %s, got %s", ipAddress, session.IPAddress)
    }
}
