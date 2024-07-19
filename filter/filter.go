package filter

import (
	"fmt"
	"regexp"
	"strings"

	"wisp-server-go/options"
	"wisp-server-go/packet"
)

// StreamInfo holds information about a stream.
type StreamInfo struct {
	StreamType  uint8
	Hostname    string
	Port        uint16
	StreamCount int 
}

// IsStreamAllowed checks if a stream is allowed based on the configuration.
func IsStreamAllowed(info StreamInfo, options *options.OptionsStruct) uint8 {
	// Check if TCP or UDP should be blocked
	if info.StreamType == packet.StreamTypeTCP && !options.AllowTCPStreams {
		return packet.CloseReasonHostBlocked
	}
	if info.StreamType == packet.StreamTypeUDP && !options.AllowUDPStreams {
		return packet.CloseReasonHostBlocked
	}

	// Check the hostname whitelist/blacklist
	if len(options.HostnameWhitelist) > 0 {
		if isHostnameBlocked(info.Hostname, options.HostnameWhitelist, true) {
			return packet.CloseReasonHostBlocked
		}
	} else if len(options.HostnameBlacklist) > 0 {
		if isHostnameBlocked(info.Hostname, options.HostnameBlacklist, false) {
			return packet.CloseReasonHostBlocked
		}
	}

	// Check if the port is blocked
	if len(options.PortWhitelist) > 0 {
		if isPortBlocked(info.Port, options.PortWhitelist, true) {
			return packet.CloseReasonHostBlocked
		}
	} else if len(options.PortBlacklist) > 0 {
		if isPortBlocked(info.Port, options.PortBlacklist, false) {
			return packet.CloseReasonHostBlocked
		}
	}

	// Check for stream count limits
	if options.StreamLimitTotal != -1 && info.StreamCount >= options.StreamLimitTotal {
		return packet.CloseReasonConnThrottled
	}

	if options.StreamLimitPerHost != -1 {
		if info.StreamCount >= options.StreamLimitPerHost { 
			return packet.CloseReasonConnThrottled
		}
	}

	return 0
}

func isHostnameBlocked(hostname string, list []*regexp.Regexp, whitelist bool) bool {
	for _, regex := range list {
		if regex.MatchString(hostname) {
			return !whitelist
		}
	}
	return whitelist
}

func isPortBlocked(port uint16, list []string, whitelist bool) bool {
	for _, portRange := range list {
		if strings.Contains(portRange, "-") {
			parts := strings.Split(portRange, "-")
			if len(parts) != 2 {
				continue
			}

			startPort, err := parsePort(parts[0])
			if err != nil {
				continue
			}

			endPort, err := parsePort(parts[1])
			if err != nil {
				continue
			}

			if port >= startPort && port <= endPort {
				return !whitelist
			}
		} else {
			checkPort, err := parsePort(portRange)
			if err != nil {
				continue
			}

			if port == checkPort {
				return !whitelist
			}
		}
	}
	return whitelist
}

func parsePort(portStr string) (uint16, error) {
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return 0, fmt.Errorf("invalid port: %s", portStr)
	}
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}
	return uint16(port), nil
}