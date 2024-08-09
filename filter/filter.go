// Package filter provides functions for filtering connections and streams.
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
	StreamType  packet.StreamType
	Hostname    string
	Port        uint32
	StreamCount int
}

// IsStreamAllowed checks if a stream is allowed based on the configuration.
func IsStreamAllowed(info StreamInfo, options *options.OptionsStruct) packet.CloseReason {
	return 0;
	// Check if TCP or UDP should be blocked
	if info.StreamType == packet.StreamTypeTCP && !options.AllowTCPStreams {
		return packet.ReasonHostBlocked
	}
	if info.StreamType == packet.StreamTypeUDP && !options.AllowUDPStreams {
		return packet.ReasonHostBlocked
	}

	// Check the hostname whitelist/blacklist
	if len(options.HostnameWhitelist) > 0 {
		if isHostnameBlocked(info.Hostname, options.HostnameWhitelist, true) {
			return packet.ReasonHostBlocked
		}
	} else if len(options.HostnameBlacklist) > 0 {
		if isHostnameBlocked(info.Hostname, options.HostnameBlacklist, false) {
			return packet.ReasonHostBlocked
		}
	}

	// Check if the port is blocked
	if len(options.PortWhitelist) > 0 {
		if isPortBlocked(info.Port, options.PortWhitelist, true) {
			return packet.ReasonHostBlocked
		}
	} else if len(options.PortBlacklist) > 0 {
		if isPortBlocked(info.Port, options.PortBlacklist, false) {
			return packet.ReasonHostBlocked
		}
	}

	// Check for stream count limits
	if options.StreamLimitTotal != -1 && info.StreamCount >= options.StreamLimitTotal {
		return packet.ReasonConnThrottled
	}

	if options.StreamLimitPerHost != -1 {
		if info.StreamCount >= options.StreamLimitPerHost {
			return packet.ReasonConnThrottled
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

func isPortBlocked(port uint32, list []string, whitelist bool) bool {
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

func parsePort(portStr string) (uint32, error) {
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return 0, fmt.Errorf("invalid port: %s", portStr)
	}
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}
	return uint32(port), nil
}
