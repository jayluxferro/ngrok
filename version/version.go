package version

import (
	"fmt"
)

const (
	Proto = "2"
	Major = "1"
	Minor = "0"
	Patch = "0"
)

func MajorMinor() string {
	return fmt.Sprintf("%s.%s", Major, Minor)
}

func MajorMinorPatch() string {
	return fmt.Sprintf("%s.%s.%s", Major, Minor, Patch)
}

func Full() string {
	return fmt.Sprintf("%s-%s.%s.%s", Proto, Major, Minor, Patch)
}

func Compat(client string, server string) bool {
	return client == server
}
