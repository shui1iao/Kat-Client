package clientcore

import (
	"strconv"
	"strings"
)

func stageResource(key string) (string, int) {
	if key == "country.mmdb" {
		return "geoip", 0
	}
	if key == "asn.mmdb" {
		return "asn", 0
	}
	if strings.HasPrefix(key, "set-") {
		n, e := strconv.Atoi(strings.TrimPrefix(key, "set-"))
		if e == nil {
			return "rule_set", n + 1
		}
	}
	return "resource_stage", 0
}
