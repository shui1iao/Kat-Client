module github.com/shui1iao/Kat

go 1.26.9

require (
	github.com/klauspost/compress v1.18.7
	github.com/oschwald/maxminddb-golang v1.13.1
	golang.org/x/crypto v0.57.0
	gopkg.in/yaml.v3 v3.0.1
	lukechampine.com/blake3 v1.4.1
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	golang.org/x/text v0.42.0 // indirect
)

require (
	github.com/google/btree v1.1.3 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/exp v0.0.0-20260611194520-c48552f49976 // indirect
	golang.org/x/net v0.60.0
	golang.org/x/sys v0.48.0
	golang.org/x/time v0.15.0 // indirect
	gvisor.dev/gvisor v0.0.0-20260701204157-69c2d17aea96
)

replace gvisor.dev/gvisor => ./third_party/gvisor
