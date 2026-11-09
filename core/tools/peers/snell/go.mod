module example.invalid/stage/snell-peer

go 1.26.9

require (
	github.com/sagernet/sing v0.8.12-0.20260727003324-d096a164bc7f
	github.com/sagernet/sing-snell v0.0.0
)

require (
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace github.com/sagernet/sing-snell => /opt/proxy-kernel-research-protocols-20261017/sources/sing-snell
