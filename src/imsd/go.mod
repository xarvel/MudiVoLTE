module github.com/xarvel/MudiVoLTE/src/imsd

go 1.26.3

require github.com/damonto/wwan-go v0.0.1

require rsc.io/qr v0.2.0

require (
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
)

require (
	github.com/emiago/sipgo v1.7.2
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.3.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/icholy/digest v1.2.0 // indirect
	github.com/xarvel/MudiVoLTE/volte v0.0.0
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace github.com/xarvel/MudiVoLTE/volte => ../../volte
