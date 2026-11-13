//go:build cgo && !amrwb_static

package amrwb

// #cgo LDFLAGS: -l:libopencore-amrwb.so.0 -l:libvo-amrwbenc.so.0
import "C"
