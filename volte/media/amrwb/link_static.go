//go:build cgo && amrwb_static

package amrwb

// #cgo LDFLAGS: -lopencore-amrwb -lvo-amrwbenc -lm
import "C"
