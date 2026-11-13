//go:build cgo

package main

// AMR-WB on the network side exists only in the cgo build (opencore-amrwb +
// vo-amrwbenc). Without cgo the daemon negotiates G.711.
import _ "github.com/xarvel/MudiVoLTE/volte/media/amrwb"
