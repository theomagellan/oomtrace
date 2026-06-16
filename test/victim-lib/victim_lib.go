package main

import "C"

// storage holds references so Go's GC doesn't free the allocations.
var storage [][]byte

//export AllocateMB
func AllocateMB(mb C.int) {
	chunk := make([]byte, int(mb)*1024*1024)
	chunk[0] = 1 // touch to force page commit
	storage = append(storage, chunk)
}

func main() {}
