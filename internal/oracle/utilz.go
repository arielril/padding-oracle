package oracle

func splitByteBlocks(cipherMessage []byte, blockSize int) [][]byte {
	res := make([][]byte, 0)

	for i := 0; i < len(cipherMessage); i += blockSize {
		res = append(res, cipherMessage[i:i+blockSize])
	}

	return res
}

func xorByteSlice(a, b []byte) []byte {
	// gologger.Debug().Msgf("xorByteSlice a=%v b=%v\n", a, b)
	r := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		r[i] = a[i] ^ b[i]
	}
	// gologger.Debug().Msgf("xorByteSlice result r=%v\n", r)
	return r
}
