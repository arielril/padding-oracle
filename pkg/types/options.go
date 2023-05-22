package types

type Options struct {
	HexCipherMessage string
	CipherMessage    []byte
	BlockSize        int

	Verbose bool
	Silent  bool
}
